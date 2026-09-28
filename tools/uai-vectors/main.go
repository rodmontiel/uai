// Command uai-vectors generates the normative UAI conformance vectors into
// spec/test-vectors/.
//
// It is run by a maintainer when the protocol changes, never by tests. The
// generated files are committed and the test suites read them; regenerating
// expectations at test time would prove only self-consistency.
//
// Generation is deterministic: fixed Ed25519 seeds and a counter-mode key
// stream for ECDSA, so re-running produces byte-identical files and a diff
// means the protocol actually changed.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/testvectors"
	"github.com/rodmontiel/uai/pkg/attest"
	"github.com/rodmontiel/uai/pkg/governance"
	"github.com/rodmontiel/uai/pkg/merkle"
	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// detReader is a deterministic key stream: SHA-256 in counter mode over a fixed
// seed. It exists so that ECDSA key generation, which consumes randomness,
// yields the same key on every run.
type detReader struct {
	seed    []byte
	counter uint64
	buf     []byte
}

func newDetReader(seed string) *detReader { return &detReader{seed: []byte(seed)} }

func (r *detReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			var ctr [8]byte
			binary.BigEndian.PutUint64(ctr[:], r.counter)
			r.counter++
			sum := sha256.Sum256(append(append([]byte{}, r.seed...), ctr[:]...))
			r.buf = sum[:]
		}
		c := copy(p[n:], r.buf)
		r.buf = r.buf[c:]
		n += c
	}
	return n, nil
}

var outDir = flag.String("out", "", "output directory (default: <repo>/spec/test-vectors)")

func main() {
	flag.Parse()
	dir := *outDir
	if dir == "" {
		dir = testvectors.Dir()
	}

	writers := []struct {
		path string
		fn   func() (any, error)
	}{
		{"jcs/canonicalization.json", jcsVectors},
		{"digest/domain-separation.json", digestVectors},
		{"commitment/salted-commitment.json", commitmentVectors},
		{"keys/jwk-thumbprint.json", thumbprintVectors},
		{"merkle/hashing.json", merkleHashVectors},
		{"merkle/tree-proofs.json", merkleTreeVectors},
		{"signature/ed25519.json", ed25519Vectors},
		{"signature/ecdsa.json", ecdsaVectors},
		{"identifier/uai-id.json", identifierVectors},
		{"attestation/event-chain.json", chainVectors},
		{"attestation/signing-payload.json", signingPayloadVectors},
		{"governance/vote-assertion.json", voteAssertionVectors},
		{"pop/rfc9421.json", popVectors},
	}

	for _, w := range writers {
		set, err := w.fn()
		if err != nil {
			fail(fmt.Errorf("%s: %w", w.path, err))
		}
		full := filepath.Join(dir, filepath.FromSlash(w.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			fail(err)
		}
		raw, err := json.MarshalIndent(set, "", "  ")
		if err != nil {
			fail(err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(full, raw, 0o644); err != nil {
			fail(err)
		}
		fmt.Printf("  wrote %s\n", w.path)
	}
	fmt.Printf("generated %d vector sets in %s\n", len(writers), dir)
}

func jcsVectors() (any, error) {
	// The control-character case is built by concatenation so that this source
	// file contains no literal control byte of its own.
	controlEscape := `{"s":"` + `\u0007` + `"}`
	inputs := []struct{ name, in string }{
		{"member ordering", `{ "b": 1, "a": 2, "c": { "z": true, "y": null } }`},
		{"whitespace removed", "{\n  \"a\" : 1 ,\n  \"b\" : [ 1 , 2 ]\n}"},
		{"integer valued float", `{"n":1.0}`},
		{"negative zero", `{"n":-0}`},
		{"exponent normalized to plain", `{"n":1e2}`},
		{"smallest plain notation", `{"n":0.000001}`},
		{"exponential above 1e21", `{"n":1e21}`},
		{"exponential below 1e-6", `{"n":1e-7}`},
		{"large exponent", `{"n":1.5e300}`},
		{"fraction preserved", `{"n":333333333.33}`},
		{"mandatory and short escapes", `{"s":"a\"b\\c\nd\te"}`},
		{"control character escaped as u00xx", controlEscape},
		{"non-ascii stays literal", `{"s":"é中"}`},
		{"utf-16 member ordering across the BMP boundary", `{"😀":1,"דּ":2}`},
		{"nested arrays and objects", `{"z":[{"b":2,"a":1}],"a":[]}`},
		{"empty object and array", `{"o":{},"a":[]}`},
		{"booleans and null", `{"t":true,"f":false,"n":null}`},
	}
	set := testvectors.Set[testvectors.JCSCase]{
		VectorSet:   "uai-cs-1/jcs",
		UAIVersion:  "0.1",
		Description: "RFC 8785 JSON Canonicalization Scheme. Every UAI hash and signature is computed over these bytes, so an implementation that canonicalizes differently cannot verify anything UAI produces.",
		Reference:   "docs/protocol/04-cryptography.md#72-canonicalization-and-domain-separation",
	}
	for _, in := range inputs {
		canonical, err := uaicrypto.CanonicalizeJSON([]byte(in.in))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(canonical)
		set.Cases = append(set.Cases, testvectors.JCSCase{
			Name:            in.name,
			InputJSON:       in.in,
			Canonical:       string(canonical),
			CanonicalSHA256: hex.EncodeToString(sum[:]),
		})
	}
	return set, nil
}

func digestVectors() (any, error) {
	payload := `{"a":1}`
	domains := []uaicrypto.Domain{
		uaicrypto.DomainAttestation, uaicrypto.DomainCredential, uaicrypto.DomainDIDDocument,
		uaicrypto.DomainChallenge, uaicrypto.DomainVote, uaicrypto.DomainDecision,
		uaicrypto.DomainQuarantine, uaicrypto.DomainRevocation, uaicrypto.DomainCheckpoint,
		uaicrypto.DomainCommitment, uaicrypto.DomainAudit, uaicrypto.DomainRegistration, uaicrypto.DomainPolicyBundle,
		uaicrypto.DomainCapabilityRequest, uaicrypto.DomainSuspicion, uaicrypto.DomainPassport,
	}
	set := testvectors.Set[testvectors.DigestCase]{
		VectorSet:   "uai-cs-1/digest",
		UAIVersion:  "0.1",
		Description: "Domain-separated digests: SHA-256(DOMAIN || 0x00 || payload). The same payload in two domains MUST produce different digests; that difference is what stops a signature made in one context verifying in another.",
		Reference:   "docs/protocol/04-cryptography.md#72-canonicalization-and-domain-separation",
	}
	for _, d := range domains {
		in, err := uaicrypto.SigningInput(d, []byte(payload))
		if err != nil {
			return nil, err
		}
		sum, err := uaicrypto.Digest(d, []byte(payload))
		if err != nil {
			return nil, err
		}
		set.Cases = append(set.Cases, testvectors.DigestCase{
			Name:            "domain " + string(d),
			Domain:          string(d),
			PayloadUTF8:     payload,
			SigningInputHex: hex.EncodeToString(in),
			Digest:          uaicrypto.FormatDigest(sum),
		})
	}
	return set, nil
}

func commitmentVectors() (any, error) {
	saltA := mustHex("0000000000000000000000000000000000000000000000000000000000000001")
	saltB := mustHex("00000000000000000000000000000000000000000000000000000000000000ff")
	contents := []struct{ name, content string }{
		{"low-entropy email", "customer@example.com"},
		{"low-entropy answer", "YES"},
		{"amount", "4200.00"},
		{"empty content", ""},
		{"json payload", `{"resource":"urn:cloud:aws:eu-central-1:sg-0a1b2c3d"}`},
	}
	set := testvectors.Set[testvectors.CommitmentCase]{
		VectorSet:   "uai-cs-1/commitment",
		UAIVersion:  "0.1",
		Description: "Salted commitments: SHA-256(\"UAI-v1:commitment\" || 0x00 || salt || content). The salt is mandatory. A bare hash of low-entropy content is recoverable by dictionary attack, and commitments are published on-chain where that leak is permanent.",
		Reference:   "docs/protocol/04-cryptography.md#73-commitments--salted-never-bare-hashes",
	}
	for _, c := range contents {
		commitment, err := uaicrypto.Commit(saltA, []byte(c.content))
		if err != nil {
			return nil, err
		}
		set.Cases = append(set.Cases, testvectors.CommitmentCase{
			Name: c.name, SaltHex: hex.EncodeToString(saltA),
			ContentUTF8: c.content, Commitment: uaicrypto.FormatDigest(commitment), Opens: true,
		})
	}
	// Same content, different salt: the commitments MUST differ. This is the
	// case an implementation that "optimized away" the salt would fail.
	c1, err := uaicrypto.Commit(saltA, []byte("YES"))
	if err != nil {
		return nil, err
	}
	c2, err := uaicrypto.Commit(saltB, []byte("YES"))
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(c1) == hex.EncodeToString(c2) {
		return nil, fmt.Errorf("salt has no effect on the commitment")
	}
	set.Cases = append(set.Cases,
		testvectors.CommitmentCase{
			Name: "same content under a second salt", SaltHex: hex.EncodeToString(saltB),
			ContentUTF8: "YES", Commitment: uaicrypto.FormatDigest(c2), Opens: true,
		},
		testvectors.CommitmentCase{
			Name: "wrong content does not open the commitment", SaltHex: hex.EncodeToString(saltA),
			ContentUTF8: "NO", Commitment: uaicrypto.FormatDigest(c1), Opens: false,
		},
	)
	return set, nil
}

func merkleHashVectors() (any, error) {
	set := testvectors.Set[testvectors.MerkleHashCase]{
		VectorSet:   "uai-cs-1/merkle-hashing",
		UAIVersion:  "0.1",
		Description: "RFC 6962 leaf and node hashing. The 0x00 and 0x01 prefixes are second-preimage protection: without them an interior node hash can be presented as a leaf hash and every inclusion proof becomes forgeable.",
		Reference:   "docs/protocol/04-cryptography.md#74-merkle-trees-rfc-6962-profile",
	}
	set.Cases = append(set.Cases, testvectors.MerkleHashCase{
		Name: "empty tree root", Kind: "empty", HashHex: hex.EncodeToString(merkle.EmptyRoot()),
	})
	for _, d := range []string{"", "a", "entry-0000"} {
		set.Cases = append(set.Cases, testvectors.MerkleHashCase{
			Name: "leaf " + quoteOrEmpty(d), Kind: "leaf", DataUTF8: d,
			HashHex: hex.EncodeToString(merkle.LeafHash([]byte(d))),
		})
	}
	l, r := merkle.LeafHash([]byte("a")), merkle.LeafHash([]byte("b"))
	set.Cases = append(set.Cases, testvectors.MerkleHashCase{
		Name: "interior node of leaves a and b", Kind: "node",
		LeftHex: hex.EncodeToString(l), RightHex: hex.EncodeToString(r),
		HashHex: hex.EncodeToString(merkle.NodeHash(l, r)),
	})
	return set, nil
}

func merkleTreeVectors() (any, error) {
	set := testvectors.Set[testvectors.MerkleTreeCase]{
		VectorSet:   "uai-cs-1/merkle-proofs",
		UAIVersion:  "0.1",
		Description: "Merkle roots, inclusion proofs and consistency proofs. Inclusion proves a statement is in the log; consistency proves the log was only appended to, which is what makes append-only verifiable rather than merely asserted.",
		Reference:   "docs/protocol/11-ledger-transparency.md#181-transparency-service",
	}
	for _, size := range []uint64{1, 2, 3, 4, 7, 8, 9, 16} {
		tree := merkle.New()
		var entries []string
		for i := uint64(0); i < size; i++ {
			e := fmt.Sprintf("entry-%04d", i)
			entries = append(entries, e)
			tree.Append([]byte(e))
		}
		c := testvectors.MerkleTreeCase{
			Name: fmt.Sprintf("tree of %d entries", size), EntriesUTF8: entries,
			Size: size, RootHex: hex.EncodeToString(tree.Root()),
		}
		for i := uint64(0); i < size; i++ {
			proof, err := tree.InclusionProof(i, size)
			if err != nil {
				return nil, err
			}
			leaf, err := tree.LeafHashAt(i)
			if err != nil {
				return nil, err
			}
			c.Inclusion = append(c.Inclusion, testvectors.MerkleInclusion{
				Index: i, LeafHashHex: hex.EncodeToString(leaf), ProofHex: hexAll(proof),
			})
		}
		for first := uint64(0); first <= size; first++ {
			proof, err := tree.ConsistencyProof(first, size)
			if err != nil {
				return nil, err
			}
			firstRoot, err := tree.RootAtSize(first)
			if err != nil {
				return nil, err
			}
			c.Consistency = append(c.Consistency, testvectors.MerkleConsistency{
				First: first, Second: size,
				FirstRootHex: hex.EncodeToString(firstRoot), ProofHex: hexAll(proof),
			})
		}
		set.Cases = append(set.Cases, c)
	}
	return set, nil
}

func ed25519Vectors() (any, error) {
	seed := sha256.Sum256([]byte("UAI conformance vector seed / ed25519 / v0.1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	signer := uaicrypto.NewEd25519Signer(priv, "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1")

	payloads := []struct {
		name, domain, payload string
	}{
		{"attestation payload", string(uaicrypto.DomainAttestation), `{"event_id":"01JY8RA3C7K2V9M0QW4T6Z8XPD","sequence":418}`},
		{"vote payload", string(uaicrypto.DomainVote), `{"case_id":"UAI-INC-000041","vote":"YES"}`},
		{"decision payload", string(uaicrypto.DomainDecision), `{"decision":"ALLOW_WITH_MONITORING","policy_version":"GASC-2027.4"}`},
		{"empty object", string(uaicrypto.DomainCredential), `{}`},
	}
	set := testvectors.Set[testvectors.SignatureCase]{
		VectorSet:   "uai-cs-1/ed25519",
		UAIVersion:  "0.1",
		Description: "Ed25519 signatures over domain-separated canonical bytes. Ed25519 is deterministic (RFC 8032), so the signature bytes are pinned: a conformant implementation reproduces them exactly.",
		Reference:   "docs/protocol/04-cryptography.md#75-signature-envelopes",
	}
	for _, p := range payloads {
		canonical, err := uaicrypto.CanonicalizeJSON([]byte(p.payload))
		if err != nil {
			return nil, err
		}
		sig, err := signer.Sign(uaicrypto.Domain(p.domain), canonical)
		if err != nil {
			return nil, err
		}
		set.Cases = append(set.Cases, testvectors.SignatureCase{
			Name: p.name, Alg: string(uaicrypto.AlgEdDSA), SeedHex: hex.EncodeToString(seed[:]),
			PublicKeyHex: hex.EncodeToString(pub), Domain: p.domain, PayloadJSON: p.payload,
			Canonical: string(canonical), SignatureB64: sig.Value,
			VerifyDomain: p.domain, MustVerify: true,
		})
	}

	// Negative cases. An implementation that passes only the positive vectors
	// has not demonstrated domain separation at all.
	canonical, err := uaicrypto.CanonicalizeJSON([]byte(`{"x":1}`))
	if err != nil {
		return nil, err
	}
	voteSig, err := signer.Sign(uaicrypto.DomainVote, canonical)
	if err != nil {
		return nil, err
	}
	set.Cases = append(set.Cases,
		testvectors.SignatureCase{
			Name: "vote signature MUST NOT verify as an attestation", Alg: string(uaicrypto.AlgEdDSA),
			SeedHex: hex.EncodeToString(seed[:]), PublicKeyHex: hex.EncodeToString(pub),
			Domain: string(uaicrypto.DomainVote), PayloadJSON: `{"x":1}`, Canonical: string(canonical),
			SignatureB64: voteSig.Value, VerifyDomain: string(uaicrypto.DomainAttestation),
			MustVerify: false, FailureReason: "domain mismatch: the domain is inside the signed bytes, so relabelling the envelope does not help",
		},
		testvectors.SignatureCase{
			Name: "tampered payload MUST NOT verify", Alg: string(uaicrypto.AlgEdDSA),
			SeedHex: hex.EncodeToString(seed[:]), PublicKeyHex: hex.EncodeToString(pub),
			Domain: string(uaicrypto.DomainVote), PayloadJSON: `{"x":2}`, Canonical: `{"x":2}`,
			SignatureB64: voteSig.Value, VerifyDomain: string(uaicrypto.DomainVote),
			MustVerify: false, FailureReason: "payload differs from the signed canonical bytes",
		},
	)
	return set, nil
}

func ecdsaVectors() (any, error) {
	set := testvectors.Set[testvectors.SignatureCase]{
		VectorSet:   "uai-cs-1/ecdsa",
		UAIVersion:  "0.1",
		Description: "ECDSA P-256 and P-384 over domain-separated canonical bytes, with fixed-width R||S so signatures interoperate with JOSE and WebAuthn. ECDSA is randomized, so these cases are verify-only: the committed signature MUST verify and the negative cases MUST NOT.",
		Reference:   "docs/protocol/04-cryptography.md#71-cipher-suite-uai-cs-1",
	}
	specs := []struct {
		alg   uaicrypto.Algorithm
		curve elliptic.Curve
		name  string
	}{
		{uaicrypto.AlgES256, elliptic.P256(), "P-256"},
		{uaicrypto.AlgES384, elliptic.P384(), "P-384"},
	}
	// ECDSA key generation and signing are randomized by design in Go, so a
	// naive regeneration would rewrite these files on every run and a diff
	// would stop meaning "the protocol changed". Existing cases are therefore
	// reused as long as their committed signature still verifies against their
	// committed key, domain and payload. New bytes appear only when the signed
	// material actually changes.
	existing, _ := testvectors.Load[testvectors.SignatureCase]("signature/ecdsa.json")

	for _, s := range specs {
		payload := `{"case_id":"UAI-INC-000041","vote":"YES"}`
		canonical, err := uaicrypto.CanonicalizeJSON([]byte(payload))
		if err != nil {
			return nil, err
		}

		var base testvectors.SignatureCase
		if reused, ok := reusableECDSA(existing, string(s.alg), string(uaicrypto.DomainVote), string(canonical)); ok {
			base = reused
		} else {
			key, err := ecdsa.GenerateKey(s.curve, newDetReader("UAI conformance vector seed / "+s.name+" / v0.1"))
			if err != nil {
				return nil, err
			}
			signer, err := uaicrypto.NewECDSASigner(key, "did:uai:delegate:01JY8R9ZD00000000000000000#wa-1")
			if err != nil {
				return nil, err
			}
			sig, err := signer.Sign(uaicrypto.DomainVote, canonical)
			if err != nil {
				return nil, err
			}
			base = testvectors.SignatureCase{
				Alg: string(s.alg), Curve: s.name,
				PublicKeyXHex: hex.EncodeToString(key.PublicKey.X.Bytes()),
				PublicKeyYHex: hex.EncodeToString(key.PublicKey.Y.Bytes()),
				Domain:        string(uaicrypto.DomainVote), PayloadJSON: payload,
				Canonical: string(canonical), SignatureB64: sig.Value,
			}
		}
		base.Name, base.VerifyDomain, base.MustVerify, base.FailureReason = "", "", false, ""
		base.Alg, base.Curve = string(s.alg), s.name
		base.Domain, base.PayloadJSON, base.Canonical = string(uaicrypto.DomainVote), payload, string(canonical)
		positive := base
		positive.Name = s.name + " vote signature verifies"
		positive.VerifyDomain = string(uaicrypto.DomainVote)
		positive.MustVerify = true

		crossDomain := base
		crossDomain.Name = s.name + " signature MUST NOT verify in another domain"
		crossDomain.VerifyDomain = string(uaicrypto.DomainAttestation)
		crossDomain.MustVerify = false
		crossDomain.FailureReason = "domain mismatch"

		set.Cases = append(set.Cases, positive, crossDomain)
	}
	return set, nil
}

// reusableECDSA returns a committed case whose signature still verifies against
// its own key, domain and canonical bytes, so that regenerating the vectors
// does not churn randomized ECDSA signatures.
func reusableECDSA(set testvectors.Set[testvectors.SignatureCase], alg, domain, canonical string) (testvectors.SignatureCase, bool) {
	for _, c := range set.Cases {
		if c.Alg != alg || c.Domain != domain || c.Canonical != canonical {
			continue
		}
		pub, err := ecdsaPublicKey(c.Curve, c.PublicKeyXHex, c.PublicKeyYHex)
		if err != nil {
			continue
		}
		sig := uaicrypto.Signature{
			Alg: uaicrypto.Algorithm(c.Alg), Domain: uaicrypto.Domain(c.Domain), Value: c.SignatureB64,
		}
		if uaicrypto.Verify(pub, uaicrypto.Domain(domain), []byte(canonical), sig) == nil {
			return c, true
		}
	}
	return testvectors.SignatureCase{}, false
}

// ecdsaPublicKey rebuilds a public key from the hex coordinates stored in a vector.
func ecdsaPublicKey(curveName, xHex, yHex string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch curveName {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unknown curve %q", curveName)
	}
	xb, err := hex.DecodeString(xHex)
	if err != nil {
		return nil, err
	}
	yb, err := hex.DecodeString(yHex)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
}

func identifierVectors() (any, error) {
	set := testvectors.Set[testvectors.IdentifierCase]{
		VectorSet:   "uai-id/parsing",
		UAIVersion:  "0.1",
		Description: "UAI-ID and DID parsing. A UAI-ID and its DID are the same identifier with and without the scheme prefix. Input is accepted case-insensitively and with Crockford's ambiguous characters folded; output is always canonical.",
		Reference:   "docs/protocol/03-identity.md#61-the-uai-id",
	}
	valid := []struct{ name, input string }{
		{"canonical agent identifier", "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"},
		{"DID spelling of the same identifier", "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"},
		{"uppercase scheme and entity", "UAI:AGENT:01JY8R9ZAF392N7QX2T81JH6KM"},
		{"lowercase ULID", "uai:agent:01jy8r9zaf392n7qx2t81jh6km"},
		{"Crockford I folds to 1", "uai:agent:01JY8R9ZAF392N7QX2T8IJH6KM"},
		{"owner entity", "uai:owner:01JY8R9ZB00000000000000000"},
		{"delegate entity", "did:uai:delegate:01JY8R9ZD00000000000000000"},
		{"minimum ULID", "uai:agent:00000000000000000000000000"},
		{"maximum ULID", "uai:agent:7ZZZZZZZZZZZZZZZZZZZZZZZZZ"},
	}
	for _, v := range valid {
		id, err := uaiid.Parse(v.input)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", v.name, err)
		}
		set.Cases = append(set.Cases, testvectors.IdentifierCase{
			Name: v.name, Input: v.input, Valid: true,
			CanonicalUAIID: id.String(), CanonicalDID: id.DID(),
			Entity: string(id.Entity()), TimestampMS: id.Time().UnixMilli(),
		})
	}
	invalid := []struct{ name, input, reason string }{
		{"missing scheme", "agent:01JY8R9ZAF392N7QX2T81JH6KM", "no uai: or did:uai: prefix"},
		{"different DID method", "did:web:example.com", "not the uai DID method"},
		{"unknown entity class", "uai:robot:01JY8R9ZAF392N7QX2T81JH6KM", "entity must be agent, owner, org, delegate or country"},
		{"ULID too short", "uai:agent:01JY8R9ZAF392N7QX2T81JH6K", "ULID must be 26 characters"},
		{"ULID too long", "uai:agent:01JY8R9ZAF392N7QX2T81JH6KMM", "ULID must be 26 characters"},
		{"character outside the Crockford alphabet", "uai:agent:01JY8R9ZAF392N7QX2T81JH6K!", "invalid character"},
		{"ULID overflows 128 bits", "uai:agent:8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "first character encodes only 2 bits"},
		{"empty", "", "empty input"},
	}
	for _, v := range invalid {
		if _, err := uaiid.Parse(v.input); err == nil {
			return nil, fmt.Errorf("%s: expected a parse failure", v.name)
		}
		set.Cases = append(set.Cases, testvectors.IdentifierCase{
			Name: v.name, Input: v.input, Valid: false, RejectReason: v.reason,
		})
	}
	return set, nil
}

func chainVectors() (any, error) {
	set := testvectors.Set[testvectors.ChainCase]{
		VectorSet:   "attestation/event-chain",
		UAIVersion:  "0.1",
		Description: "Per-agent attestation hash chain. Each event references its predecessor, so deleting or back-dating an event is detectable. Two events claiming the same predecessor is a fork, which has no benign cause and is the observable signature of a cloned agent or a stolen key.",
		Reference:   "docs/protocol/06-action-attestation.md#104-the-event-chain",
	}
	agent := "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"
	genesisHash, err := uaicrypto.Digest(uaicrypto.DomainRegistration, []byte(`{"registration":"`+agent+`"}`))
	if err != nil {
		return nil, err
	}
	prev := uaicrypto.FormatDigest(genesisHash)

	events := []struct {
		name, eventID, actionType, capability string
		sequence                              int
	}{
		{"first attested action", "01JY8RA3C7K2V9M0QW4T6Z8XPD", "route.optimize", "route.optimize", 1},
		{"second attested action", "01JY8RA4D8L3W0N1RX5U7A9YQE", "crm.customer.read", "crm.customer.read", 2},
		{"third attested action", "01JY8RA5E9M4X1P2SY6V8B0ZRF", "infrastructure.modify", "cloud.securitygroup.update", 3},
	}
	var forkPredecessor string
	for _, e := range events {
		att := map[string]any{
			"uai_version":         "0.1",
			"event_id":            e.eventID,
			"agent_did":           agent,
			"owner_did":           "did:uai:owner:01JY8R9ZB00000000000000000",
			"action":              map[string]any{"type": e.actionType, "capability": e.capability},
			"purpose":             "delivery_optimization",
			"outcome":             "SUCCESS",
			"sequence":            e.sequence,
			"previous_event_hash": prev,
		}
		raw, err := json.Marshal(att)
		if err != nil {
			return nil, err
		}
		canonical, err := uaicrypto.CanonicalizeJSON(raw)
		if err != nil {
			return nil, err
		}
		sum, err := uaicrypto.Digest(uaicrypto.DomainAttestation, canonical)
		if err != nil {
			return nil, err
		}
		set.Cases = append(set.Cases, testvectors.ChainCase{
			Name: e.name, Attestation: json.RawMessage(canonical), Canonical: string(canonical),
			EventHash: uaicrypto.FormatDigest(sum), PreviousEventHash: prev,
		})
		forkPredecessor = prev
		prev = uaicrypto.FormatDigest(sum)
	}

	// A fork: a second event claiming the same predecessor as the last one.
	fork := map[string]any{
		"uai_version":         "0.1",
		"event_id":            "01JY8RA6F0N5Y2Q3TZ7W9C1ASG",
		"agent_did":           agent,
		"owner_did":           "did:uai:owner:01JY8R9ZB00000000000000000",
		"action":              map[string]any{"type": "infrastructure.modify", "capability": "cloud.securitygroup.update"},
		"purpose":             "delivery_optimization",
		"outcome":             "SUCCESS",
		"sequence":            3,
		"previous_event_hash": forkPredecessor,
	}
	raw, err := json.Marshal(fork)
	if err != nil {
		return nil, err
	}
	canonical, err := uaicrypto.CanonicalizeJSON(raw)
	if err != nil {
		return nil, err
	}
	sum, err := uaicrypto.Digest(uaicrypto.DomainAttestation, canonical)
	if err != nil {
		return nil, err
	}
	set.Cases = append(set.Cases, testvectors.ChainCase{
		Name: "fork: a second event claiming the same predecessor", Attestation: json.RawMessage(canonical),
		Canonical: string(canonical), EventHash: uaicrypto.FormatDigest(sum), PreviousEventHash: forkPredecessor,
		IsFork:   true,
		ForkNote: "A conformant implementation MUST detect that two distinct events reference the same previous_event_hash and MUST NOT silently accept the second. A fork has no benign cause.",
	})
	return set, nil
}

func popVectors() (any, error) {
	set := testvectors.Set[testvectors.PoPCase]{
		VectorSet:   "uai-cs-1/pop-rfc9421",
		UAIVersion:  "0.1",
		Description: "RFC 9421 HTTP message signatures. The signature base is pinned as an exact string because that is where implementations diverge: a stray newline, an unquoted component name or a lowercased method all yield a base that verifies against nothing. Domain separation is carried by the `tag` parameter inside the base, not by a UAI prefix, so a standard RFC 9421 verifier interoperates.",
		Reference:   "docs/protocol/04-cryptography.md#761-http-message-signatures-rfc-9421--default-for-the-rest-api",
	}

	seed := sha256.Sum256([]byte("UAI conformance vector seed / pop-ed25519 / v0.1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	const kid = "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1"
	signer := uaicrypto.NewEd25519Signer(priv, kid)

	build := func(name, method, target, body, tag string, created int64) (testvectors.PoPCase, []byte, error) {
		req, err := http.NewRequest(method, target, nil)
		if err != nil {
			return testvectors.PoPCase{}, nil, err
		}
		digest := pop.ContentDigest([]byte(body))
		headers := map[string]string{
			"Content-Digest": digest,
			"UAI-Agent-Id":   "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
			"UAI-Nonce":      "8f1c2b9d4e6a7c3f0b1d2e3a4c5b6d7e",
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		p := pop.Params{
			Components: pop.DefaultComponents,
			Created:    created,
			KeyID:      kid,
			Alg:        "ed25519",
			Tag:        tag,
		}
		base, err := pop.SignatureBase(pop.FromRequest(req, "https"), p)
		if err != nil {
			return testvectors.PoPCase{}, nil, err
		}
		return testvectors.PoPCase{
			Name: name, Method: method, TargetURI: target, Headers: headers, BodyUTF8: body,
			Components: p.Components, Created: created, KeyID: kid, Alg: "ed25519", Tag: tag,
			SignatureInput: pop.Label + "=" + p.Serialize(),
			SignatureBase:  string(base),
			ContentDigest:  digest,
			SeedHex:        hex.EncodeToString(seed[:]),
			PublicKeyHex:   hex.EncodeToString(pub),
		}, base, nil
	}

	attest, base, err := build("attestation submission", "POST",
		"https://api.uai.world/v1/actions/attest",
		`{"event_id":"01JY8RA3C7K2V9M0QW4T6Z8XPD"}`,
		string(uaicrypto.DomainAttestation), 1790000524)
	if err != nil {
		return nil, err
	}
	_, sig, err := uaicrypto.SignHTTPSignatureBase(signer, base)
	if err != nil {
		return nil, err
	}
	attest.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	attest.VerifyTag = attest.Tag
	attest.MustVerify = true
	set.Cases = append(set.Cases, attest)

	vote, voteBase, err := build("vote submission", "POST",
		"https://api.uai.world/v1/governance/cases/UAI-INC-000041/vote",
		`{"vote":"YES"}`, string(uaicrypto.DomainVote), 1790000600)
	if err != nil {
		return nil, err
	}
	_, voteSig, err := uaicrypto.SignHTTPSignatureBase(signer, voteBase)
	if err != nil {
		return nil, err
	}
	vote.SignatureB64 = base64.StdEncoding.EncodeToString(voteSig)
	vote.VerifyTag = vote.Tag
	vote.MustVerify = true
	set.Cases = append(set.Cases, vote)

	// Negative: the vote signature presented at the attestation endpoint. The
	// tag is inside the signed base, so relabelling the header does not help.
	crossDomain := vote
	crossDomain.Name = "vote signature MUST NOT verify under the attestation tag"
	crossDomain.VerifyTag = string(uaicrypto.DomainAttestation)
	crossDomain.MustVerify = false
	crossDomain.FailureReason = "the tag is a signed component: changing it in the header invalidates the signature"
	set.Cases = append(set.Cases, crossDomain)

	// Negative: same signature, different target. A captured call to one
	// endpoint must not authorize another.
	swapped := attest
	swapped.Name = "signature MUST NOT verify against a different target URI"
	swapped.TargetURI = "https://api.uai.world/v1/revocations/01JY8RF60000000000000000ZZ/execute"
	swapped.MustVerify = false
	swapped.FailureReason = "@target-uri is a covered component"
	set.Cases = append(set.Cases, swapped)

	// Negative: the body was swapped after signing.
	tampered := attest
	tampered.Name = "tampered body MUST NOT verify"
	tampered.BodyUTF8 = `{"event_id":"01JY8RA3C7K2V9M0QW4T6Z8XPDX"}`
	tampered.MustVerify = false
	tampered.FailureReason = "content-digest is covered, so the body cannot be swapped after signing"
	set.Cases = append(set.Cases, tampered)

	return set, nil
}

func hexAll(in [][]byte) []string {
	out := make([]string, 0, len(in))
	for _, b := range in {
		out = append(out, hex.EncodeToString(b))
	}
	return out
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func quoteOrEmpty(s string) string {
	if s == "" {
		return "(empty)"
	}
	return fmt.Sprintf("%q", s)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "uai-vectors: %v\n", err)
	os.Exit(1)
}

// thumbprintVectors pins RFC 7638 thumbprints for the key types UAI accepts.
//
// The canonical JSON is included because that is where implementations diverge:
// RFC 7638 fixes the member set and their order per key type, and a serializer
// that emits its own field order produces a different thumbprint for the same
// key. Pinning only the digest would let two implementations disagree about WHY
// they agree.
func thumbprintVectors() (any, error) {
	set := testvectors.Set[testvectors.ThumbprintCase]{
		VectorSet:  "uai-cs-1/jwk-thumbprint",
		UAIVersion: "0.1",
		Description: "RFC 7638 JWK thumbprints, rendered in the UAI wire form \"sha256:<hex>\". " +
			"The thumbprint is the subject identifier of a registration proof: both halves of the " +
			"proof sign it, so two implementations that compute it differently do not compose into " +
			"a proof. This is the one digest in UAI that is NOT domain-separated, because RFC 7638 " +
			"fixes its input exactly and a prefix would make it a different function under the same name.",
		Reference: "docs/protocol/04-cryptography.md#72-canonicalization-and-domain-separation",
	}
	inputs := []struct {
		name string
		raw  string
	}{
		{"Ed25519", `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`},
		{"Ed25519 with extra members that are not hashed",
			`{"use":"sig","kid":"ignored","kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","alg":"EdDSA"}`},
		{"P-256", `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`},
		{"P-384", `{"kty":"EC","crv":"P-384","x":"KDwdc2XOR4jyn46_I07f_q1v6Zf76l_6LVjMnfp7HFCLBVJvVbnrsgQPBbSPttDh","y":"lHXJkGHkG4i6Uu_bjBaQRxph2GfteZcp2cks0B29IlYw2E7eMqePnmRmTNrFEu-M"}`},
	}
	for _, in := range inputs {
		jwk, err := uaicrypto.ParseJWK([]byte(in.raw))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", in.name, err)
		}
		// Loudly, not by skipping. A generator that dropped a case it could not
		// produce would quietly ship a smaller vector set than the one the
		// description promises, and the missing key type would be the one
		// nobody found a disagreement in.
		tp, err := jwk.ThumbprintString()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", in.name, err)
		}
		set.Cases = append(set.Cases, testvectors.ThumbprintCase{
			Name: in.name, JWK: json.RawMessage(in.raw),
			CanonicalJSON: uaicrypto.ThumbprintInput(jwk), Thumbprint: tp,
		})
	}
	return set, nil
}

// signingPayloadVectors pins the bytes a signature over a self-signed object
// covers.
//
// §10.4: "jcs-canonicalize A minus signature". Minus, not blank. The document
// here is the SIGNED form -- what actually travels -- and the payload is what a
// verifier must reconstruct from it. An implementation that reconstructs
// anything else produces signatures only it can check.
func signingPayloadVectors() (any, error) {
	set := testvectors.Set[testvectors.SigningPayloadCase]{
		VectorSet:  "attestation/signing-payload",
		UAIVersion: "0.1",
		Description: "What a signature over a self-signed object covers: the document with its " +
			"\"signature\" member REMOVED, canonicalized per RFC 8785, then domain-separated. " +
			"The distinction from blanking the member is four empty strings, and an implementation " +
			"that gets it wrong is byte-correct everywhere else while signing something nobody can " +
			"verify.",
		Reference: "docs/protocol/06-action-attestation.md#104-the-event-chain",
	}

	seed := mustHex("54294285078392269563723994b44bbcd4e41de58bed8d652cd23dc372f9c523")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	signer := uaicrypto.NewEd25519Signer(priv, "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1")

	att := attest.Attestation{
		UAIVersion: "0.1",
		EventID:    "01JY8RA3C7K2V9M0QW4T6Z8XPD",
		AgentDID:   "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
		OwnerDID:   "did:uai:owner:01JY8R9ZB00000000000000000",
		Timestamp:  attest.NewTimestamp(time.Date(2026, 9, 22, 14, 7, 11, 0, time.UTC)),
		Nonce:      "8f1c2b9d4e6a7c3f0b1d2e3a4c5b6d7e",
		Action: attest.Action{
			Type: "route.optimize", Capability: "route.optimize", RiskClass: "LOW",
		},
		Purpose: "delivery_optimization",
		Jurisdiction: attest.Jurisdiction{
			Origin: "AR", Targets: []string{"DE"}, CrossBorder: true, Basis: "resource_location",
		},
		Policy: attest.Policy{
			Version: "GASC-2027.4", BundleHash: "sha256:" + strings.Repeat("b", 64),
			DecisionID: "01JY8RB1Q4X7N2M8V0K3T5S9WE", Decision: "ALLOW",
		},
		InputCommitment:   "sha256:" + strings.Repeat("c", 64),
		OutputCommitment:  "sha256:" + strings.Repeat("d", 64),
		Outcome:           attest.OutcomeSuccess,
		PreviousEventHash: "sha256:" + strings.Repeat("a", 64),
		Sequence:          2,
	}
	signed, err := attest.Sign(signer, att)
	if err != nil {
		return nil, err
	}
	payload, err := signed.SigningBytes()
	if err != nil {
		return nil, err
	}
	document, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(payload)
	set.Cases = append(set.Cases, testvectors.SigningPayloadCase{
		Name: "action attestation", Document: document,
		Payload: string(payload), PayloadSHA: hex.EncodeToString(sum[:]),
		Domain:  string(uaicrypto.DomainAttestation),
		SeedHex: hex.EncodeToString(seed), PublicHex: hex.EncodeToString(pub),
		Signature: signed.Signature.Value, MustVerify: true,
	})

	// The negative case: the payload a naive implementation produces by blanking
	// the member instead of removing it. Pinned so the difference is visible as
	// a vector rather than discovered as a verification failure in production.
	var blanked map[string]any
	if err := json.Unmarshal(document, &blanked); err != nil {
		return nil, err
	}
	blanked["signature"] = map[string]string{"alg": "", "kid": "", "domain": "", "value": ""}
	wrong, err := uaicrypto.Canonicalize(blanked)
	if err != nil {
		return nil, err
	}
	wrongSum := sha256.Sum256(wrong)
	set.Cases = append(set.Cases, testvectors.SigningPayloadCase{
		Name:     "the same attestation with the signature member BLANKED instead of removed",
		Document: document, Payload: string(wrong), PayloadSHA: hex.EncodeToString(wrongSum[:]),
		Domain:  string(uaicrypto.DomainAttestation),
		SeedHex: hex.EncodeToString(seed), PublicHex: hex.EncodeToString(pub),
		Signature: signed.Signature.Value, MustVerify: false,
	})
	return set, nil
}

// voteAssertionVectors pins a delegate's WebAuthn assertion over a vote digest.
//
// Ed25519 (COSE alg -8), not ES256, for one reason: ECDSA signing is
// randomized, so an ES256 vector could pin a signature to VERIFY but never one
// an implementation could reproduce by signing. Ed25519 is deterministic, so
// these vectors check both directions. ES256 is equally accepted by
// pkg/webauthn and is covered by that package's own tests.
//
// §16.1's whole design is here: the challenge in clientDataJSON is the vote
// digest, so the hardware signature covers the voted content and cannot be
// lifted onto a different case, agent, or answer.
func voteAssertionVectors() (any, error) {
	set := testvectors.Set[testvectors.VoteAssertionCase]{
		VectorSet:  "governance/vote-assertion",
		UAIVersion: "0.1",
		Description: "A human delegate's vote, carried by a WebAuthn assertion whose CHALLENGE is " +
			"the vote digest. That is what makes INV-005 cryptographic rather than procedural: the " +
			"signature covers the voted content, so no process that did not touch the authenticator " +
			"can produce one, and an assertion cannot be replayed onto a different vote. An " +
			"assertion with the user-verified flag clear is not a vote and must be refused.",
		Reference: "docs/protocol/10-governance-revocation.md#161-how-a-vote-is-cast",
	}

	const (
		rpID   = "governance.uai.world"
		origin = "https://governance.uai.world"
	)
	seed := mustHex("b1946ac92492d2347c6235b4d2611184cb2c1b8b33f3e0e8f0e2f3d5c6a7b8c9")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	jwk := json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`,
		base64.RawURLEncoding.EncodeToString(pub)))

	statement := governance.Statement{
		CaseID: "UAI-INC-000041", Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
		EvidenceDigest:  "sha256:" + strings.Repeat("3e7b", 16),
		DelegateDID:     "did:uai:delegate:01JY8RD40000000000000000AR",
		Value:           governance.VoteYes,
		Nonce:           "8f1c2b9d4e6a7c3f0b1d2e3a4c5b6d7e",
	}
	digest, err := statement.Digest()
	if err != nil {
		return nil, err
	}
	statementJSON, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}

	// authenticatorData = SHA-256(rpId) || flags || signCount.
	authData := func(flags byte) []byte {
		sum := sha256.Sum256([]byte(rpID))
		out := append([]byte{}, sum[:]...)
		out = append(out, flags)
		return append(out, 0x00, 0x00, 0x00, 0x2a)
	}
	clientData := func(challenge []byte, org string) []byte {
		// Hand-built rather than marshalled from a map, because the exact bytes
		// are what gets hashed: a reordering by a serializer would change the
		// signature without changing anything a reader would notice.
		return []byte(`{"type":"webauthn.get","challenge":"` +
			base64.RawURLEncoding.EncodeToString(challenge) +
			`","origin":"` + org + `","crossOrigin":false}`)
	}
	sign := func(auth, client []byte) string {
		message := append(append([]byte{}, auth...), func() []byte {
			sum := sha256.Sum256(client)
			return sum[:]
		}()...)
		return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, message))
	}

	const (
		flagsUPUV = 0x05 // user present + user verified
		flagsUP   = 0x01 // user present only
	)

	good := clientData(digest, origin)
	set.Cases = append(set.Cases, testvectors.VoteAssertionCase{
		Name: "a delegate votes YES", Statement: statementJSON,
		VoteDigest:        uaicrypto.FormatDigest(digest),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData(flagsUPUV)),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(good),
		Signature:         sign(authData(flagsUPUV), good),
		PublicKeyJWK:      jwk, RelyingPartyID: rpID, Origin: origin,
		UserVerified: true, MustVerify: true,
	})

	// The same signature, over authenticator data whose UV flag is clear. It is
	// cryptographically fine and it is not a vote.
	noUV := authData(flagsUP)
	set.Cases = append(set.Cases, testvectors.VoteAssertionCase{
		Name:      "the same ceremony without user verification is not a vote",
		Statement: statementJSON, VoteDigest: uaicrypto.FormatDigest(digest),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(noUV),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(good),
		Signature:         sign(noUV, good),
		PublicKeyJWK:      jwk, RelyingPartyID: rpID, Origin: origin,
		UserVerified: false, MustVerify: false,
		FailureReason: "INV-005: an assertion without user verification proves a device was " +
			"present, not that a human decided. Counting it would make the threshold mean " +
			"something else.",
	})

	// A YES on one case, presented as a YES on another.
	other := statement
	other.CaseID = "UAI-INC-000042"
	otherDigest, err := other.Digest()
	if err != nil {
		return nil, err
	}
	otherJSON, err := json.Marshal(other)
	if err != nil {
		return nil, err
	}
	set.Cases = append(set.Cases, testvectors.VoteAssertionCase{
		Name:      "an assertion cannot be lifted onto another case",
		Statement: otherJSON, VoteDigest: uaicrypto.FormatDigest(otherDigest),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData(flagsUPUV)),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(good),
		Signature:         sign(authData(flagsUPUV), good),
		PublicKeyJWK:      jwk, RelyingPartyID: rpID, Origin: origin,
		UserVerified: true, MustVerify: false,
		FailureReason: "the challenge inside the assertion is the digest of a different case",
	})

	// Produced for a different site.
	elsewhere := clientData(digest, "https://not-uai.example")
	set.Cases = append(set.Cases, testvectors.VoteAssertionCase{
		Name:      "an assertion produced for another origin is refused",
		Statement: statementJSON, VoteDigest: uaicrypto.FormatDigest(digest),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData(flagsUPUV)),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(elsewhere),
		Signature:         sign(authData(flagsUPUV), elsewhere),
		PublicKeyJWK:      jwk, RelyingPartyID: rpID, Origin: origin,
		UserVerified: true, MustVerify: false,
		FailureReason: "the ceremony happened at another origin",
	})
	return set, nil
}
