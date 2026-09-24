// Package conformance runs the committed UAI test vectors against this
// implementation.
//
// It is the single source of truth for what "conformant" means. The package
// tests and the uai-conformance CLI both call these functions, so the checks
// cannot drift apart — duplicated cryptographic assertions are exactly the kind
// of divergence that lets a real defect pass one runner and fail the other.
//
// An implementation in another language reproduces this file's logic against
// the same JSON vectors. Nothing here depends on Go beyond the standard library.
package conformance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/rodmontiel/uai/internal/testvectors"
	"github.com/rodmontiel/uai/pkg/governance"
	"github.com/rodmontiel/uai/pkg/merkle"
	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
	"github.com/rodmontiel/uai/pkg/webauthn"
)

// CaseResult is the outcome of one vector case.
type CaseResult struct {
	Name   string
	OK     bool
	Detail string
}

// Result is the outcome of one vector set.
type Result struct {
	Set         string
	File        string
	Description string
	Cases       []CaseResult
	LoadError   error
}

// Failures returns the cases that did not pass.
func (r Result) Failures() []CaseResult {
	var out []CaseResult
	for _, c := range r.Cases {
		if !c.OK {
			out = append(out, c)
		}
	}
	return out
}

// OK reports whether the whole set passed.
func (r Result) OK() bool { return r.LoadError == nil && len(r.Failures()) == 0 }

// All runs every vector set.
func All() []Result {
	return []Result{
		JCS(), Digest(), Commitment(), Thumbprint(), MerkleHashing(), MerkleProofs(),
		Ed25519(), ECDSA(), Identifiers(), EventChain(), SigningPayload(), PoP(),
		VoteAssertions(),
	}
}

// PoPSets runs the sets that pkg/pop is responsible for.
func PoPSets() []Result { return []Result{PoP()} }

// CryptoSets runs the sets that pkg/uaicrypto is responsible for.
func CryptoSets() []Result {
	return []Result{
		JCS(), Digest(), Commitment(), Thumbprint(), Ed25519(), ECDSA(), EventChain(),
		SigningPayload(),
	}
}

// MerkleSets runs the sets that pkg/merkle is responsible for.
func MerkleSets() []Result { return []Result{MerkleHashing(), MerkleProofs()} }

// IdentifierSets runs the sets that pkg/uaiid is responsible for.
func IdentifierSets() []Result { return []Result{Identifiers()} }

func pass(name string) CaseResult { return CaseResult{Name: name, OK: true} }

func fail(name, format string, args ...any) CaseResult {
	return CaseResult{Name: name, OK: false, Detail: fmt.Sprintf(format, args...)}
}

// JCS checks RFC 8785 canonicalization.
func JCS() Result {
	const file = "jcs/canonicalization.json"
	r := Result{Set: "uai-cs-1/jcs", File: file}
	set, err := testvectors.Load[testvectors.JCSCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		got, err := uaicrypto.CanonicalizeJSON([]byte(c.InputJSON))
		switch {
		case err != nil:
			r.Cases = append(r.Cases, fail(c.Name, "canonicalize: %v", err))
		case string(got) != c.Canonical:
			r.Cases = append(r.Cases, fail(c.Name, "canonical bytes differ\n  got:  %s\n  want: %s", got, c.Canonical))
		default:
			sum := sha256.Sum256(got)
			if hex.EncodeToString(sum[:]) != c.CanonicalSHA256 {
				r.Cases = append(r.Cases, fail(c.Name, "digest %s, want %s", hex.EncodeToString(sum[:]), c.CanonicalSHA256))
			} else {
				r.Cases = append(r.Cases, pass(c.Name))
			}
		}
	}
	return r
}

// Digest checks domain-separated digests, including the property that two
// domains never share a digest for the same payload.
func Digest() Result {
	const file = "digest/domain-separation.json"
	r := Result{Set: "uai-cs-1/digest", File: file}
	set, err := testvectors.Load[testvectors.DigestCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	seen := map[string]string{}
	for _, c := range set.Cases {
		in, err := uaicrypto.SigningInput(uaicrypto.Domain(c.Domain), []byte(c.PayloadUTF8))
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "signing input: %v", err))
			continue
		}
		if hex.EncodeToString(in) != c.SigningInputHex {
			r.Cases = append(r.Cases, fail(c.Name, "signing input %s, want %s", hex.EncodeToString(in), c.SigningInputHex))
			continue
		}
		sum, err := uaicrypto.Digest(uaicrypto.Domain(c.Domain), []byte(c.PayloadUTF8))
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "digest: %v", err))
			continue
		}
		if uaicrypto.FormatDigest(sum) != c.Digest {
			r.Cases = append(r.Cases, fail(c.Name, "digest %s, want %s", uaicrypto.FormatDigest(sum), c.Digest))
			continue
		}
		if prev, dup := seen[c.Digest]; dup {
			r.Cases = append(r.Cases, fail(c.Name, "domains %q and %q share a digest: domain separation is not in effect", prev, c.Domain))
			continue
		}
		seen[c.Digest] = c.Domain
		r.Cases = append(r.Cases, pass(c.Name))
	}
	return r
}

// Commitment checks salted commitments, including that a wrong opening fails.
func Commitment() Result {
	const file = "commitment/salted-commitment.json"
	r := Result{Set: "uai-cs-1/commitment", File: file}
	set, err := testvectors.Load[testvectors.CommitmentCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		salt, err := hex.DecodeString(c.SaltHex)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "salt: %v", err))
			continue
		}
		commitment, err := uaicrypto.ParseDigest(c.Commitment)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "commitment: %v", err))
			continue
		}
		if opens := uaicrypto.VerifyCommitment(commitment, salt, []byte(c.ContentUTF8)); opens != c.Opens {
			r.Cases = append(r.Cases, fail(c.Name, "opens = %v, want %v", opens, c.Opens))
			continue
		}
		r.Cases = append(r.Cases, pass(c.Name))
	}
	return r
}

// Thumbprint checks RFC 7638 JWK thumbprints, including the exact bytes hashed.
//
// The canonical JSON is checked as well as the digest, because pinning only the
// digest would let two implementations agree by accident on the key types the
// vectors happen to cover and diverge on the first one they do not.
func Thumbprint() Result {
	const file = "keys/jwk-thumbprint.json"
	r := Result{Set: "uai-cs-1/jwk-thumbprint", File: file}
	set, err := testvectors.Load[testvectors.ThumbprintCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		jwk, err := uaicrypto.ParseJWK(c.JWK)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "parse jwk: %v", err))
			continue
		}
		if got := uaicrypto.ThumbprintInput(jwk); got != c.CanonicalJSON {
			r.Cases = append(r.Cases, fail(c.Name, "canonical json\n  got:  %s\n  want: %s",
				got, c.CanonicalJSON))
			continue
		}
		got, err := jwk.ThumbprintString()
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "thumbprint: %v", err))
			continue
		}
		if got != c.Thumbprint {
			r.Cases = append(r.Cases, fail(c.Name, "thumbprint = %s, want %s", got, c.Thumbprint))
			continue
		}
		r.Cases = append(r.Cases, pass(c.Name))
	}
	return r
}

// SigningPayload checks what a signature over a self-signed object covers.
//
// The bytes are compared, not only the verification outcome. A verifier that
// rebuilt a different payload and happened to reject a bad signature would pass
// an outcome-only check while being unable to verify a good one.
func SigningPayload() Result {
	const file = "attestation/signing-payload.json"
	r := Result{Set: "attestation/signing-payload", File: file}
	set, err := testvectors.Load[testvectors.SigningPayloadCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		payload, err := uaicrypto.CanonicalizeWithout(json.RawMessage(c.Document), "signature")
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "canonicalize: %v", err))
			continue
		}
		// Only the positive case pins the payload we must reproduce; the
		// negative one pins the payload we must NOT produce.
		if c.MustVerify && string(payload) != c.Payload {
			r.Cases = append(r.Cases, fail(c.Name,
				"signing payload differs\n  got:  %s\n  want: %s", payload, c.Payload))
			continue
		}
		if !c.MustVerify && string(payload) == c.Payload {
			r.Cases = append(r.Cases, fail(c.Name,
				"the implementation produced the payload the vector marks as wrong"))
			continue
		}
		pubBytes, err := hex.DecodeString(c.PublicHex)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "public key: %v", err))
			continue
		}
		sig := uaicrypto.Signature{
			Alg: uaicrypto.AlgEdDSA, KID: "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1",
			Domain: uaicrypto.Domain(c.Domain), Value: c.Signature,
		}
		verifyErr := uaicrypto.Verify(ed25519.PublicKey(pubBytes),
			uaicrypto.Domain(c.Domain), []byte(c.Payload), sig)
		if (verifyErr == nil) != c.MustVerify {
			r.Cases = append(r.Cases, fail(c.Name,
				"verification outcome = %v, want must_verify=%v", verifyErr == nil, c.MustVerify))
			continue
		}
		r.Cases = append(r.Cases, pass(c.Name))
	}
	return r
}

// VoteAssertions checks a delegate's WebAuthn assertion over a vote digest.
//
// Both directions are checked: the digest recomputed from the statement, and
// the assertion accepted or refused as the vector says. An implementation that
// agreed on the digest but accepted an assertion without user verification
// would recompute tallies that include votes no human cast.
func VoteAssertions() Result {
	const file = "governance/vote-assertion.json"
	r := Result{Set: "governance/vote-assertion", File: file}
	set, err := testvectors.Load[testvectors.VoteAssertionCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		var statement governance.Statement
		if err := json.Unmarshal(c.Statement, &statement); err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "statement: %v", err))
			continue
		}
		digest, err := statement.Digest()
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "vote digest: %v", err))
			continue
		}
		if got := uaicrypto.FormatDigest(digest); got != c.VoteDigest {
			r.Cases = append(r.Cases, fail(c.Name, "vote digest = %s, want %s", got, c.VoteDigest))
			continue
		}
		pub, err := uaicrypto.PublicFromJWKBytes(c.PublicKeyJWK)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "delegate key: %v", err))
			continue
		}
		assertion := webauthn.Assertion{
			AuthenticatorData: b64url(c.AuthenticatorData),
			ClientDataJSON:    b64url(c.ClientDataJSON),
			Signature:         b64url(c.Signature),
		}
		verifyErr := webauthn.Verify(pub, assertion, webauthn.Expectation{
			Challenge: digest, Origin: c.Origin, RelyingPartyID: c.RelyingPartyID,
		})
		accepted := verifyErr == nil
		switch {
		case c.MustVerify && !accepted:
			r.Cases = append(r.Cases, fail(c.Name, "expected acceptance: %v", verifyErr))
		case !c.MustVerify && accepted:
			r.Cases = append(r.Cases, fail(c.Name,
				"expected the assertion to be REFUSED (%s) but it was accepted", c.FailureReason))
		default:
			r.Cases = append(r.Cases, pass(c.Name))
		}
	}
	return r
}

// b64url decodes an unpadded base64url field, returning nil on failure so the
// verification step reports the refusal rather than this helper.
func b64url(s string) []byte {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return raw
}

// MerkleHashing checks the RFC 6962 leaf and node prefixes.
func MerkleHashing() Result {
	const file = "merkle/hashing.json"
	r := Result{Set: "uai-cs-1/merkle-hashing", File: file}
	set, err := testvectors.Load[testvectors.MerkleHashCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		var got []byte
		switch c.Kind {
		case "empty":
			got = merkle.EmptyRoot()
		case "leaf":
			got = merkle.LeafHash([]byte(c.DataUTF8))
		case "node":
			l, err1 := hex.DecodeString(c.LeftHex)
			rr, err2 := hex.DecodeString(c.RightHex)
			if err1 != nil || err2 != nil {
				r.Cases = append(r.Cases, fail(c.Name, "decode children"))
				continue
			}
			got = merkle.NodeHash(l, rr)
		default:
			r.Cases = append(r.Cases, fail(c.Name, "unknown kind %q", c.Kind))
			continue
		}
		if hex.EncodeToString(got) != c.HashHex {
			r.Cases = append(r.Cases, fail(c.Name, "hash %s, want %s", hex.EncodeToString(got), c.HashHex))
			continue
		}
		r.Cases = append(r.Cases, pass(c.Name))
	}
	return r
}

// MerkleProofs checks roots, inclusion proofs and consistency proofs. Proofs
// are verified from the committed bytes, not from freshly generated ones:
// verifying our own output would not demonstrate interoperability.
func MerkleProofs() Result {
	const file = "merkle/tree-proofs.json"
	r := Result{Set: "uai-cs-1/merkle-proofs", File: file}
	set, err := testvectors.Load[testvectors.MerkleTreeCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		tree := merkle.New()
		for _, e := range c.EntriesUTF8 {
			tree.Append([]byte(e))
		}
		root := tree.Root()
		if hex.EncodeToString(root) != c.RootHex {
			r.Cases = append(r.Cases, fail(c.Name, "root %s, want %s", hex.EncodeToString(root), c.RootHex))
			continue
		}
		bad := ""
		for _, inc := range c.Inclusion {
			proof, err := tree.InclusionProof(inc.Index, c.Size)
			if err != nil {
				bad = fmt.Sprintf("inclusion %d: %v", inc.Index, err)
				break
			}
			if !sameHex(proof, inc.ProofHex) {
				bad = fmt.Sprintf("inclusion %d: audit path differs from the committed proof", inc.Index)
				break
			}
			leaf, err := hex.DecodeString(inc.LeafHashHex)
			if err != nil {
				bad = fmt.Sprintf("inclusion %d: leaf hash: %v", inc.Index, err)
				break
			}
			committed, err := unhexAll(inc.ProofHex)
			if err != nil {
				bad = fmt.Sprintf("inclusion %d: proof: %v", inc.Index, err)
				break
			}
			if err := merkle.VerifyInclusion(inc.Index, c.Size, leaf, root, committed); err != nil {
				bad = fmt.Sprintf("inclusion %d: committed proof failed to verify: %v", inc.Index, err)
				break
			}
		}
		if bad == "" {
			for _, con := range c.Consistency {
				proof, err := tree.ConsistencyProof(con.First, con.Second)
				if err != nil {
					bad = fmt.Sprintf("consistency %d->%d: %v", con.First, con.Second, err)
					break
				}
				if !sameHex(proof, con.ProofHex) {
					bad = fmt.Sprintf("consistency %d->%d: proof differs from the committed one", con.First, con.Second)
					break
				}
				firstRoot, err := hex.DecodeString(con.FirstRootHex)
				if err != nil {
					bad = fmt.Sprintf("consistency %d->%d: first root: %v", con.First, con.Second, err)
					break
				}
				committed, err := unhexAll(con.ProofHex)
				if err != nil {
					bad = fmt.Sprintf("consistency %d->%d: proof: %v", con.First, con.Second, err)
					break
				}
				if err := merkle.VerifyConsistency(con.First, con.Second, firstRoot, root, committed); err != nil {
					bad = fmt.Sprintf("consistency %d->%d: committed proof failed to verify: %v", con.First, con.Second, err)
					break
				}
			}
		}
		if bad != "" {
			r.Cases = append(r.Cases, fail(c.Name, "%s", bad))
			continue
		}
		r.Cases = append(r.Cases, pass(c.Name))
	}
	return r
}

// Ed25519 checks deterministic signature reproduction and the negative cases.
func Ed25519() Result {
	const file = "signature/ed25519.json"
	r := Result{Set: "uai-cs-1/ed25519", File: file}
	set, err := testvectors.Load[testvectors.SignatureCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		seed, err := hex.DecodeString(c.SeedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			r.Cases = append(r.Cases, fail(c.Name, "seed: %v", err))
			continue
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pubBytes, err := hex.DecodeString(c.PublicKeyHex)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "public key: %v", err))
			continue
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pubBytes) {
			r.Cases = append(r.Cases, fail(c.Name, "seed does not derive the committed public key"))
			continue
		}
		// Ed25519 is deterministic: reproduce the signature exactly.
		if c.MustVerify {
			produced, err := uaicrypto.NewEd25519Signer(priv, "vector").Sign(uaicrypto.Domain(c.Domain), []byte(c.Canonical))
			if err != nil {
				r.Cases = append(r.Cases, fail(c.Name, "sign: %v", err))
				continue
			}
			if produced.Value != c.SignatureB64 {
				r.Cases = append(r.Cases, fail(c.Name, "signature differs\n  got:  %s\n  want: %s", produced.Value, c.SignatureB64))
				continue
			}
		}
		sig := uaicrypto.Signature{Alg: uaicrypto.Algorithm(c.Alg), Domain: uaicrypto.Domain(c.Domain), Value: c.SignatureB64}
		err = uaicrypto.Verify(ed25519.PublicKey(pubBytes), uaicrypto.Domain(c.VerifyDomain), []byte(c.Canonical), sig)
		r.Cases = append(r.Cases, verdict(c, err))
	}
	return r
}

// ECDSA checks verify-only cases for P-256 and P-384.
func ECDSA() Result {
	const file = "signature/ecdsa.json"
	r := Result{Set: "uai-cs-1/ecdsa", File: file}
	set, err := testvectors.Load[testvectors.SignatureCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		pub, err := ecdsaPublicKey(c.Curve, c.PublicKeyXHex, c.PublicKeyYHex)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "public key: %v", err))
			continue
		}
		sig := uaicrypto.Signature{Alg: uaicrypto.Algorithm(c.Alg), Domain: uaicrypto.Domain(c.Domain), Value: c.SignatureB64}
		err = uaicrypto.Verify(pub, uaicrypto.Domain(c.VerifyDomain), []byte(c.Canonical), sig)
		r.Cases = append(r.Cases, verdict(c, err))
	}
	return r
}

// Identifiers checks UAI-ID and DID parsing and canonicalization.
func Identifiers() Result {
	const file = "identifier/uai-id.json"
	r := Result{Set: "uai-id/parsing", File: file}
	set, err := testvectors.Load[testvectors.IdentifierCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description
	for _, c := range set.Cases {
		id, err := uaiid.Parse(c.Input)
		if !c.Valid {
			if err == nil {
				r.Cases = append(r.Cases, fail(c.Name, "expected rejection (%s) but the input parsed", c.RejectReason))
			} else {
				r.Cases = append(r.Cases, pass(c.Name))
			}
			continue
		}
		switch {
		case err != nil:
			r.Cases = append(r.Cases, fail(c.Name, "parse: %v", err))
		case id.String() != c.CanonicalUAIID:
			r.Cases = append(r.Cases, fail(c.Name, "canonical UAI-ID %q, want %q", id.String(), c.CanonicalUAIID))
		case id.DID() != c.CanonicalDID:
			r.Cases = append(r.Cases, fail(c.Name, "canonical DID %q, want %q", id.DID(), c.CanonicalDID))
		case string(id.Entity()) != c.Entity:
			r.Cases = append(r.Cases, fail(c.Name, "entity %q, want %q", id.Entity(), c.Entity))
		case id.Time().UnixMilli() != c.TimestampMS:
			r.Cases = append(r.Cases, fail(c.Name, "timestamp %d ms, want %d ms", id.Time().UnixMilli(), c.TimestampMS))
		case id.DID() != "did:"+id.String():
			r.Cases = append(r.Cases, fail(c.Name, "the DID is not the UAI-ID with a did: prefix"))
		default:
			r.Cases = append(r.Cases, pass(c.Name))
		}
	}
	return r
}

// EventChain checks attestation hashing, chain linkage and fork detection.
func EventChain() Result {
	const file = "attestation/event-chain.json"
	r := Result{Set: "attestation/event-chain", File: file}
	set, err := testvectors.Load[testvectors.ChainCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description

	var prevHash string
	successors := map[string][]string{}
	for _, c := range set.Cases {
		canonical, err := uaicrypto.CanonicalizeJSON(c.Attestation)
		switch {
		case err != nil:
			r.Cases = append(r.Cases, fail(c.Name, "canonicalize: %v", err))
		case string(canonical) != c.Canonical:
			r.Cases = append(r.Cases, fail(c.Name, "canonical bytes differ"))
		default:
			sum, err := uaicrypto.Digest(uaicrypto.DomainAttestation, canonical)
			if err != nil {
				r.Cases = append(r.Cases, fail(c.Name, "digest: %v", err))
			} else if uaicrypto.FormatDigest(sum) != c.EventHash {
				r.Cases = append(r.Cases, fail(c.Name, "event hash %s, want %s", uaicrypto.FormatDigest(sum), c.EventHash))
			} else if !c.IsFork && prevHash != "" && c.PreviousEventHash != prevHash {
				r.Cases = append(r.Cases, fail(c.Name, "chain broken: previous_event_hash %s, want %s", c.PreviousEventHash, prevHash))
			} else {
				r.Cases = append(r.Cases, pass(c.Name))
			}
		}
		successors[c.PreviousEventHash] = append(successors[c.PreviousEventHash], c.EventHash)
		if !c.IsFork {
			prevHash = c.EventHash
		}
	}

	forks := 0
	for _, s := range successors {
		if len(s) > 1 {
			forks++
		}
	}
	if forks == 1 {
		r.Cases = append(r.Cases, pass("fork is detectable: exactly one predecessor has two successors"))
	} else {
		r.Cases = append(r.Cases, fail("fork is detectable",
			"expected exactly one forked predecessor, found %d — without a fork the vectors cannot demonstrate clone detection", forks))
	}
	return r
}

// PoP checks RFC 9421 signature base construction and HTTP message signatures.
//
// The base is compared as an exact string. That is the point of this set: two
// implementations that agree on the crypto but disagree on a newline cannot
// verify each other, and the disagreement is invisible until it matters.
func PoP() Result {
	const file = "pop/rfc9421.json"
	r := Result{Set: "uai-cs-1/pop-rfc9421", File: file}
	set, err := testvectors.Load[testvectors.PoPCase](file)
	if err != nil {
		r.LoadError = err
		return r
	}
	r.Description = set.Description

	for _, c := range set.Cases {
		req, err := http.NewRequest(c.Method, c.TargetURI, nil)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "build request: %v", err))
			continue
		}
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}

		// The verifier sees the tag as presented, which for the cross-domain
		// case is not the tag that was signed.
		verifyTag := c.VerifyTag
		if verifyTag == "" {
			verifyTag = c.Tag
		}
		params := pop.Params{
			Components: c.Components, Created: c.Created,
			KeyID: c.KeyID, Alg: c.Alg, Tag: verifyTag,
		}
		base, err := pop.SignatureBase(pop.FromRequest(req, "https"), params)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "signature base: %v", err))
			continue
		}

		// An untampered case must reproduce the committed base exactly.
		untampered := verifyTag == c.Tag && c.TargetURI != "" && c.MustVerify
		if untampered && string(base) != c.SignatureBase {
			r.Cases = append(r.Cases, fail(c.Name,
				"signature base differs\n  got:\n%s\n  want:\n%s", base, c.SignatureBase))
			continue
		}

		digestErr := pop.VerifyContentDigest(c.ContentDigest, []byte(c.BodyUTF8))
		pubBytes, err := hex.DecodeString(c.PublicKeyHex)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "public key: %v", err))
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(c.SignatureB64)
		if err != nil {
			r.Cases = append(r.Cases, fail(c.Name, "signature: %v", err))
			continue
		}
		sigErr := uaicrypto.VerifyHTTPSignatureBase(ed25519.PublicKey(pubBytes), c.Alg, base, sig)

		accepted := digestErr == nil && sigErr == nil
		switch {
		case c.MustVerify && !accepted:
			detail := "expected the request to be accepted"
			if digestErr != nil {
				detail += "; digest: " + digestErr.Error()
			}
			if sigErr != nil {
				detail += "; signature: " + sigErr.Error()
			}
			r.Cases = append(r.Cases, fail(c.Name, "%s", detail))
		case !c.MustVerify && accepted:
			r.Cases = append(r.Cases, fail(c.Name,
				"expected the request to be REJECTED (%s) but it was accepted", c.FailureReason))
		default:
			r.Cases = append(r.Cases, pass(c.Name))
		}
	}
	return r
}

func verdict(c testvectors.SignatureCase, err error) CaseResult {
	switch {
	case c.MustVerify && err != nil:
		return fail(c.Name, "expected verification to succeed: %v", err)
	case !c.MustVerify && err == nil:
		return fail(c.Name, "expected verification to FAIL (%s) but it succeeded", c.FailureReason)
	default:
		return pass(c.Name)
	}
}

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

func sameHex(actual [][]byte, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i := range actual {
		if hex.EncodeToString(actual[i]) != expected[i] {
			return false
		}
	}
	return true
}

func unhexAll(in []string) ([][]byte, error) {
	out := make([][]byte, 0, len(in))
	for _, s := range in {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}
