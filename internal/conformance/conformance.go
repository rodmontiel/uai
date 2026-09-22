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
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/rodmontiel/uai/internal/testvectors"
	"github.com/rodmontiel/uai/pkg/merkle"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
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
		JCS(), Digest(), Commitment(), MerkleHashing(), MerkleProofs(),
		Ed25519(), ECDSA(), Identifiers(), EventChain(),
	}
}

// CryptoSets runs the sets that pkg/uaicrypto is responsible for.
func CryptoSets() []Result {
	return []Result{JCS(), Digest(), Commitment(), Ed25519(), ECDSA(), EventChain()}
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
