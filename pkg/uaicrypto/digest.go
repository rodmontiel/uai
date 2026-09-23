package uaicrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Domain is a domain-separation string. Every digest and every signature in UAI
// is computed over DOMAIN || 0x00 || payload, so that a signature produced in
// one context can never be replayed as valid in another.
type Domain string

// The domain registry defined by UAI v0.1 §7.2. Adding a context means adding a
// constant here; reusing an existing one for a new purpose is a security bug.
const (
	DomainAttestation Domain = "UAI-v1:attestation"
	DomainCredential  Domain = "UAI-v1:credential"
	DomainDIDDocument Domain = "UAI-v1:did-document"
	// DomainRegistration covers the registration record that anchors an
	// identity's event chain (§8.3). It is distinct from DomainAttestation
	// because a genesis record is not a claim about an action: giving them one
	// domain would let a crafted attestation hash be presented as an identity's
	// origin, which is the exact substitution domain separation exists to stop.
	DomainRegistration Domain = "UAI-v1:registration"
	DomainChallenge    Domain = "UAI-v1:challenge"
	DomainVote         Domain = "UAI-v1:vote"
	DomainDecision     Domain = "UAI-v1:decision"
	DomainQuarantine   Domain = "UAI-v1:quarantine"
	DomainRevocation   Domain = "UAI-v1:revocation"
	DomainCheckpoint   Domain = "UAI-v1:checkpoint"
	DomainCommitment   Domain = "UAI-v1:commitment"
	DomainAudit        Domain = "UAI-v1:audit"
)

var knownDomains = map[Domain]bool{
	DomainAttestation: true, DomainCredential: true, DomainDIDDocument: true,
	DomainChallenge: true, DomainVote: true, DomainDecision: true,
	DomainRegistration: true,
	DomainQuarantine:   true, DomainRevocation: true, DomainCheckpoint: true,
	DomainCommitment: true, DomainAudit: true,
}

// ErrUnknownDomain is returned for a domain outside the registry. Verifiers
// reject unknown domains rather than accepting them permissively: an
// unrecognized context is exactly the situation in which a cross-context replay
// would succeed.
var ErrUnknownDomain = errors.New("uaicrypto: unknown domain separation string")

// Valid reports whether d is in the domain registry.
func (d Domain) Valid() bool { return knownDomains[d] }

// SaltLen is the length in bytes of a commitment salt.
const SaltLen = 32

// SigningInput returns DOMAIN || 0x00 || payload, the exact bytes that are
// hashed or signed.
func SigningInput(d Domain, payload []byte) ([]byte, error) {
	if !d.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrUnknownDomain, d)
	}
	out := make([]byte, 0, len(d)+1+len(payload))
	out = append(out, d...)
	out = append(out, 0x00)
	out = append(out, payload...)
	return out, nil
}

// Digest returns SHA-256 over the domain-separated payload.
func Digest(d Domain, payload []byte) ([]byte, error) {
	in, err := SigningInput(d, payload)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(in)
	return sum[:], nil
}

// DigestObject canonicalizes v per RFC 8785 and returns its domain-separated
// digest. This is the function most callers want.
func DigestObject(d Domain, v any) ([]byte, error) {
	canonical, err := Canonicalize(v)
	if err != nil {
		return nil, err
	}
	return Digest(d, canonical)
}

// Salt returns a fresh 32-byte commitment salt.
func Salt() ([]byte, error) {
	s := make([]byte, SaltLen)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("uaicrypto: salt: %w", err)
	}
	return s, nil
}

// Commit returns a salted commitment to content:
//
//	SHA-256("UAI-v1:commitment" || 0x00 || salt || content)
//
// The salt is mandatory and must be at least SaltLen bytes. A bare hash of
// content would be recoverable by dictionary attack whenever the content has
// low entropy — an email address, an amount, a customer ID, a yes/no answer —
// and commitments are published on-chain, where a privacy mistake is permanent.
func Commit(salt, content []byte) ([]byte, error) {
	if len(salt) < SaltLen {
		return nil, fmt.Errorf("uaicrypto: salt must be at least %d bytes, got %d", SaltLen, len(salt))
	}
	payload := make([]byte, 0, len(salt)+len(content))
	payload = append(payload, salt...)
	payload = append(payload, content...)
	return Digest(DomainCommitment, payload)
}

// CommitObject canonicalizes v and commits to its canonical form.
func CommitObject(salt []byte, v any) ([]byte, error) {
	canonical, err := Canonicalize(v)
	if err != nil {
		return nil, err
	}
	return Commit(salt, canonical)
}

// VerifyCommitment reports whether (salt, content) opens the commitment. This
// is the disclosure path: an authorized party is shown the salt and the
// content, and checks the match itself rather than trusting an assertion.
func VerifyCommitment(commitment, salt, content []byte) bool {
	computed, err := Commit(salt, content)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(commitment, computed) == 1
}

// FormatDigest renders a digest in the wire form used throughout UAI:
// "sha256:" followed by lowercase hex.
func FormatDigest(sum []byte) string { return "sha256:" + hex.EncodeToString(sum) }

// ParseDigest parses the "sha256:<hex>" wire form.
func ParseDigest(s string) ([]byte, error) {
	rest, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return nil, fmt.Errorf("uaicrypto: digest %q: missing sha256: prefix", s)
	}
	b, err := hex.DecodeString(rest)
	if err != nil {
		return nil, fmt.Errorf("uaicrypto: digest %q: %w", s, err)
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("uaicrypto: digest %q: got %d bytes, want %d", s, len(b), sha256.Size)
	}
	return b, nil
}
