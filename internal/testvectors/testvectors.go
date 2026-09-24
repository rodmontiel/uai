// Package testvectors loads the normative UAI conformance vectors from
// spec/test-vectors/.
//
// The vectors are the contract between implementations. Two rules make them
// meaningful, and both are enforced by how this package is used:
//
//  1. Tests READ the committed files. They never regenerate them. A test that
//     regenerates its own expectations proves only that the code agrees with
//     itself, which is exactly the gap Phase 2 exists to close.
//  2. The files are language-neutral JSON. Everything an implementer needs is
//     in the file: inputs, intermediate canonical bytes, and expected outputs.
package testvectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Set is one vector file.
type Set[C any] struct {
	VectorSet   string `json:"vector_set"`
	UAIVersion  string `json:"uai_version"`
	Description string `json:"description"`
	Reference   string `json:"reference"`
	Cases       []C    `json:"cases"`
}

// JCSCase covers RFC 8785 canonicalization.
type JCSCase struct {
	Name            string `json:"name"`
	InputJSON       string `json:"input_json"`
	Canonical       string `json:"canonical"`
	CanonicalSHA256 string `json:"canonical_sha256"`
}

// DigestCase covers domain-separated digests.
type DigestCase struct {
	Name            string `json:"name"`
	Domain          string `json:"domain"`
	PayloadUTF8     string `json:"payload_utf8"`
	SigningInputHex string `json:"signing_input_hex"`
	Digest          string `json:"digest"`
}

// ThumbprintCase covers RFC 7638 JWK thumbprints.
//
// The thumbprint is the subject identifier of a registration proof (§8.2): both
// halves sign it, and an owner vouching for a thumbprint the agent's
// implementation computes differently vouches for a key that was never
// presented. That makes agreement between implementations load-bearing, not
// cosmetic.
type ThumbprintCase struct {
	Name          string          `json:"name"`
	JWK           json.RawMessage `json:"jwk"`
	CanonicalJSON string          `json:"canonical_json"`
	Thumbprint    string          `json:"thumbprint"`
}

// CommitmentCase covers salted commitments.
type CommitmentCase struct {
	Name        string `json:"name"`
	SaltHex     string `json:"salt_hex"`
	ContentUTF8 string `json:"content_utf8"`
	Commitment  string `json:"commitment"`
	Opens       bool   `json:"opens"`
}

// MerkleHashCase covers the RFC 6962 leaf and node prefixes.
type MerkleHashCase struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"` // "leaf" | "node" | "empty"
	DataUTF8 string `json:"data_utf8,omitempty"`
	LeftHex  string `json:"left_hex,omitempty"`
	RightHex string `json:"right_hex,omitempty"`
	HashHex  string `json:"hash_hex"`
}

// MerkleTreeCase covers roots, inclusion proofs and consistency proofs.
type MerkleTreeCase struct {
	Name        string              `json:"name"`
	EntriesUTF8 []string            `json:"entries_utf8"`
	Size        uint64              `json:"size"`
	RootHex     string              `json:"root_hex"`
	Inclusion   []MerkleInclusion   `json:"inclusion,omitempty"`
	Consistency []MerkleConsistency `json:"consistency,omitempty"`
}

// MerkleInclusion is one audit path.
type MerkleInclusion struct {
	Index       uint64   `json:"index"`
	LeafHashHex string   `json:"leaf_hash_hex"`
	ProofHex    []string `json:"proof_hex"`
}

// MerkleConsistency proves one snapshot is a prefix of another.
type MerkleConsistency struct {
	First        uint64   `json:"first"`
	Second       uint64   `json:"second"`
	FirstRootHex string   `json:"first_root_hex"`
	ProofHex     []string `json:"proof_hex"`
}

// SignatureCase covers signing and verification. Ed25519 is deterministic
// (RFC 8032), so its signature bytes are pinned. ECDSA is randomized, so those
// cases are verify-only: the committed signature must verify, and the negative
// cases must not.
type SignatureCase struct {
	Name          string `json:"name"`
	Alg           string `json:"alg"`
	SeedHex       string `json:"seed_hex,omitempty"` // Ed25519 only
	PublicKeyHex  string `json:"public_key_hex,omitempty"`
	PublicKeyXHex string `json:"public_key_x_hex,omitempty"` // ECDSA
	PublicKeyYHex string `json:"public_key_y_hex,omitempty"`
	Curve         string `json:"curve,omitempty"`
	Domain        string `json:"domain"`
	PayloadJSON   string `json:"payload_json"`
	Canonical     string `json:"canonical"`
	SignatureB64  string `json:"signature_b64url"`
	VerifyDomain  string `json:"verify_domain"`
	MustVerify    bool   `json:"must_verify"`
	FailureReason string `json:"failure_reason,omitempty"`
}

// IdentifierCase covers UAI-ID and DID parsing and canonicalization.
type IdentifierCase struct {
	Name           string `json:"name"`
	Input          string `json:"input"`
	Valid          bool   `json:"valid"`
	CanonicalUAIID string `json:"canonical_uai_id,omitempty"`
	CanonicalDID   string `json:"canonical_did,omitempty"`
	Entity         string `json:"entity,omitempty"`
	TimestampMS    int64  `json:"timestamp_ms,omitempty"`
	RejectReason   string `json:"reject_reason,omitempty"`
}

// PoPCase covers RFC 9421 HTTP message signatures: signature base
// construction, the Signature-Input field, and the signature itself.
//
// The signature base is pinned as an exact string because it is where
// implementations diverge: a stray newline, an unquoted component name or a
// lowercased method all produce a base that verifies against nothing.
type PoPCase struct {
	Name           string            `json:"name"`
	Method         string            `json:"method"`
	TargetURI      string            `json:"target_uri"`
	Headers        map[string]string `json:"headers"`
	BodyUTF8       string            `json:"body_utf8"`
	Components     []string          `json:"components"`
	Created        int64             `json:"created"`
	KeyID          string            `json:"keyid"`
	Alg            string            `json:"alg"`
	Tag            string            `json:"tag"`
	SignatureInput string            `json:"signature_input"`
	SignatureBase  string            `json:"signature_base"`
	ContentDigest  string            `json:"content_digest"`
	SeedHex        string            `json:"seed_hex,omitempty"`
	PublicKeyHex   string            `json:"public_key_hex,omitempty"`
	SignatureB64   string            `json:"signature_b64,omitempty"`
	VerifyTag      string            `json:"verify_tag,omitempty"`
	MustVerify     bool              `json:"must_verify"`
	FailureReason  string            `json:"failure_reason,omitempty"`
}

// ChainCase covers the per-agent attestation hash chain, including the fork
// that a cloned agent or stolen key produces.
type ChainCase struct {
	Name              string          `json:"name"`
	Attestation       json.RawMessage `json:"attestation"`
	Canonical         string          `json:"canonical"`
	EventHash         string          `json:"event_hash"`
	PreviousEventHash string          `json:"previous_event_hash,omitempty"`
	IsFork            bool            `json:"is_fork,omitempty"`
	ForkNote          string          `json:"fork_note,omitempty"`
}

// SigningPayloadCase covers what a signature over a self-signed object
// actually covers: the document with its `signature` member REMOVED (§10.4).
//
// It exists because the alternative reading -- blank the member, keep the key --
// is what a struct-based implementation produces by accident, and the two
// disagree on four empty strings that no reader of the spec would think to add.
// An implementation can be byte-correct on every other vector and still sign
// something nobody else can verify.
type SigningPayloadCase struct {
	Name       string          `json:"name"`
	Document   json.RawMessage `json:"document"`
	Payload    string          `json:"signing_payload"`
	PayloadSHA string          `json:"signing_payload_sha256"`
	Domain     string          `json:"domain"`
	SeedHex    string          `json:"seed_hex"`
	PublicHex  string          `json:"public_key_hex"`
	Signature  string          `json:"signature_b64url"`
	MustVerify bool            `json:"must_verify"`
}

// Root returns the repository root, located relative to this source file so
// that tests work regardless of the package they run from.
func Root() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("testvectors: cannot locate source file")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// Dir returns the absolute path of spec/test-vectors.
func Dir() string { return filepath.Join(Root(), "spec", "test-vectors") }

// Load reads a vector file by its path relative to spec/test-vectors.
func Load[C any](relPath string) (Set[C], error) {
	var set Set[C]
	full := filepath.Join(Dir(), filepath.FromSlash(relPath))
	raw, err := os.ReadFile(full)
	if err != nil {
		return set, fmt.Errorf("testvectors: %w", err)
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return set, fmt.Errorf("testvectors: %s: %w", relPath, err)
	}
	if len(set.Cases) == 0 {
		return set, fmt.Errorf("testvectors: %s has no cases", relPath)
	}
	return set, nil
}

// MustLoad is Load for tests; it panics on error so a missing or malformed
// vector file fails loudly rather than silently skipping conformance.
func MustLoad[C any](relPath string) Set[C] {
	set, err := Load[C](relPath)
	if err != nil {
		panic(err)
	}
	return set
}
