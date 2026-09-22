// Package receipt implements UAI transparency checkpoints and receipts.
//
// A receipt turns a signed statement into a Transparent Statement: something a
// third party can verify with no UAI service running, using only the log's
// public key, the witness key set and (for full assurance) a chain anchor.
// That is the design goal — evidence that survives the disappearance of its
// issuer.
//
// Two properties are worth stating because they are easy to lose:
//
//   - Witness co-signatures are what makes a split view detectable. A log
//     operator showing two verifiers different histories must obtain witness
//     signatures over inconsistent checkpoints, and an honest witness refuses
//     because it checks consistency against what it already signed.
//   - An unanchored receipt is a weaker claim than an anchored one. Verifiers
//     must be able to express that difference rather than silently treating a
//     log-only assertion as fully verified.
package receipt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rodmontiel/uai/pkg/merkle"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Status is the strength of a verified receipt.
type Status string

// Verification outcomes.
const (
	// StatusVerified means the statement is in a witnessed, anchored log.
	StatusVerified Status = "VERIFIED"
	// StatusVerifiedUnanchored means the log and its witnesses vouch for the
	// statement, but no on-chain anchor covers it yet. Between an event and its
	// next anchor there is a window (target: <= 60s) in which this is the
	// strongest truthful answer.
	StatusVerifiedUnanchored Status = "VERIFIED_UNANCHORED"
	// StatusUnderwitnessed means fewer independent witnesses co-signed the
	// checkpoint than policy requires.
	StatusUnderwitnessed Status = "UNDERWITNESSED"
)

var (
	// ErrBadInclusion is returned when the audit path does not reconstruct the root.
	ErrBadInclusion = errors.New("receipt: inclusion proof does not reconstruct the checkpoint root")
	// ErrBadLogSignature is returned when the log's checkpoint signature fails.
	ErrBadLogSignature = errors.New("receipt: checkpoint signature is not valid")
	// ErrUnknownLogKey is returned when the checkpoint is signed by an unknown key.
	ErrUnknownLogKey = errors.New("receipt: checkpoint signed by an unknown log key")
	// ErrNotEnoughWitnesses is returned when too few witnesses co-signed.
	ErrNotEnoughWitnesses = errors.New("receipt: too few witness co-signatures")
	// ErrMalformedCheckpoint is returned for an unparsable checkpoint.
	ErrMalformedCheckpoint = errors.New("receipt: malformed checkpoint")
	// ErrLeafMismatch is returned when the receipt does not describe the statement.
	ErrLeafMismatch = errors.New("receipt: leaf hash does not match the statement")
	// ErrIndexOutOfTree is returned when the index is not inside the checkpoint.
	ErrIndexOutOfTree = errors.New("receipt: log index is not inside the checkpoint")
)

// Checkpoint is a signed commitment to the log at one size.
type Checkpoint struct {
	Origin    string    `json:"origin"`
	Size      uint64    `json:"size"`
	Root      []byte    `json:"-"`
	RootB64   string    `json:"root"`
	Timestamp time.Time `json:"timestamp"`
}

// Body returns the canonical bytes a checkpoint signature covers.
//
// The format follows the C2SP tlog-checkpoint note: origin, size and root, one
// per line, each line terminated. Keeping the trailing newline matters — a
// verifier that drops it computes a different signing input and rejects every
// genuine checkpoint.
func (c Checkpoint) Body() []byte {
	root := c.RootB64
	if root == "" {
		root = base64.StdEncoding.EncodeToString(c.Root)
	}
	return []byte(c.Origin + "\n" + strconv.FormatUint(c.Size, 10) + "\n" + root + "\n")
}

// ParseCheckpointBody parses the canonical checkpoint body.
func ParseCheckpointBody(body []byte) (Checkpoint, error) {
	lines := strings.Split(string(body), "\n")
	if len(lines) < 4 || lines[0] == "" || lines[3] != "" {
		return Checkpoint{}, fmt.Errorf("%w: expected origin, size and root, each newline-terminated", ErrMalformedCheckpoint)
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: size: %v", ErrMalformedCheckpoint, err)
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: root: %v", ErrMalformedCheckpoint, err)
	}
	if len(root) != merkle.HashSize {
		return Checkpoint{}, fmt.Errorf("%w: root is %d bytes, want %d", ErrMalformedCheckpoint, len(root), merkle.HashSize)
	}
	return Checkpoint{Origin: lines[0], Size: size, Root: root, RootB64: lines[2]}, nil
}

// WitnessSignature is one independent co-signature over a checkpoint.
type WitnessSignature struct {
	Witness   string `json:"witness"`
	Signature string `json:"value"` // base64url, no padding
}

// Anchor records where a checkpoint was committed on-chain.
type Anchor struct {
	ChainID uint64 `json:"chain_id"`
	Tx      string `json:"tx"`
	Block   uint64 `json:"block"`
	Epoch   uint64 `json:"epoch"`
}

// Receipt proves a statement is at a given index of the log.
type Receipt struct {
	LogOrigin         string              `json:"log_origin"`
	LogIndex          uint64              `json:"log_index"`
	LeafHash          string              `json:"leaf_hash"` // sha256:<hex>
	Checkpoint        Checkpoint          `json:"checkpoint"`
	InclusionProof    []string            `json:"inclusion_proof"` // sha256:<hex>
	LogSignature      uaicrypto.Signature `json:"log_signature"`
	WitnessSignatures []WitnessSignature  `json:"witness_signatures,omitempty"`
	Anchor            *Anchor             `json:"anchor,omitempty"`
}

// Issue builds a receipt for a leaf in a tree.
func Issue(logSigner uaicrypto.Signer, origin string, tree *merkle.Tree, index uint64, at time.Time) (Receipt, error) {
	size := tree.Size()
	if index >= size {
		return Receipt{}, fmt.Errorf("%w: index %d, size %d", ErrIndexOutOfTree, index, size)
	}
	leaf, err := tree.LeafHashAt(index)
	if err != nil {
		return Receipt{}, err
	}
	proof, err := tree.InclusionProof(index, size)
	if err != nil {
		return Receipt{}, err
	}
	root := tree.Root()
	cp := Checkpoint{
		Origin:    origin,
		Size:      size,
		Root:      root,
		RootB64:   base64.StdEncoding.EncodeToString(root),
		Timestamp: at.UTC(),
	}
	sig, err := logSigner.Sign(uaicrypto.DomainCheckpoint, cp.Body())
	if err != nil {
		return Receipt{}, err
	}
	r := Receipt{
		LogOrigin:      origin,
		LogIndex:       index,
		LeafHash:       uaicrypto.FormatDigest(leaf),
		Checkpoint:     cp,
		InclusionProof: make([]string, 0, len(proof)),
		LogSignature:   sig,
	}
	for _, h := range proof {
		r.InclusionProof = append(r.InclusionProof, uaicrypto.FormatDigest(h))
	}
	return r, nil
}

// CoSign produces a witness co-signature over a checkpoint.
func CoSign(witness uaicrypto.Signer, name string, cp Checkpoint) (WitnessSignature, error) {
	sig, err := witness.Sign(uaicrypto.DomainCheckpoint, cp.Body())
	if err != nil {
		return WitnessSignature{}, err
	}
	return WitnessSignature{Witness: name, Signature: sig.Value}, nil
}

// TrustAnchors are the keys a verifier trusts, from section 5.1 of the
// specification. A verifier holding these needs nothing from the log operator.
type TrustAnchors struct {
	// LogKeys maps a verification method identifier to its public key.
	LogKeys map[string]any
	// WitnessKeys maps a witness name to its public key.
	WitnessKeys map[string]any
	// MinWitnesses is the number of independent co-signatures policy requires.
	MinWitnesses int
}

// Verify checks a receipt against a statement and the trust anchors.
//
// It returns the strongest status the evidence supports, and never silently
// upgrades a log-only claim to a full one.
func Verify(r Receipt, statement []byte, anchors TrustAnchors) (Status, error) {
	leaf := merkle.LeafHash(statement)
	if uaicrypto.FormatDigest(leaf) != r.LeafHash {
		return "", fmt.Errorf("%w: statement hashes to %s, receipt says %s",
			ErrLeafMismatch, uaicrypto.FormatDigest(leaf), r.LeafHash)
	}
	if r.LogIndex >= r.Checkpoint.Size {
		return "", fmt.Errorf("%w: index %d, checkpoint size %d",
			ErrIndexOutOfTree, r.LogIndex, r.Checkpoint.Size)
	}

	root := r.Checkpoint.Root
	if len(root) == 0 && r.Checkpoint.RootB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(r.Checkpoint.RootB64)
		if err != nil {
			return "", fmt.Errorf("%w: root: %v", ErrMalformedCheckpoint, err)
		}
		root = decoded
	}

	proof := make([][]byte, 0, len(r.InclusionProof))
	for _, h := range r.InclusionProof {
		b, err := uaicrypto.ParseDigest(h)
		if err != nil {
			return "", fmt.Errorf("receipt: audit path: %w", err)
		}
		proof = append(proof, b)
	}
	if err := merkle.VerifyInclusion(r.LogIndex, r.Checkpoint.Size, leaf, root, proof); err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadInclusion, err)
	}

	logKey, ok := anchors.LogKeys[r.LogSignature.KID]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknownLogKey, r.LogSignature.KID)
	}
	cp := r.Checkpoint
	if len(cp.Root) == 0 {
		cp.Root = root
	}
	if err := uaicrypto.Verify(logKey, uaicrypto.DomainCheckpoint, cp.Body(), r.LogSignature); err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadLogSignature, err)
	}

	// Count only co-signatures from witnesses the verifier actually trusts, and
	// only once each: a log operator could otherwise inflate the count by
	// repeating one witness or inventing names.
	counted := map[string]bool{}
	for _, w := range r.WitnessSignatures {
		key, known := anchors.WitnessKeys[w.Witness]
		if !known || counted[w.Witness] {
			continue
		}
		sig := uaicrypto.Signature{
			Alg: r.LogSignature.Alg, KID: w.Witness,
			Domain: uaicrypto.DomainCheckpoint, Value: w.Signature,
		}
		if uaicrypto.Verify(key, uaicrypto.DomainCheckpoint, cp.Body(), sig) == nil {
			counted[w.Witness] = true
		}
	}
	if len(counted) < anchors.MinWitnesses {
		return StatusUnderwitnessed, fmt.Errorf("%w: %d of %d required",
			ErrNotEnoughWitnesses, len(counted), anchors.MinWitnesses)
	}

	if r.Anchor == nil {
		return StatusVerifiedUnanchored, nil
	}
	return StatusVerified, nil
}
