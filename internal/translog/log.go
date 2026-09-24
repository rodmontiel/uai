package translog

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/merkle"
	"github.com/rodmontiel/uai/pkg/receipt"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// Subject kinds a statement can be.
const (
	KindAttestation = "attestation"
	KindDecision    = "decision"
	KindCredential  = "credential"
	KindVote        = "vote"
	KindBinding     = "binding"
)

// Log is the transparency service for one origin.
type Log struct {
	origin    string
	db        *store.DB
	signer    uaicrypto.Signer
	witnesses []*Witness
	minWit    int

	mu   sync.Mutex
	tree *merkle.Tree
}

// Option configures a Log.
type Option func(*Log)

// WithWitnesses attaches co-signers and the number a checkpoint needs.
func WithWitnesses(min int, ws ...*Witness) Option {
	return func(l *Log) { l.minWit, l.witnesses = min, ws }
}

// Open loads a log and rebuilds its Merkle tree from the committed leaves.
func Open(ctx context.Context, db *store.DB, origin string, signer uaicrypto.Signer, opts ...Option) (*Log, error) {
	l := &Log{origin: origin, db: db, signer: signer, tree: merkle.New()}
	for _, o := range opts {
		o(l)
	}
	leaves, err := db.LogLeaves(ctx, origin)
	if err != nil {
		return nil, err
	}
	for i, h := range leaves {
		raw, err := uaicrypto.ParseDigest(h)
		if err != nil {
			// A leaf that cannot be parsed means the tree cannot be rebuilt
			// faithfully, and a tree that is ALMOST right produces inclusion
			// proofs that are confidently wrong. Refuse to open instead.
			return nil, fmt.Errorf("translog: leaf %d of %s is unusable: %w", i, origin, err)
		}
		l.tree.AppendLeafHash(raw)
	}
	return l, nil
}

// Origin is the log's identifier, which a receipt names.
func (l *Log) Origin() string { return l.origin }

// Size is the number of entries.
func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tree.Size()
}

// Root is the current Merkle root.
//
// Exposed so that a restart can be checked against the last published
// checkpoint: a log that rebuilt its tree wrongly would still issue internally
// consistent proofs, and the only thing that catches that is comparing the
// rebuilt root against what was already signed.
func (l *Log) Root() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tree.Root()
}

// Append registers a signed statement and returns its receipt.
//
// The statement itself is never stored: the leaf is SHA-256(0x00 || statement)
// and that is all the log keeps. A relying party holding the statement and the
// receipt can verify inclusion without the log; the log holding the statement
// would only create something worth stealing.
func (l *Log) Append(ctx context.Context, statement []byte, kind, subjectID string,
	at time.Time) (receipt.Receipt, error) {

	leaf := merkle.LeafHash(statement)
	entry, err := l.db.AppendLogEntry(ctx, l.origin, uaicrypto.FormatDigest(leaf), kind, subjectID, at)
	if err != nil {
		return receipt.Receipt{}, err
	}

	l.mu.Lock()
	// The database allocated the index; the in-memory tree must agree with it.
	// If they have diverged, every proof this log issues from here on would be
	// for the wrong position, so this is fatal rather than recoverable.
	if uint64(entry.Index) != l.tree.Size() {
		l.mu.Unlock()
		return receipt.Receipt{}, fmt.Errorf(
			"translog: log %s is at index %d in the database and %d in memory; refusing to issue proofs",
			l.origin, entry.Index, l.tree.Size())
	}
	l.tree.AppendLeafHash(leaf)
	r, err := receipt.Issue(l.signer, l.origin, l.tree, uint64(entry.Index), at)
	l.mu.Unlock()
	if err != nil {
		return receipt.Receipt{}, err
	}

	if err := l.witness(&r); err != nil {
		return receipt.Receipt{}, err
	}
	if err := l.persist(ctx, r, kind, subjectID, at); err != nil {
		return receipt.Receipt{}, err
	}
	return r, nil
}

// witness collects co-signatures for the receipt's checkpoint.
//
// A witness that refuses is NOT an error for the caller: §18.4 says a
// checkpoint below the witness threshold is marked UNDERWITNESSED so verifiers
// see reduced assurance rather than a silent downgrade. Failing the append
// instead would let one offline witness stop the whole system from recording
// anything, which is the availability failure that makes operators disable
// transparency in the first place.
func (l *Log) witness(r *receipt.Receipt) error {
	for _, w := range l.witnesses {
		last, _ := w.View()
		var proof [][]byte
		if last > 0 && last < r.Checkpoint.Size {
			l.mu.Lock()
			p, err := l.tree.ConsistencyProof(last, r.Checkpoint.Size)
			l.mu.Unlock()
			if err != nil {
				return err
			}
			proof = p
		}
		sig, err := w.CoSign(r.Checkpoint, proof)
		if err != nil {
			// Recorded by its absence: the receipt simply carries one fewer
			// co-signature, and receipt.Verify reports UNDERWITNESSED.
			continue
		}
		r.WitnessSignatures = append(r.WitnessSignatures, sig)
	}
	return nil
}

func (l *Log) persist(ctx context.Context, r receipt.Receipt, kind, subjectID string, at time.Time) error {
	witnesses, err := json.Marshal(r.WitnessSignatures)
	if err != nil {
		return err
	}
	if err := l.db.SaveCheckpoint(ctx, store.LogCheckpoint{
		Origin: l.origin, Size: int64(r.Checkpoint.Size),
		Root:         uaicrypto.FormatDigest(r.Checkpoint.Root),
		LogSignature: r.LogSignature.Value, SignerKID: r.LogSignature.KID,
		WitnessSignatures: witnesses, WitnessCount: len(r.WitnessSignatures), IssuedAt: at,
	}); err != nil {
		return err
	}
	proof, err := json.Marshal(r.InclusionProof)
	if err != nil {
		return err
	}
	id, err := uaiid.NewULID()
	if err != nil {
		return err
	}
	return l.db.SaveReceipt(ctx, "rcpt-"+id.String(), l.origin, int64(r.LogIndex), r.LeafHash,
		kind, subjectID, int64(r.Checkpoint.Size), uaicrypto.FormatDigest(r.Checkpoint.Root),
		proof, r.LogSignature.Value, witnesses, at)
}

// MinWitnesses is the co-signature count policy requires, which a verifier
// needs in order to tell UNDERWITNESSED from fully witnessed.
func (l *Log) MinWitnesses() int { return l.minWit }

// TrustAnchors returns what a verifier needs to check this log's receipts
// without asking the log anything.
func (l *Log) TrustAnchors() receipt.TrustAnchors {
	anchors := receipt.TrustAnchors{
		LogKeys:      map[string]any{l.signer.KID(): l.signer.Public()},
		WitnessKeys:  map[string]any{},
		MinWitnesses: l.minWit,
	}
	for _, w := range l.witnesses {
		anchors.WitnessKeys[w.Name()] = w.Public()
	}
	return anchors
}

// SignedCheckpoint is a checkpoint with everything needed to check it.
//
// The signature travels with it, always. A checkpoint on its own is the log's
// word about its own contents, and a verifier comparing a receipt against an
// unverified checkpoint is asking the log whether its own receipt is genuine.
type SignedCheckpoint struct {
	receipt.Checkpoint
	LogSignature      uaicrypto.Signature        `json:"log_signature"`
	WitnessSignatures []receipt.WitnessSignature `json:"witness_signatures"`
	MinWitnesses      int                        `json:"min_witnesses"`
}

// Checkpoint issues a signed checkpoint over the log as it stands, with witness
// co-signatures.
//
// Issued fresh rather than read back from storage, so that a caller asking "what
// does this log say right now" gets an answer covering everything appended so
// far. The persisted checkpoints remain the record of what was published at each
// size; this is the current view, and the two must agree at any size they share
// or the log has forked.
func (l *Log) Checkpoint(ctx context.Context, at time.Time) (SignedCheckpoint, error) {
	l.mu.Lock()
	size := l.tree.Size()
	if size == 0 {
		l.mu.Unlock()
		return SignedCheckpoint{}, fmt.Errorf("translog: log %s is empty", l.origin)
	}
	r, err := receipt.Issue(l.signer, l.origin, l.tree, size-1, at)
	l.mu.Unlock()
	if err != nil {
		return SignedCheckpoint{}, err
	}
	if err := l.witness(&r); err != nil {
		return SignedCheckpoint{}, err
	}
	return SignedCheckpoint{
		Checkpoint: r.Checkpoint, LogSignature: r.LogSignature,
		WitnessSignatures: r.WitnessSignatures, MinWitnesses: l.minWit,
	}, nil
}
