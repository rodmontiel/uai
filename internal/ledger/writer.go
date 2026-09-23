package ledger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rodmontiel/uai/internal/chain"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// The contract function this writer calls. Written out rather than derived from
// an ABI file so that a change to the contract's signature breaks the build
// here instead of producing a transaction the contract silently ignores.
const anchorSignature = "anchor(bytes32,uint64,uint32)"

// Writer anchors witnessed checkpoints on the consortium ledger.
type Writer struct {
	db       *store.DB
	client   *chain.Client
	contract string
	origin   string
	adapter  PublicAnchorAdapter
	batch    int
	log      *slog.Logger
}

// Options configure a Writer.
type Options struct {
	Origin   string
	Contract string
	Batch    int
	Adapter  PublicAnchorAdapter
	Logger   *slog.Logger
}

// New builds a writer.
func New(db *store.DB, client *chain.Client, opts Options) *Writer {
	if opts.Batch <= 0 {
		opts.Batch = 16
	}
	if opts.Adapter == nil {
		opts.Adapter = NoopAdapter{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Writer{
		db: db, client: client, contract: opts.Contract, origin: opts.Origin,
		adapter: opts.Adapter, batch: opts.Batch, log: opts.Logger,
	}
}

// Drain anchors every checkpoint still waiting, oldest first, and reports how
// many reached the ledger.
//
// Order matters and is not an optimisation. UAITransparencyAnchor refuses a
// checkpoint that does not grow, so anchoring out of order would have the
// ledger reject the earlier ones permanently — turning a queue into a hole.
func (w *Writer) Drain(ctx context.Context) (int, error) {
	pending, err := w.db.UnanchoredCheckpoints(ctx, w.origin, w.batch)
	if err != nil {
		return 0, err
	}
	anchored := 0
	for _, cp := range pending {
		if err := w.anchorOne(ctx, cp); err != nil {
			if errors.Is(err, chain.ErrUnavailable) {
				// §12.4: the ledger being unreachable is not an admission gate.
				// The log keeps operating and the queue drains later; events
				// stay VERIFIED_UNANCHORED until it does.
				w.log.Warn("ledger unavailable; checkpoints remain unanchored",
					"pending", len(pending)-anchored, "err", err)
				return anchored, nil
			}
			return anchored, err
		}
		anchored++
	}
	return anchored, nil
}

func (w *Writer) anchorOne(ctx context.Context, cp store.LogCheckpoint) error {
	root, err := uaicrypto.ParseDigest(cp.Root)
	if err != nil {
		return fmt.Errorf("ledger: checkpoint %d: %w", cp.Size, err)
	}
	rootWord, err := chain.WordFromBytes32(root)
	if err != nil {
		return err
	}
	data := chain.Encode(anchorSignature, rootWord,
		chain.WordFromUint(uint64(cp.Size)), chain.WordFromUint(uint64(cp.WitnessCount)))

	receipt, err := w.client.Send(ctx, w.contract, data)
	if err != nil {
		if errors.Is(err, chain.ErrReverted) {
			// The contract refused. Recording that is the point: an anchor the
			// ledger rejected must never be reported as an anchor, and retrying
			// a correct refusal forever would turn it into an outage.
			w.log.Error("ledger refused a checkpoint", "size", cp.Size, "root", cp.Root, "err", err)
		}
		return err
	}

	at := time.Now().UTC()
	if err := w.db.RecordAnchor(ctx, cp.Origin, cp.Size, receipt.TxHash, at); err != nil {
		return err
	}
	id, err := uaiid.NewULID()
	if err != nil {
		return err
	}
	return w.db.RecordLedgerCommitment(ctx, store.LedgerCommitment{
		ID: "anch-" + id.String(), ChainID: w.client.ChainID(), Contract: w.contract,
		EventName: "CheckpointAnchored", TxHash: receipt.TxHash, BlockNumber: receipt.BlockNumber,
		CheckpointRoot: cp.Root, CheckpointSize: cp.Size,
		SubjectKind: "checkpoint", SubjectID: fmt.Sprintf("%s#%d", cp.Origin, cp.Size),
		AnchoredAt: at,
	})
}

// PublishEpoch closes an epoch and offers its root to the public adapter.
//
// A refusal from the adapter is normal for a deployment that publishes nowhere,
// and is reported as such rather than failing the run.
func (w *Writer) PublishEpoch(ctx context.Context, epoch uint64, root []byte) (*PublicAnchor, error) {
	anchor, err := w.adapter.Publish(ctx, epoch, root)
	if err != nil {
		if errors.Is(err, ErrNoPublicAnchor) {
			w.log.Info("no public anchor for this deployment", "adapter", w.adapter.Name(), "epoch", epoch)
			return nil, nil
		}
		return nil, err
	}
	return &anchor, nil
}
