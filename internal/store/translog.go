package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Transparency log errors.
var (
	// ErrSplitView means a second, different root was offered for a size the
	// log has already checkpointed. There is no benign cause: it is the
	// observable signature of an operator showing two verifiers two histories.
	ErrSplitView = errors.New("store: a different root already exists for that checkpoint size")
	// ErrAlreadyLogged means the statement is already in the log.
	ErrAlreadyLogged = errors.New("store: statement is already logged")
)

// LogEntry is one leaf of the transparency log.
type LogEntry struct {
	Origin      string
	Index       int64
	LeafHash    string
	SubjectKind string
	SubjectID   string
	AppendedAt  time.Time
}

// LogCheckpoint is a signed, possibly co-signed, possibly anchored checkpoint.
type LogCheckpoint struct {
	Origin            string
	Size              int64
	Root              string
	LogSignature      string
	SignerKID         string
	WitnessSignatures json.RawMessage
	WitnessCount      int
	IssuedAt          time.Time
	AnchoredTx        string
	AnchoredAt        *time.Time
}

// AppendLogEntry adds a leaf at the next index.
//
// The index is allocated inside the transaction under a lock on the log's
// existing entries, because two concurrent appends that both computed "size"
// from a stale read would claim the same index -- and an index that two
// statements claim makes every inclusion proof at that position ambiguous.
func (db *DB) AppendLogEntry(ctx context.Context, origin, leafHash, kind, subjectID string,
	at time.Time) (LogEntry, error) {

	var e LogEntry
	err := db.InTx(ctx, func(tx pgx.Tx) error {
		// Serialize appends per log. A transparency log is append-only and
		// ordered; a gap or a collision is not something to reconcile later.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, origin); err != nil {
			return classify(err)
		}
		var next int64
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(log_index) + 1, 0) FROM log_entries WHERE log_origin = $1`,
			origin).Scan(&next); err != nil {
			return classify(err)
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO log_entries (log_origin, log_index, leaf_hash, subject_kind, subject_id, appended_at)
			VALUES ($1,$2,$3,$4,$5,$6)`, origin, next, leafHash, kind, subjectID, at)
		if err != nil {
			if errors.Is(classify(err), ErrConflict) {
				return ErrAlreadyLogged
			}
			return classify(err)
		}
		e = LogEntry{Origin: origin, Index: next, LeafHash: leafHash,
			SubjectKind: kind, SubjectID: subjectID, AppendedAt: at}
		return nil
	})
	return e, err
}

// LogLeaves returns every leaf hash of a log in index order.
//
// The Merkle tree is rebuilt from these on startup rather than persisted as
// internal nodes. For the sizes the MVP handles that is simpler and has one
// property worth keeping: the tree can only ever be what the leaves say it is,
// so a corrupted cache of internal nodes is not a failure mode that exists.
func (db *DB) LogLeaves(ctx context.Context, origin string) ([]string, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT leaf_hash FROM log_entries WHERE log_origin = $1 ORDER BY log_index`, origin)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, classify(err)
		}
		out = append(out, h)
	}
	return out, classify(rows.Err())
}

// LogEntryBySubject finds the entry for a statement, if it was logged.
func (db *DB) LogEntryBySubject(ctx context.Context, origin, kind, subjectID string) (LogEntry, error) {
	var e LogEntry
	err := db.pool.QueryRow(ctx, `
		SELECT log_origin, log_index, leaf_hash, subject_kind, subject_id, appended_at
		  FROM log_entries WHERE log_origin = $1 AND subject_kind = $2 AND subject_id = $3`,
		origin, kind, subjectID).
		Scan(&e.Origin, &e.Index, &e.LeafHash, &e.SubjectKind, &e.SubjectID, &e.AppendedAt)
	if err != nil {
		return LogEntry{}, classify(err)
	}
	return e, nil
}

// SaveCheckpoint stores a signed checkpoint.
//
// A second, different root for a size the log already published is refused and
// reported as a split view rather than as a duplicate key. The two are not the
// same event: one is a retry, the other is the failure this whole layer exists
// to make impossible to hide.
func (db *DB) SaveCheckpoint(ctx context.Context, c LogCheckpoint) error {
	witnesses := c.WitnessSignatures
	if len(witnesses) == 0 {
		witnesses = json.RawMessage(`[]`)
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO log_checkpoints (log_origin, size, root, log_signature, signer_kid,
		                             witness_signatures, witness_count, issued_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (log_origin, size) DO NOTHING`,
		c.Origin, c.Size, c.Root, c.LogSignature, c.SignerKID, witnesses, c.WitnessCount, c.IssuedAt)
	if err != nil {
		if errors.Is(classify(err), ErrConflict) {
			return ErrSplitView
		}
		return classify(err)
	}
	// ON CONFLICT DO NOTHING swallows a retry at the same size, so confirm the
	// stored root is the one we just signed. A different root means the log
	// published two histories at one size.
	var stored string
	if err := db.pool.QueryRow(ctx,
		`SELECT root FROM log_checkpoints WHERE log_origin = $1 AND size = $2`,
		c.Origin, c.Size).Scan(&stored); err != nil {
		return classify(err)
	}
	if stored != c.Root {
		return ErrSplitView
	}
	return nil
}

// LatestCheckpoint returns the newest checkpoint of a log.
func (db *DB) LatestCheckpoint(ctx context.Context, origin string) (LogCheckpoint, error) {
	return scanCheckpoint(db.pool.QueryRow(ctx, `
		SELECT log_origin, size, root, log_signature, signer_kid, witness_signatures,
		       witness_count, issued_at, anchored_tx, anchored_at
		  FROM log_checkpoints WHERE log_origin = $1 ORDER BY size DESC LIMIT 1`, origin))
}

// UnanchoredCheckpoints returns checkpoints still waiting for the ledger.
func (db *DB) UnanchoredCheckpoints(ctx context.Context, origin string, limit int) ([]LogCheckpoint, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT log_origin, size, root, log_signature, signer_kid, witness_signatures,
		       witness_count, issued_at, anchored_tx, anchored_at
		  FROM log_checkpoints WHERE log_origin = $1 AND anchored_tx IS NULL
		 ORDER BY size LIMIT $2`, origin, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []LogCheckpoint
	for rows.Next() {
		var c LogCheckpoint
		var tx *string
		if err := rows.Scan(&c.Origin, &c.Size, &c.Root, &c.LogSignature, &c.SignerKID,
			&c.WitnessSignatures, &c.WitnessCount, &c.IssuedAt, &tx, &c.AnchoredAt); err != nil {
			return nil, classify(err)
		}
		c.AnchoredTx = deref(tx)
		out = append(out, c)
	}
	return out, classify(rows.Err())
}

func scanCheckpoint(row pgx.Row) (LogCheckpoint, error) {
	var c LogCheckpoint
	var tx *string
	err := row.Scan(&c.Origin, &c.Size, &c.Root, &c.LogSignature, &c.SignerKID,
		&c.WitnessSignatures, &c.WitnessCount, &c.IssuedAt, &tx, &c.AnchoredAt)
	if err != nil {
		return LogCheckpoint{}, classify(err)
	}
	c.AnchoredTx = deref(tx)
	return c, nil
}

// RecordAnchor notes where a checkpoint reached the ledger.
func (db *DB) RecordAnchor(ctx context.Context, origin string, size int64, txHash string,
	at time.Time) error {
	tag, err := db.pool.Exec(ctx, `
		UPDATE log_checkpoints SET anchored_tx = $3, anchored_at = $4
		 WHERE log_origin = $1 AND size = $2`, origin, size, txHash, at)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveReceipt stores an issued receipt.
func (db *DB) SaveReceipt(ctx context.Context, id, origin string, index int64, leafHash,
	kind, subjectID string, size int64, root string, proof json.RawMessage,
	logSignature string, witnesses json.RawMessage, at time.Time) error {
	if len(witnesses) == 0 {
		witnesses = json.RawMessage(`[]`)
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO transparency_receipts (id, log_origin, log_index, leaf_hash, subject_kind,
		                                   subject_id, checkpoint_size, checkpoint_root,
		                                   inclusion_proof, log_signature, witness_signatures, issued_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		id, origin, index, leafHash, kind, subjectID, size, root, proof, logSignature, witnesses, at)
	return classify(err)
}

// LedgerCommitment records that something reached the consortium ledger.
type LedgerCommitment struct {
	ID             string
	ChainID        uint64
	Contract       string
	EventName      string
	TxHash         string
	BlockNumber    uint64
	Epoch          *int64
	CheckpointRoot string
	CheckpointSize int64
	SubjectKind    string
	SubjectID      string
	AnchoredAt     time.Time
}

// RecordLedgerCommitment stores an on-chain anchor.
func (db *DB) RecordLedgerCommitment(ctx context.Context, c LedgerCommitment) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO ledger_commitments (id, chain_id, contract, event_name, tx_hash, block_number,
		                                epoch, checkpoint_root, checkpoint_size, subject_kind,
		                                subject_id, anchored_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		c.ID, c.ChainID, c.Contract, c.EventName, c.TxHash, c.BlockNumber, c.Epoch,
		nullable(c.CheckpointRoot), c.CheckpointSize, nullable(c.SubjectKind),
		nullable(c.SubjectID), c.AnchoredAt)
	return classify(err)
}
