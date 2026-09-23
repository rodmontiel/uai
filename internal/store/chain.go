package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Chain event kinds. Everything that happens to an identity is one of these,
// and all of them live in the same chain (§9.4).
const (
	KindRegister = "REGISTER"
	KindBind     = "BIND"
	KindUnbind   = "UNBIND"
	KindRebind   = "REBIND"
	KindAction   = "ACTION"
)

// ChainEvent is one link in an agent's event chain.
type ChainEvent struct {
	ID                string
	AgentID           string
	Sequence          int64
	Kind              string
	PreviousEventHash string
	EventHash         string
	OccurredAt        time.Time
	LogIndex          *int64
}

// chainHead returns the hash the next event must reference.
//
// It reads the chain and nothing else. Registration writes the first link, so
// an agent with no head is an agent that was created wrong -- and saying so is
// better than silently substituting a genesis hash from another table and
// hiding the bug.
func chainHead(ctx context.Context, q querier, agentID string) (ChainHead, error) {
	var head ChainHead
	err := q.QueryRow(ctx, `
		SELECT event_hash, sequence FROM agent_chain_events
		 WHERE agent_id = $1 ORDER BY sequence DESC LIMIT 1`, agentID).
		Scan(&head.Hash, &head.Sequence)
	if err != nil {
		if errors.Is(classify(err), ErrNotFound) {
			return ChainHead{}, fmt.Errorf("%w: agent %s has no chain", ErrNotFound, agentID)
		}
		return ChainHead{}, classify(err)
	}
	return head, nil
}

// appendChainEvent links a new event onto the head the caller saw.
//
// Optimistic, deliberately: §9.5 allows an agent to run replicated, and
// serializing every append behind a lock would make replicas queue behind each
// other for the lifetime of the agent. The loser of a race gets a retryable
// conflict carrying the current head.
func appendChainEvent(ctx context.Context, tx pgx.Tx, ev ChainEvent, head ChainHead) error {
	if ev.PreviousEventHash != head.Hash {
		return &ChainConflictError{Expected: ev.PreviousEventHash, Actual: head}
	}
	if ev.Sequence == 0 {
		ev.Sequence = head.Sequence + 1
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO agent_chain_events (id, agent_id, sequence, kind, previous_event_hash,
		                                event_hash, occurred_at, log_index)
		VALUES ($1,$2,$3,$4::chain_event_kind,$5,$6,$7,$8)`,
		ev.ID, ev.AgentID, ev.Sequence, ev.Kind, nullable(ev.PreviousEventHash),
		ev.EventHash, ev.OccurredAt, ev.LogIndex)
	return chainConflict(classify(err), ev.PreviousEventHash, head)
}

// chainConflict maps a lost race onto a retryable conflict.
//
// Whichever index catches the concurrent writer, the meaning is the same: the
// head moved. It is NOT reported as a fork. Within one database a fork cannot
// be committed at all, so the losing insert is evidence of concurrency and
// nothing else, and calling it a clone would raise an accusation against an
// innocent agent every time two of its replicas acted at once (T-24).
func chainConflict(err error, expected string, head ChainHead) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrConflict) &&
		(strings.Contains(err.Error(), "agent_chain_events_link_uq") ||
			strings.Contains(err.Error(), "agent_chain_events_agent_id_sequence_key") ||
			strings.Contains(err.Error(), "agent_chain_events_agent_id_event_hash_key")) {
		return &ChainConflictError{Expected: expected, Actual: head}
	}
	return err
}

// ChainEvents returns an agent's chain in order, every kind included.
func (db *DB) ChainEvents(ctx context.Context, agentID string, limit int) ([]ChainEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := db.pool.Query(ctx, `
		SELECT id, agent_id, sequence, kind::text, previous_event_hash, event_hash,
		       occurred_at, log_index
		FROM agent_chain_events WHERE agent_id = $1 ORDER BY sequence LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []ChainEvent
	for rows.Next() {
		var ev ChainEvent
		var prev *string
		if err := rows.Scan(&ev.ID, &ev.AgentID, &ev.Sequence, &ev.Kind, &prev,
			&ev.EventHash, &ev.OccurredAt, &ev.LogIndex); err != nil {
			return nil, classify(err)
		}
		ev.PreviousEventHash = deref(prev)
		out = append(out, ev)
	}
	return out, classify(rows.Err())
}

// VerifyChain walks an agent's chain and reports the first broken link.
//
// The unique index makes a fork impossible to commit, so this walk catches the
// other failure: a gap, which is what a deleted or never-submitted event looks
// like from the outside.
func (db *DB) VerifyChain(ctx context.Context, agentID string) error {
	events, err := db.ChainEvents(ctx, agentID, 500)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("%w: agent %s has no chain", ErrNotFound, agentID)
	}
	if events[0].Kind != KindRegister || events[0].PreviousEventHash != "" {
		return fmt.Errorf("chain does not start at registration: sequence %d is %s",
			events[0].Sequence, events[0].Kind)
	}
	expected := events[0].EventHash
	for _, ev := range events[1:] {
		if ev.PreviousEventHash != expected {
			return fmt.Errorf("chain broken at sequence %d: event references %s, expected %s",
				ev.Sequence, ev.PreviousEventHash, expected)
		}
		expected = ev.EventHash
	}
	return nil
}
