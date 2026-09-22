package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ChainHead is the current tip of an agent's event chain.
type ChainHead struct {
	// Hash is what the next event must reference. For an agent with no events
	// it is the genesis hash recorded at registration, so the chain is anchored
	// to the identity itself rather than starting from nothing.
	Hash     string
	Sequence int64
}

// ChainConflictError reports that an append referenced a stale head, and
// carries the current one so the caller can retry without a second round trip.
type ChainConflictError struct {
	Expected string
	Actual   ChainHead
}

func (e *ChainConflictError) Error() string {
	return fmt.Sprintf("store: stale chain head: event references %s, current head is %s at sequence %d",
		e.Expected, e.Actual.Hash, e.Actual.Sequence)
}

// Is makes errors.Is(err, ErrChainConflict) work.
func (e *ChainConflictError) Is(target error) bool { return target == ErrChainConflict }

// ActionEvent is an attested action.
type ActionEvent struct {
	ID                  string
	AgentID             string
	OwnerID             string
	RuntimeIdentityID   string
	DecisionID          string
	Sequence            int64
	ActionType          string
	Resource            string
	Capability          string
	Risk                string
	Purpose             string
	JurisdictionOrigin  string
	JurisdictionTargets []string
	CrossBorder         bool
	JurisdictionBasis   string
	PassportID          string
	PassportRequired    bool
	InputCommitment     string
	OutputCommitment    string
	Outcome             string
	PreviousEventHash   string
	EventHash           string
	AssertedAt          time.Time
	LogTime             *time.Time
}

// Attestation is the signed payload accompanying an action event.
type Attestation struct {
	EventID   string
	AgentID   string
	Payload   json.RawMessage
	Alg       string
	Signature string
	SignerKID string
	Nonce     string
}

// ChainHead returns the hash the next event must reference.
func (db *DB) ChainHead(ctx context.Context, agentID string) (ChainHead, error) {
	return chainHead(ctx, db.pool, agentID)
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func chainHead(ctx context.Context, q querier, agentID string) (ChainHead, error) {
	var head ChainHead
	err := q.QueryRow(ctx, `
		SELECT COALESCE(
		         (SELECT event_hash FROM action_events
		           WHERE agent_id = $1 ORDER BY sequence DESC LIMIT 1),
		         (SELECT genesis_event_hash FROM agents WHERE id = $1)),
		       COALESCE(
		         (SELECT sequence FROM action_events
		           WHERE agent_id = $1 ORDER BY sequence DESC LIMIT 1), 0)`,
		agentID).Scan(&head.Hash, &head.Sequence)
	if err != nil {
		return ChainHead{}, classify(err)
	}
	if head.Hash == "" {
		return ChainHead{}, fmt.Errorf("%w: agent %s", ErrNotFound, agentID)
	}
	return head, nil
}

// AppendAction records an action event and its attestation atomically.
//
// Two failure modes matter to callers:
//
//   - ErrChainConflict: the submitter raced another append at the same head and
//     lost. Refetch the head and retry. Ordinary and expected whenever an agent
//     runs replicated.
//   - ErrConflict on the nonce: a replay. Not retryable.
//
// A lost race is NOT reported as a fork. Two writers extending the same head
// violate either the chain index or the (agent, sequence) index depending on
// which one PostgreSQL checks first, so the constraint name carries no signal
// about intent. More importantly, within one database a fork cannot be
// committed at all, which means the losing insert is evidence of concurrency
// and nothing else. Treating it as a clone would raise an incident against an
// innocent agent every time two of its replicas attested at once, which is
// precisely the false-accusation failure mode the threat model is built to
// avoid (T-24). Genuine fork detection is a cross-instance, cross-log
// observation.
func (db *DB) AppendAction(ctx context.Context, ev ActionEvent, att Attestation) error {
	return db.InTx(ctx, func(tx pgx.Tx) error {
		head, err := chainHead(ctx, tx, ev.AgentID)
		if err != nil {
			return err
		}
		if ev.PreviousEventHash != head.Hash {
			return &ChainConflictError{Expected: ev.PreviousEventHash, Actual: head}
		}
		// Whichever index catches a concurrent writer, the meaning is the same:
		// the head moved. Map both to a retryable conflict carrying the head as
		// the caller last saw it.
		toConflict := func(err error) error {
			if err == nil {
				return nil
			}
			if errors.Is(err, ErrConflict) &&
				(strings.Contains(err.Error(), "action_events_chain_uq") ||
					strings.Contains(err.Error(), "action_events_agent_id_sequence_key")) {
				return &ChainConflictError{Expected: ev.PreviousEventHash, Actual: head}
			}
			return err
		}
		if ev.Sequence == 0 {
			ev.Sequence = head.Sequence + 1
		}
		// The column is NOT NULL with an empty-array default; a nil slice would
		// arrive as NULL and be rejected.
		if ev.JurisdictionTargets == nil {
			ev.JurisdictionTargets = []string{}
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO action_events (
				id, agent_id, owner_id, runtime_identity_id, decision_id, sequence, action_type,
				resource, capability, risk, purpose, jurisdiction_origin, jurisdiction_targets,
				cross_border, jurisdiction_basis, passport_id, passport_required,
				input_commitment, output_commitment, outcome, previous_event_hash, event_hash,
				asserted_at, log_time)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE(NULLIF($10,''),'LOW')::risk_class,$11,$12,
			        $13::iso_country[],$14,$15,$16,$17,$18,$19,$20::action_outcome,$21,$22,$23,$24)`,
			ev.ID, ev.AgentID, ev.OwnerID, nullable(ev.RuntimeIdentityID), nullable(ev.DecisionID),
			ev.Sequence, ev.ActionType, nullable(ev.Resource), nullable(ev.Capability), ev.Risk,
			ev.Purpose, ev.JurisdictionOrigin, ev.JurisdictionTargets, ev.CrossBorder,
			ev.JurisdictionBasis, nullable(ev.PassportID), ev.PassportRequired,
			nullable(ev.InputCommitment), nullable(ev.OutputCommitment), ev.Outcome,
			nullable(ev.PreviousEventHash), ev.EventHash, ev.AssertedAt, ev.LogTime)
		if err != nil {
			return toConflict(classify(err))
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO action_attestations (event_id, agent_id, payload, alg, signature, signer_kid, nonce)
			VALUES ($1,$2,$3,$4::signature_alg,$5,$6,$7)`,
			att.EventID, att.AgentID, att.Payload, att.Alg, att.Signature, att.SignerKID, att.Nonce)
		return classify(err)
	})
}

// ActionByID loads an event and its attestation.
func (db *DB) ActionByID(ctx context.Context, eventID string) (ActionEvent, Attestation, error) {
	var ev ActionEvent
	var att Attestation
	var runtimeID, decisionID, resource, capability, passportID *string
	var inputC, outputC, prevHash *string
	err := db.pool.QueryRow(ctx, `
		SELECT e.id, e.agent_id, e.owner_id, e.runtime_identity_id, e.decision_id, e.sequence,
		       e.action_type, e.resource, e.capability, e.risk::text, e.purpose,
		       e.jurisdiction_origin, e.jurisdiction_targets, e.cross_border, e.jurisdiction_basis,
		       e.passport_id, e.passport_required, e.input_commitment, e.output_commitment,
		       e.outcome::text, e.previous_event_hash, e.event_hash, e.asserted_at, e.log_time,
		       a.payload, a.alg::text, a.signature, a.signer_kid, a.nonce
		FROM action_events e
		JOIN action_attestations a ON a.event_id = e.id
		WHERE e.id = $1`, eventID).
		Scan(&ev.ID, &ev.AgentID, &ev.OwnerID, &runtimeID, &decisionID, &ev.Sequence,
			&ev.ActionType, &resource, &capability, &ev.Risk, &ev.Purpose,
			&ev.JurisdictionOrigin, &ev.JurisdictionTargets, &ev.CrossBorder, &ev.JurisdictionBasis,
			&passportID, &ev.PassportRequired, &inputC, &outputC,
			&ev.Outcome, &prevHash, &ev.EventHash, &ev.AssertedAt, &ev.LogTime,
			&att.Payload, &att.Alg, &att.Signature, &att.SignerKID, &att.Nonce)
	if err != nil {
		return ActionEvent{}, Attestation{}, classify(err)
	}
	ev.RuntimeIdentityID, ev.DecisionID = deref(runtimeID), deref(decisionID)
	ev.Resource, ev.Capability, ev.PassportID = deref(resource), deref(capability), deref(passportID)
	ev.InputCommitment, ev.OutputCommitment = deref(inputC), deref(outputC)
	ev.PreviousEventHash = deref(prevHash)
	att.EventID, att.AgentID = ev.ID, ev.AgentID
	return ev, att, nil
}

// Chain returns an agent's events in order.
func (db *DB) Chain(ctx context.Context, agentID string, limit int) ([]ActionEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := db.pool.Query(ctx, `
		SELECT id, sequence, action_type, outcome::text, previous_event_hash, event_hash, asserted_at
		FROM action_events WHERE agent_id = $1 ORDER BY sequence LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []ActionEvent
	for rows.Next() {
		var ev ActionEvent
		var prev *string
		if err := rows.Scan(&ev.ID, &ev.Sequence, &ev.ActionType, &ev.Outcome,
			&prev, &ev.EventHash, &ev.AssertedAt); err != nil {
			return nil, classify(err)
		}
		ev.AgentID, ev.PreviousEventHash = agentID, deref(prev)
		out = append(out, ev)
	}
	return out, classify(rows.Err())
}

// VerifyChain walks an agent's events and reports the first broken link.
//
// The database's unique index makes a fork impossible to commit, and this walk
// catches the other failure: a gap, which is what a deleted or never-submitted
// event looks like from the outside.
func (db *DB) VerifyChain(ctx context.Context, agentID string) error {
	agent, err := db.agentGenesis(ctx, agentID)
	if err != nil {
		return err
	}
	events, err := db.Chain(ctx, agentID, 500)
	if err != nil {
		return err
	}
	expected := agent
	for i, ev := range events {
		if ev.PreviousEventHash != expected {
			return fmt.Errorf("chain broken at sequence %d: event references %s, expected %s",
				ev.Sequence, ev.PreviousEventHash, expected)
		}
		if ev.Sequence != int64(i+1) {
			return fmt.Errorf("sequence gap: event %d is at position %d", ev.Sequence, i+1)
		}
		expected = ev.EventHash
	}
	return nil
}

func (db *DB) agentGenesis(ctx context.Context, agentID string) (string, error) {
	var genesis string
	err := db.pool.QueryRow(ctx, `SELECT genesis_event_hash FROM agents WHERE id = $1`, agentID).Scan(&genesis)
	if err != nil {
		if errors.Is(classify(err), ErrNotFound) {
			return "", fmt.Errorf("%w: agent %s", ErrNotFound, agentID)
		}
		return "", classify(err)
	}
	return genesis, nil
}
