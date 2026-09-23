package store

import (
	"context"
	"encoding/json"
	"fmt"
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
		if ev.Sequence == 0 {
			ev.Sequence = head.Sequence + 1
		}
		// The chain link goes in first. Everything that orders or links this
		// event lives in agent_chain_events; action_events carries only what
		// makes it an ACTION, so the two can never disagree about where the
		// event sits in history.
		if err := appendChainEvent(ctx, tx, ChainEvent{
			ID: ev.ID, AgentID: ev.AgentID, Sequence: ev.Sequence, Kind: KindAction,
			PreviousEventHash: ev.PreviousEventHash, EventHash: ev.EventHash,
			OccurredAt: ev.AssertedAt, LogIndex: nil,
		}, head); err != nil {
			return err
		}

		// The column is NOT NULL with an empty-array default; a nil slice would
		// arrive as NULL and be rejected.
		if ev.JurisdictionTargets == nil {
			ev.JurisdictionTargets = []string{}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO action_events (
				id, agent_id, owner_id, runtime_identity_id, decision_id, action_type,
				resource, capability, risk, purpose, jurisdiction_origin, jurisdiction_targets,
				cross_border, jurisdiction_basis, passport_id, passport_required,
				input_commitment, output_commitment, outcome, asserted_at, log_time)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE(NULLIF($9,''),'LOW')::risk_class,$10,$11,
			        $12::iso_country[],$13,$14,$15,$16,$17,$18,$19::action_outcome,$20,$21)`,
			ev.ID, ev.AgentID, ev.OwnerID, nullable(ev.RuntimeIdentityID), nullable(ev.DecisionID),
			ev.ActionType, nullable(ev.Resource), nullable(ev.Capability), ev.Risk,
			ev.Purpose, ev.JurisdictionOrigin, ev.JurisdictionTargets, ev.CrossBorder,
			ev.JurisdictionBasis, nullable(ev.PassportID), ev.PassportRequired,
			nullable(ev.InputCommitment), nullable(ev.OutputCommitment), ev.Outcome,
			ev.AssertedAt, ev.LogTime)
		if err != nil {
			return classify(err)
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
		SELECT e.id, e.agent_id, e.owner_id, e.runtime_identity_id, e.decision_id, c.sequence,
		       e.action_type, e.resource, e.capability, e.risk::text, e.purpose,
		       e.jurisdiction_origin, e.jurisdiction_targets, e.cross_border, e.jurisdiction_basis,
		       e.passport_id, e.passport_required, e.input_commitment, e.output_commitment,
		       e.outcome::text, c.previous_event_hash, c.event_hash, e.asserted_at, e.log_time,
		       a.payload, a.alg::text, a.signature, a.signer_kid, a.nonce
		FROM action_events e
		JOIN agent_chain_events c ON c.id = e.id
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

// Chain returns an agent's ACTION events in order.
//
// Use ChainEvents for the whole history: this view is the action timeline, and
// a caller that needs to know whether the agent was bound at a given moment has
// to look at every kind of event, not only the ones it took itself.
func (db *DB) Chain(ctx context.Context, agentID string, limit int) ([]ActionEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := db.pool.Query(ctx, `
		SELECT e.id, c.sequence, e.action_type, e.outcome::text, c.previous_event_hash,
		       c.event_hash, e.asserted_at
		FROM action_events e JOIN agent_chain_events c ON c.id = e.id
		WHERE e.agent_id = $1 ORDER BY c.sequence LIMIT $2`, agentID, limit)
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
