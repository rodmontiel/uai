package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// AuditEvent is one operation this registry performed, signed.
//
// The table has existed since migration 0001 and, until federation, nothing
// wrote to it. That is worth saying out loud rather than quietly fixing: an
// empty audit table looks exactly like a system where nothing happened.
//
// Signed, because an audit record an operator can edit is a record of what the
// operator wanted read. The signature covers the canonical form of everything
// below it, so a changed outcome or a changed object stops verifying.
type AuditEvent struct {
	ActorDID   string         `json:"actor_did"`
	ActorType  string         `json:"actor_type"`
	Operation  string         `json:"operation"`
	ObjectKind string         `json:"object_kind"`
	ObjectID   string         `json:"object_id"`
	Source     string         `json:"source"`
	Outcome    string         `json:"outcome"`
	Detail     map[string]any `json:"detail,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
}

// RecordAudit signs an event and appends it.
//
// A failure here is returned and never swallowed. An operation that succeeded
// while its audit record was silently dropped is the one case an audit log
// exists to make impossible, so the caller decides -- and for federation the
// caller refuses the operation.
func (db *DB) RecordAudit(ctx context.Context, signer uaicrypto.Signer, ev AuditEvent) error {
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	if ev.Detail == nil {
		ev.Detail = map[string]any{}
	}
	sig, err := uaicrypto.SignObject(signer, uaicrypto.DomainAudit, ev)
	if err != nil {
		return err
	}
	detail, err := json.Marshal(ev.Detail)
	if err != nil {
		return err
	}
	id, err := uaiid.NewULID()
	if err != nil {
		return err
	}
	_, err = db.pool.Exec(ctx, `
		INSERT INTO audit_events
		    (id, actor_did, actor_type, operation, object_kind, object_id, source,
		     outcome, detail, signature, signer_kid, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12)`,
		"aud-"+id.String(), ev.ActorDID, ev.ActorType, ev.Operation, ev.ObjectKind,
		ev.ObjectID, ev.Source, ev.Outcome, string(detail), sig.Value, sig.KID, ev.OccurredAt)
	return classify(err)
}

// AuditEventsFor returns the recorded operations on one object, newest first.
func (db *DB) AuditEventsFor(ctx context.Context, objectKind, objectID string, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.pool.Query(ctx, `
		SELECT actor_did, actor_type, operation, object_kind, object_id, source,
		       outcome, detail, occurred_at
		  FROM audit_events
		 WHERE object_kind = $1 AND object_id = $2
		 ORDER BY occurred_at DESC LIMIT $3`, objectKind, objectID, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var ev AuditEvent
		var detail []byte
		if err := rows.Scan(&ev.ActorDID, &ev.ActorType, &ev.Operation, &ev.ObjectKind,
			&ev.ObjectID, &ev.Source, &ev.Outcome, &detail, &ev.OccurredAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detail, &ev.Detail)
		out = append(out, ev)
	}
	return out, rows.Err()
}
