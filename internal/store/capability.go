package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CapabilityRequest is an agent asking for a capability it does not hold.
//
// It is deliberately a different type from a grant, stored in a different
// table, with no method here that turns one into the other. §22.9 states the
// rule as "no MCP tool grants capabilities"; the absence of an Approve method
// on this file is that rule expressed where it cannot be argued with.
//
// Approval happens out of band: the owner signs, and the signature travels a
// path the agent's process never touches.
type CapabilityRequest struct {
	ID             string
	AgentID        string
	OwnerID        string
	Capability     string
	Justification  string
	Purpose        string
	Resource       string
	State          string
	RequestedByDID string
	RequestedAt    time.Time
	ExpiresAt      time.Time
}

// CreateCapabilityRequest records a pending request.
//
// It returns ErrConflict when the agent already has one open for the same
// capability. Re-asking in a loop until an owner approves out of fatigue is a
// real attack on a human approver, and the partial unique index refuses to host
// it rather than leaving the rate limit to be the only defence.
func (db *DB) CreateCapabilityRequest(ctx context.Context, r CapabilityRequest) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO capability_requests
		    (id, agent_id, owner_id, capability, justification, requested_purpose, resource,
		     requested_by_did, requested_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		r.ID, r.AgentID, r.OwnerID, r.Capability, r.Justification,
		nullable(r.Purpose), nullable(r.Resource), r.RequestedByDID, r.RequestedAt, r.ExpiresAt)
	return classify(err)
}

// CapabilityRequests lists an agent's requests, newest first.
func (db *DB) CapabilityRequests(ctx context.Context, agentID string, limit int) ([]CapabilityRequest, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.pool.Query(ctx, `
		SELECT id, agent_id, owner_id, capability, justification, requested_purpose, resource,
		       state::text, requested_by_did, requested_at, expires_at
		  FROM capability_requests
		 WHERE agent_id = $1
		 ORDER BY requested_at DESC
		 LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []CapabilityRequest{}
	for rows.Next() {
		var r CapabilityRequest
		var purpose, resource *string
		if err := rows.Scan(&r.ID, &r.AgentID, &r.OwnerID, &r.Capability, &r.Justification,
			&purpose, &resource, &r.State, &r.RequestedByDID, &r.RequestedAt, &r.ExpiresAt); err != nil {
			return nil, classify(err)
		}
		r.Purpose, r.Resource = deref(purpose), deref(resource)
		out = append(out, r)
	}
	return out, classify(rows.Err())
}

// Suspicion is a signed report that an agent may have caused harm.
//
// Every field that identifies the reporter is required. §14 makes accusation
// itself a consequential act: an anonymous path into this table would turn the
// quarantine machinery into a denial-of-service tool against any identity, at
// no cost and no risk to whoever pulls it (T-24).
type Suspicion struct {
	ID                    string
	AgentID               string
	OwnerID               string
	ReporterDID           string
	ReporterType          string
	RelatedEventIDs       []string
	HarmCategories        json.RawMessage
	GuardrailRule         string
	PolicyVersion         string
	BundleHash            string
	EvidenceCommitments   []string
	Confidence            float64
	AffectedJurisdictions []string
	DedupKey              string
	Signature             string
	SignerKID             string
	CreatedAt             time.Time
}

// FileSuspicion records a report, merging it into an existing one when the
// dedup key matches.
//
// Merging rather than inserting is what stops one adversary manufacturing
// corroboration from many identities: N reports of the same (agent, rule,
// events) raise one counter instead of producing N independent-looking
// suspicions. It returns the surviving row's id and its corroboration count.
func (db *DB) FileSuspicion(ctx context.Context, s Suspicion) (string, int, error) {
	var (
		id    string
		count int
	)
	err := db.pool.QueryRow(ctx, `
		WITH merged AS (
			UPDATE harm_suspicions
			   SET corroboration_count = corroboration_count + 1
			 WHERE dedup_key = $1 AND agent_id = $2
			   AND reporter_did <> $3
			RETURNING id, corroboration_count
		), inserted AS (
			INSERT INTO harm_suspicions
			    (id, agent_id, owner_id, reporter_did, reporter_type, related_event_ids,
			     harm_categories, guardrail_rule, policy_version, bundle_hash,
			     evidence_commitments, confidence, affected_jurisdictions, dedup_key,
			     signature, signer_kid, created_at)
			SELECT $4,$2,$5,$3,$6::reporter_type,$7,$8::jsonb,$9,$10,$11,$12,$13,$14,$1,$15,$16,$17
			 WHERE NOT EXISTS (SELECT 1 FROM merged)
			RETURNING id, corroboration_count
		)
		SELECT id, corroboration_count FROM merged
		UNION ALL
		SELECT id, corroboration_count FROM inserted`,
		s.DedupKey, s.AgentID, s.ReporterDID, s.ID, s.OwnerID, s.ReporterType,
		s.RelatedEventIDs, s.HarmCategories, nullable(s.GuardrailRule),
		nullable(s.PolicyVersion), nullable(s.BundleHash), s.EvidenceCommitments,
		s.Confidence, s.AffectedJurisdictions, s.Signature, s.SignerKID, s.CreatedAt).
		Scan(&id, &count)
	if err != nil {
		return "", 0, classify(err)
	}
	return id, count, nil
}

// OwnerByID loads an owner.
func (db *DB) OwnerByID(ctx context.Context, id string) (Owner, error) {
	var o Owner
	var orgID *string
	err := db.pool.QueryRow(ctx, `
		SELECT id, uai_id, did, organization_id, display_name, is_individual,
		       jurisdiction, status::text
		  FROM owners WHERE id = $1`, id).
		Scan(&o.ID, &o.UAIID, &o.DID, &orgID, &o.DisplayName, &o.IsIndividual,
			&o.Jurisdiction, &o.Status)
	if err != nil {
		return Owner{}, classify(err)
	}
	o.OrganizationID = deref(orgID)
	return o, nil
}

// PendingRequest is a request waiting on its owner, with the identifiers the
// owner needs to decide it.
type PendingRequest struct {
	CapabilityRequest
	AgentDID   string
	AgentUAIID string
	OwnerDID   string
}

// PendingCapabilityRequests lists what an owner has been asked for.
func (db *DB) PendingCapabilityRequests(ctx context.Context, ownerDID string, now time.Time) ([]PendingRequest, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT r.id, r.agent_id, r.owner_id, r.capability, r.justification,
		       r.requested_purpose, r.resource, r.state::text, r.requested_by_did,
		       r.requested_at, r.expires_at, a.did, a.uai_id, o.did
		  FROM capability_requests r
		  JOIN agents a ON a.id = r.agent_id
		  JOIN owners o ON o.id = r.owner_id
		 WHERE r.state = 'PENDING' AND r.expires_at > $2
		   AND ($1 = '' OR o.did = $1)
		 ORDER BY r.requested_at`, ownerDID, now)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []PendingRequest{}
	for rows.Next() {
		var p PendingRequest
		var purpose, resource *string
		if err := rows.Scan(&p.ID, &p.AgentID, &p.OwnerID, &p.Capability, &p.Justification,
			&purpose, &resource, &p.State, &p.RequestedByDID, &p.RequestedAt, &p.ExpiresAt,
			&p.AgentDID, &p.AgentUAIID, &p.OwnerDID); err != nil {
			return nil, classify(err)
		}
		p.Purpose, p.Resource = deref(purpose), deref(resource)
		out = append(out, p)
	}
	return out, classify(rows.Err())
}

// CapabilityRequestByID loads one request with the identifiers needed to decide it.
func (db *DB) CapabilityRequestByID(ctx context.Context, id string) (PendingRequest, error) {
	var p PendingRequest
	var purpose, resource *string
	err := db.pool.QueryRow(ctx, `
		SELECT r.id, r.agent_id, r.owner_id, r.capability, r.justification,
		       r.requested_purpose, r.resource, r.state::text, r.requested_by_did,
		       r.requested_at, r.expires_at, a.did, a.uai_id, o.did
		  FROM capability_requests r
		  JOIN agents a ON a.id = r.agent_id
		  JOIN owners o ON o.id = r.owner_id
		 WHERE r.id = $1`, id).
		Scan(&p.ID, &p.AgentID, &p.OwnerID, &p.Capability, &p.Justification,
			&purpose, &resource, &p.State, &p.RequestedByDID, &p.RequestedAt, &p.ExpiresAt,
			&p.AgentDID, &p.AgentUAIID, &p.OwnerDID)
	if err != nil {
		return PendingRequest{}, classify(err)
	}
	p.Purpose, p.Resource = deref(purpose), deref(resource)
	return p, nil
}

// DecideCapabilityRequest records an owner's decision and, on approval, the
// grant it authorizes -- in one transaction.
//
// Atomic because the two halves are one act. A decision row with no grant would
// tell an auditor the owner approved while the agent still could not act; a
// grant with no decision row would be a capability nobody is recorded as having
// authorized, which is the exact thing the request table exists to prevent.
func (db *DB) DecideCapabilityRequest(ctx context.Context, requestID, state, decidedByDID,
	signature, note string, at time.Time, grantID string, expires *time.Time) error {

	return db.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE capability_requests
			   SET state = $2::capability_request_state, decided_by_did = $3,
			       decided_at = $4, decision_signature = $5, decision_note = NULLIF($6,'')
			 WHERE id = $1 AND state = 'PENDING'`,
			requestID, state, decidedByDID, at, signature, note)
		if err != nil {
			return classify(err)
		}
		if tag.RowsAffected() == 0 {
			// Already decided, or gone. Deciding twice is refused rather than
			// overwritten: an owner who changes their mind revokes the grant,
			// which leaves both facts on the record.
			return fmt.Errorf("%w: no pending request %s", ErrNotFound, requestID)
		}
		if state != "APPROVED" {
			return nil
		}
		var agentID, capability string
		if err := tx.QueryRow(ctx, `
			SELECT agent_id, capability FROM capability_requests WHERE id = $1`, requestID).
			Scan(&agentID, &capability); err != nil {
			return classify(err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO capability_grants (id, agent_id, capability, granted_by_did,
			                               granted_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			grantID, agentID, capability, decidedByDID, at, expires)
		return classify(err)
	})
}
