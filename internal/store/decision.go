package store

import (
	"context"
	"encoding/json"
	"time"
)

// Decision is a stored guardrail decision record (§12.3.1).
//
// Every decision is recorded, including ALLOW. A guardrail that only logs
// denials cannot answer "what was permitted and why", which is the first
// question asked after an incident.
type Decision struct {
	ID             string
	AgentID        string
	Capability     string
	Purpose        string
	Resource       string
	Jurisdiction   json.RawMessage
	Checks         json.RawMessage
	RulesFired     []string
	HarmAssessment json.RawMessage
	Effect         string
	Conditions     json.RawMessage
	Degraded       bool
	StalenessSecs  int
	PolicyVersion  string
	BundleHash     string
	Signature      string
	SignerKID      string
	EvaluatedAt    time.Time
}

// RecordDecision stores one decision.
func (db *DB) RecordDecision(ctx context.Context, d Decision) error {
	rules := d.RulesFired
	if rules == nil {
		rules = []string{}
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO policy_decisions (id, agent_id, capability, purpose, resource, jurisdiction,
		                              checks, rules_fired, harm_assessment, effect, conditions,
		                              degraded, bundle_staleness_seconds, policy_version,
		                              bundle_hash, signature, signer_kid, evaluated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9,'[]'::jsonb),$10::policy_decision_effect,
		        COALESCE($11,'{}'::jsonb),$12,$13,$14,$15,$16,$17,$18)`,
		d.ID, d.AgentID, nullable(d.Capability), nullable(d.Purpose), nullable(d.Resource),
		d.Jurisdiction, d.Checks, rules, d.HarmAssessment, d.Effect, d.Conditions,
		d.Degraded, d.StalenessSecs, d.PolicyVersion, d.BundleHash,
		d.Signature, d.SignerKID, d.EvaluatedAt)
	return classify(err)
}

// DecisionByID loads a decision record.
func (db *DB) DecisionByID(ctx context.Context, id string) (Decision, error) {
	var d Decision
	var capability, purpose, resource *string
	err := db.pool.QueryRow(ctx, `
		SELECT id, agent_id, capability, purpose, resource, jurisdiction, checks, rules_fired,
		       harm_assessment, effect::text, conditions, degraded, bundle_staleness_seconds,
		       policy_version, bundle_hash, signature, signer_kid, evaluated_at
		FROM policy_decisions WHERE id = $1`, id).
		Scan(&d.ID, &d.AgentID, &capability, &purpose, &resource, &d.Jurisdiction, &d.Checks,
			&d.RulesFired, &d.HarmAssessment, &d.Effect, &d.Conditions, &d.Degraded,
			&d.StalenessSecs, &d.PolicyVersion, &d.BundleHash, &d.Signature, &d.SignerKID,
			&d.EvaluatedAt)
	if err != nil {
		return Decision{}, classify(err)
	}
	d.Capability, d.Purpose, d.Resource = deref(capability), deref(purpose), deref(resource)
	return d, nil
}

// CapabilityGrants returns the capabilities an agent holds at a given moment.
//
// "At a moment" and not "now": a decision made yesterday has to be replayable
// against the grants that were in force yesterday, or an auditor cannot tell a
// wrong decision from a grant that has since expired.
//
// A revoked or expired grant is simply absent. Absence of a grant is not a
// grant (§12.4), so the policy sees a shorter list and denies, rather than
// seeing a flag it might forget to check.
func (db *DB) CapabilityGrants(ctx context.Context, agentID string, at time.Time) ([]string, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT DISTINCT capability FROM capability_grants
		 WHERE agent_id = $1
		   AND granted_at <= $2
		   AND (expires_at IS NULL OR expires_at > $2)
		   AND (revoked_at IS NULL OR revoked_at > $2)
		 ORDER BY capability`, agentID, at)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	// Never nil: a nil slice marshals to JSON null, and a policy input where
	// "granted" is null instead of [] is a different question than the one the
	// rules were written to answer.
	out := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, classify(err)
		}
		out = append(out, c)
	}
	return out, classify(rows.Err())
}

// GrantCapability records a capability grant.
func (db *DB) GrantCapability(ctx context.Context, id, agentID, capability, grantedByDID string,
	at time.Time, expires *time.Time) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO capability_grants (id, agent_id, capability, granted_by_did, granted_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, id, agentID, capability, grantedByDID, at, expires)
	return classify(err)
}
