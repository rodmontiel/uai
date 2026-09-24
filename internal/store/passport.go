package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rodmontiel/uai/pkg/passport"
)

// PassportRecord is a stored passport with its capability scope.
type PassportRecord struct {
	ID                      string
	AgentID                 string
	AgentDID                string
	OwnerDID                string
	CredentialID            string
	CredentialHash          string
	State                   string
	AllowedJurisdictions    []string
	RestrictedJurisdictions []string
	AssuranceLevel          string
	PolicyVersion           string
	PolicyBundleHash        string
	DecisionID              string
	ValidFrom               time.Time
	ValidUntil              time.Time
	Capabilities            []passport.AuthorizedCapability
}

// CreatePassport writes a passport and its capability scope in one transaction.
//
// Atomic on purpose: a passport row with no capability rows authorizes nothing
// while looking valid, and §11.6 step 7 would deny every action against it. A
// half-written passport is therefore not a smaller passport, it is a passport
// that misreports why it refuses.
func (db *DB) CreatePassport(ctx context.Context, p PassportRecord) error {
	return db.InTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO passports (id, agent_id, credential_id, credential_hash, state,
			                       allowed_jurisdictions, restricted_jurisdictions,
			                       assurance_level, policy_version, policy_bundle_hash,
			                       decision_id, valid_from, valid_until)
			VALUES ($1,$2,$3,$4,$5::passport_state,$6,$7,$8::assurance_level,$9,$10,$11,$12,$13)`,
			p.ID, p.AgentID, nullable(p.CredentialID), nullable(p.CredentialHash), p.State,
			p.AllowedJurisdictions, p.RestrictedJurisdictions, p.AssuranceLevel,
			p.PolicyVersion, p.PolicyBundleHash, nullable(p.DecisionID), p.ValidFrom, p.ValidUntil)
		if err != nil {
			return classify(err)
		}
		for _, c := range p.Capabilities {
			constraints, err := json.Marshal(c.Constraints)
			if err != nil {
				return err
			}
			// The capability must already exist in the catalogue. A passport
			// naming a capability nothing defines would authorize a string.
			if _, err := tx.Exec(ctx, `
				INSERT INTO passport_capabilities (passport_id, capability, min_assurance, constraints)
				VALUES ($1,$2,$3::assurance_level,$4)`,
				p.ID, c.Capability, c.MinAssurance, constraints); err != nil {
				return classify(err)
			}
		}
		return nil
	})
}

// PassportByID loads a passport with its capability scope.
func (db *DB) PassportByID(ctx context.Context, id string) (PassportRecord, error) {
	var p PassportRecord
	var credentialID, credentialHash, decisionID *string
	var validFrom, validUntil *time.Time
	err := db.pool.QueryRow(ctx, `
		SELECT p.id, p.agent_id, a.did, o.did, p.credential_id, p.credential_hash, p.state::text,
		       p.allowed_jurisdictions, p.restricted_jurisdictions, p.assurance_level::text,
		       p.policy_version, p.policy_bundle_hash, p.decision_id, p.valid_from, p.valid_until
		  FROM passports p
		  JOIN agents a ON a.id = p.agent_id
		  JOIN owners o ON o.id = a.owner_id
		 WHERE p.id = $1`, id).
		Scan(&p.ID, &p.AgentID, &p.AgentDID, &p.OwnerDID, &credentialID, &credentialHash, &p.State,
			&p.AllowedJurisdictions, &p.RestrictedJurisdictions, &p.AssuranceLevel,
			&p.PolicyVersion, &p.PolicyBundleHash, &decisionID, &validFrom, &validUntil)
	if err != nil {
		return PassportRecord{}, classify(err)
	}
	p.CredentialID, p.CredentialHash, p.DecisionID = deref(credentialID), deref(credentialHash), deref(decisionID)
	if validFrom != nil {
		p.ValidFrom = *validFrom
	}
	if validUntil != nil {
		p.ValidUntil = *validUntil
	}

	rows, err := db.pool.Query(ctx, `
		SELECT capability, min_assurance::text, constraints
		  FROM passport_capabilities WHERE passport_id = $1 ORDER BY capability`, id)
	if err != nil {
		return PassportRecord{}, classify(err)
	}
	defer rows.Close()
	for rows.Next() {
		var c passport.AuthorizedCapability
		var raw []byte
		if err := rows.Scan(&c.Capability, &c.MinAssurance, &raw); err != nil {
			return PassportRecord{}, classify(err)
		}
		if err := json.Unmarshal(raw, &c.Constraints); err != nil {
			return PassportRecord{}, err
		}
		p.Capabilities = append(p.Capabilities, c)
	}
	return p, classify(rows.Err())
}

// LivePassport returns an agent's current passport, or ErrNotFound.
func (db *DB) LivePassport(ctx context.Context, agentID string) (PassportRecord, error) {
	var id string
	// Newest first: a renewal is a new credential rather than an extension
	// (§11.4), so the most recently issued VALID passport is the one in force.
	err := db.pool.QueryRow(ctx, `
		SELECT id FROM passports
		 WHERE agent_id = $1 AND state = 'VALID'
		 ORDER BY valid_from DESC NULLS LAST, created_at DESC
		 LIMIT 1`, agentID).Scan(&id)
	if err != nil {
		return PassportRecord{}, classify(err)
	}
	return db.PassportByID(ctx, id)
}

// Passport renders the record as the protocol object pkg/passport checks.
//
// The state is derived here rather than copied: a passport whose agent was
// revoked or quarantined follows its agent (§11.4), and computing that at read
// time means the two can never disagree because an update was missed.
func (p PassportRecord) Passport(agentStatus string, now time.Time) *passport.Passport {
	state := passport.State(p.State)
	switch {
	case agentStatus == "REVOKED":
		state = passport.StateRevoked
	case agentStatus == "QUARANTINED" && state == passport.StateValid:
		state = passport.StateQuarantined
	case state == passport.StateValid && !now.Before(p.ValidUntil):
		state = passport.StateExpired
	}
	return &passport.Passport{
		ID: p.ID, Agent: p.AgentDID, Owner: p.OwnerDID,
		AllowedJurisdictions: p.AllowedJurisdictions, RestrictedJurisdictions: p.RestrictedJurisdictions,
		AuthorizedCapabilities: p.Capabilities, AssuranceLevel: p.AssuranceLevel,
		PolicyVersion: p.PolicyVersion, PolicyBundleHash: p.PolicyBundleHash,
		State: state, ValidFrom: p.ValidFrom, ValidUntil: p.ValidUntil,
		CredentialHash: p.CredentialHash,
	}
}

// ActionsInLastHour counts an agent's actions under one capability.
//
// It is the input to the passport rate constraint (§11.6 step 9). Counted from
// the chain rather than from a counter: a counter can be reset, and the chain
// is the record the constraint is actually about.
func (db *DB) ActionsInLastHour(ctx context.Context, agentID, capability string, now time.Time) (int, error) {
	var n int
	err := db.pool.QueryRow(ctx, `
		SELECT count(*) FROM action_events
		 WHERE agent_id = $1 AND capability = $2 AND asserted_at > $3`,
		agentID, capability, now.Add(-time.Hour)).Scan(&n)
	return n, classify(err)
}
