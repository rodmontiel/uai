package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Organization is a legal entity.
type Organization struct {
	ID           string
	DID          string
	LegalName    string
	Jurisdiction string
	Status       string
}

// Owner is the party that answers for an agent.
type Owner struct {
	ID             string
	UAIID          string
	DID            string
	OrganizationID string
	DisplayName    string
	IsIndividual   bool
	Jurisdiction   string
	Status         string
	Restrictions   []string
}

// Agent is the core identity record.
type Agent struct {
	ID                  string
	UAIID               string
	DID                 string
	OwnerID             string
	OrganizationID      string
	LogicalName         string
	Version             string
	AgentType           string
	Vendor              string
	ModelFamily         string
	ModelPinned         bool
	Framework           string
	PrimaryJurisdiction string
	AssuranceLevel      string
	Status              string
	IdentityCommitment  string
	PolicyVersion       string
	GenesisEventHash    string
	RegisteredAt        time.Time
	RevokedAt           *time.Time
}

// AgentKey is one entry of an agent's key history.
type AgentKey struct {
	ID          string
	AgentID     string
	KeyID       string
	Alg         string
	PublicJWK   json.RawMessage
	Protection  string
	ValidFrom   time.Time
	ValidUntil  *time.Time
	RevokedAt   *time.Time
	Compromised *time.Time
	LogIndex    *int64
}

// CreateOrganization inserts an organization.
func (db *DB) CreateOrganization(ctx context.Context, o Organization) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO organizations (id, did, legal_name, jurisdiction, status)
		VALUES ($1, $2, $3, $4, COALESCE(NULLIF($5,''), 'ACTIVE')::entity_status)`,
		o.ID, o.DID, o.LegalName, o.Jurisdiction, o.Status)
	return classify(err)
}

// CreateOwner inserts an owner.
func (db *DB) CreateOwner(ctx context.Context, o Owner) error {
	var orgID any
	if o.OrganizationID != "" {
		orgID = o.OrganizationID
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO owners (id, uai_id, did, organization_id, display_name, is_individual,
		                    jurisdiction, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE(NULLIF($8,''), 'ACTIVE')::entity_status)`,
		o.ID, o.UAIID, o.DID, orgID, o.DisplayName, o.IsIndividual, o.Jurisdiction, o.Status)
	return classify(err)
}

// CreateAgent inserts a registered agent together with its first key, in one
// transaction.
//
// They are atomic on purpose: an identity with no key can never be verified,
// so a registration that half-succeeded would leave an unusable record that
// nonetheless occupies its identifier forever.
func (db *DB) CreateAgent(ctx context.Context, a Agent, key AgentKey) error {
	return db.InTx(ctx, func(tx pgx.Tx) error {
		var orgID any
		if a.OrganizationID != "" {
			orgID = a.OrganizationID
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO agents (id, uai_id, did, owner_id, organization_id, logical_name, version,
			                    agent_type, vendor, model_family, model_pinned, framework,
			                    primary_jurisdiction, assurance_level, status,
			                    identity_commitment, policy_version, genesis_event_hash)
			VALUES ($1,$2,$3,$4,$5,$6,COALESCE(NULLIF($7,''),'0.0.0'),$8,$9,$10,$11,$12,$13,
			        COALESCE(NULLIF($14,''),'UAI-AL0')::assurance_level,
			        COALESCE(NULLIF($15,''),'REGISTERED')::agent_status,$16,$17,$18)`,
			a.ID, a.UAIID, a.DID, a.OwnerID, orgID, a.LogicalName, a.Version, a.AgentType,
			nullable(a.Vendor), nullable(a.ModelFamily), a.ModelPinned, nullable(a.Framework),
			a.PrimaryJurisdiction, a.AssuranceLevel, a.Status,
			a.IdentityCommitment, a.PolicyVersion, a.GenesisEventHash)
		if err != nil {
			return classify(err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO agent_keys (id, agent_id, key_id, alg, public_jwk, protection,
			                        valid_from, valid_until, log_index)
			VALUES ($1,$2,$3,$4::signature_alg,$5,$6::key_protection,$7,$8,$9)`,
			key.ID, a.ID, key.KeyID, key.Alg, key.PublicJWK, key.Protection,
			key.ValidFrom, key.ValidUntil, key.LogIndex)
		return classify(err)
	})
}

// AgentByUAIID loads an agent by its UAI-ID.
func (db *DB) AgentByUAIID(ctx context.Context, uaiID string) (Agent, error) {
	var a Agent
	var orgID, vendor, modelFamily, framework *string
	err := db.pool.QueryRow(ctx, `
		SELECT id, uai_id, did, owner_id, organization_id, logical_name, version, agent_type,
		       vendor, model_family, model_pinned, framework, primary_jurisdiction,
		       assurance_level::text, status::text, identity_commitment, policy_version,
		       genesis_event_hash, registered_at, revoked_at
		FROM agents WHERE uai_id = $1`, uaiID).
		Scan(&a.ID, &a.UAIID, &a.DID, &a.OwnerID, &orgID, &a.LogicalName, &a.Version, &a.AgentType,
			&vendor, &modelFamily, &a.ModelPinned, &framework, &a.PrimaryJurisdiction,
			&a.AssuranceLevel, &a.Status, &a.IdentityCommitment, &a.PolicyVersion,
			&a.GenesisEventHash, &a.RegisteredAt, &a.RevokedAt)
	if err != nil {
		return Agent{}, classify(err)
	}
	a.OrganizationID = deref(orgID)
	a.Vendor, a.ModelFamily, a.Framework = deref(vendor), deref(modelFamily), deref(framework)
	return a, nil
}

// AgentKeys returns an agent's key history, oldest first.
func (db *DB) AgentKeys(ctx context.Context, agentID string) ([]AgentKey, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, agent_id, key_id, alg::text, public_jwk, protection::text,
		       valid_from, valid_until, revoked_at, compromise_declared_at, log_index
		FROM agent_keys WHERE agent_id = $1 ORDER BY valid_from, key_id`, agentID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []AgentKey
	for rows.Next() {
		var k AgentKey
		if err := rows.Scan(&k.ID, &k.AgentID, &k.KeyID, &k.Alg, &k.PublicJWK, &k.Protection,
			&k.ValidFrom, &k.ValidUntil, &k.RevokedAt, &k.Compromised, &k.LogIndex); err != nil {
			return nil, classify(err)
		}
		out = append(out, k)
	}
	return out, classify(rows.Err())
}

// SetAgentStatus moves an agent to a new state.
//
// The transition is validated against the state machine in the caller; this
// method enforces only what the schema can: a revoked agent records when it was
// revoked, and no row is ever deleted (INV-006).
func (db *DB) SetAgentStatus(ctx context.Context, agentID, status string, at time.Time) error {
	var revokedAt any
	if status == "REVOKED" {
		revokedAt = at
	}
	tag, err := db.pool.Exec(ctx, `
		UPDATE agents SET status = $2::agent_status, revoked_at = $3, updated_at = now()
		WHERE id = $1`, agentID, status, revokedAt)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: agent %s", ErrNotFound, agentID)
	}
	return nil
}

// RecordBinding appends a bind, unbind or rebind event.
func (db *DB) RecordBinding(ctx context.Context, id, agentID, operation, previousEventHash,
	continuityProof, spiffeID, reason, signature, signerKID string) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO agent_bindings (id, agent_id, operation, previous_event_hash, continuity_proof,
		                            spiffe_id, reason, signature, signer_kid)
		VALUES ($1,$2,$3::binding_operation,$4,$5,$6,$7,$8,$9)`,
		id, agentID, operation, nullable(previousEventHash), nullable(continuityProof),
		nullable(spiffeID), nullable(reason), signature, signerKID)
	return classify(err)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
