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
	// IdentityCommitmentSalt opens IdentityCommitment. Without it the on-chain
	// commitment is a hash nobody can ever tie back to this identity.
	IdentityCommitmentSalt []byte
	RegisteredAt           time.Time
	RevokedAt              *time.Time
}

// KeyRecord is one entry of a key history. Agents and owners both have one:
// an owner signs the ownership half of a registration proof and, for a lost
// agent, the unbind request, so its keys need exactly the same lifecycle —
// rotation, revocation, compromise, and resolution as of a past moment.
type KeyRecord struct {
	ID string
	// SubjectID is the agent or owner the key belongs to.
	SubjectID   string
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

// AgentKey is retained as the name used at agent call sites.
type AgentKey = KeyRecord

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
	return db.InTx(ctx, func(tx pgx.Tx) error { return insertAgent(ctx, tx, a, key) })
}

// insertAgent is the shared body: registration mints an agent inside a larger
// transaction that also closes the registration, and both paths must create the
// identity and its first key together or not at all.
func insertAgent(ctx context.Context, tx pgx.Tx, a Agent, key AgentKey) error {
	{
		var orgID any
		if a.OrganizationID != "" {
			orgID = a.OrganizationID
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO agents (id, uai_id, did, owner_id, organization_id, logical_name, version,
			                    agent_type, vendor, model_family, model_pinned, framework,
			                    primary_jurisdiction, assurance_level, status,
			                    identity_commitment, policy_version, genesis_event_hash,
			                    identity_commitment_salt)
			VALUES ($1,$2,$3,$4,$5,$6,COALESCE(NULLIF($7,''),'0.0.0'),$8,$9,$10,$11,$12,$13,
			        COALESCE(NULLIF($14,''),'UAI-AL0')::assurance_level,
			        COALESCE(NULLIF($15,''),'REGISTERED')::agent_status,$16,$17,$18,$19)`,
			a.ID, a.UAIID, a.DID, a.OwnerID, orgID, a.LogicalName, a.Version, a.AgentType,
			nullable(a.Vendor), nullable(a.ModelFamily), a.ModelPinned, nullable(a.Framework),
			a.PrimaryJurisdiction, a.AssuranceLevel, a.Status,
			a.IdentityCommitment, a.PolicyVersion, a.GenesisEventHash,
			nullableBytes(a.IdentityCommitmentSalt))
		if err != nil {
			return classify(err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO agent_keys (id, agent_id, key_id, alg, public_jwk, protection,
			                        valid_from, valid_until, log_index)
			VALUES ($1,$2,$3,$4::signature_alg,$5,$6::key_protection,$7,$8,$9)`,
			key.ID, a.ID, key.KeyID, key.Alg, key.PublicJWK, key.Protection,
			key.ValidFrom, key.ValidUntil, key.LogIndex)
		if err != nil {
			return classify(err)
		}
		// The first link of the chain (§9.4, "EVENT 001 register"). Writing it
		// here rather than letting the head fall back to a column on agents
		// means an agent either has a chain or does not exist: there is no
		// third state where the head is inferred from somewhere else.
		return appendChainEvent(ctx, tx, ChainEvent{
			ID: "evt-" + a.ID, AgentID: a.ID, Sequence: 1, Kind: KindRegister,
			EventHash: a.GenesisEventHash, OccurredAt: registeredAt(a),
		}, ChainHead{})
	}
}

// registeredAt is the moment the identity came into existence.
func registeredAt(a Agent) time.Time {
	if a.RegisteredAt.IsZero() {
		return time.Now().UTC()
	}
	return a.RegisteredAt
}

// OrganizationDIDByID returns an organization's DID, or "" when there is none.
//
// Empty rather than an error for the no-organization case: an individual owner
// registering their own agent is ordinary, and a credential must not assert
// membership in an organization named "".
func (db *DB) OrganizationDIDByID(ctx context.Context, orgID string) (string, error) {
	if orgID == "" {
		return "", nil
	}
	var did string
	err := db.pool.QueryRow(ctx, `SELECT did FROM organizations WHERE id = $1`, orgID).Scan(&did)
	if err != nil {
		return "", classify(err)
	}
	return did, nil
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
		if err := rows.Scan(&k.ID, &k.SubjectID, &k.KeyID, &k.Alg, &k.PublicJWK, &k.Protection,
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

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
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

// AgentByDID loads an agent by its DID.
func (db *DB) AgentByDID(ctx context.Context, did string) (Agent, error) {
	var uaiID string
	if err := db.pool.QueryRow(ctx, `SELECT uai_id FROM agents WHERE did = $1`, did).Scan(&uaiID); err != nil {
		return Agent{}, classify(err)
	}
	return db.AgentByUAIID(ctx, uaiID)
}
