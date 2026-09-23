package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// Credential is a stored verifiable credential.
//
// The document is kept whole. Storing only the claims and re-serializing on
// demand would produce different bytes than the issuer signed, and a credential
// that cannot be handed back byte-for-byte cannot be verified by anyone.
type Credential struct {
	ID             string
	Type           string
	SubjectDID     string
	IssuerDID      string
	AgentID        string
	OwnerID        string
	OrganizationID string
	CredentialHash string
	Document       json.RawMessage
	State          string
	ValidFrom      time.Time
	ValidUntil     *time.Time
	LogIndex       *int64
	CreatedAt      time.Time
}

// CreateCredential stores one credential.
func (db *DB) CreateCredential(ctx context.Context, c Credential) error {
	return db.InTx(ctx, func(tx pgx.Tx) error { return insertCredential(ctx, tx, c) })
}

func insertCredential(ctx context.Context, tx pgx.Tx, c Credential) error {
	var agentID, ownerID, orgID any
	if c.AgentID != "" {
		agentID = c.AgentID
	}
	if c.OwnerID != "" {
		ownerID = c.OwnerID
	}
	if c.OrganizationID != "" {
		orgID = c.OrganizationID
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO credentials (id, credential_type, subject_did, issuer_did, agent_id, owner_id,
		                         organization_id, credential_hash, document, state,
		                         valid_from, valid_until, log_index)
		VALUES ($1,$2::credential_type,$3,$4,$5,$6,$7,$8,$9,
		        COALESCE(NULLIF($10,''),'VALID')::credential_state,$11,$12,$13)`,
		c.ID, c.Type, c.SubjectDID, c.IssuerDID, agentID, ownerID, orgID,
		c.CredentialHash, c.Document, c.State, c.ValidFrom, c.ValidUntil, c.LogIndex)
	return classify(err)
}

// CredentialsForAgent returns an agent's credentials, newest first.
func (db *DB) CredentialsForAgent(ctx context.Context, agentID string) ([]Credential, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, credential_type::text, subject_did, issuer_did, credential_hash, document,
		       state::text, valid_from, valid_until, log_index, created_at
		FROM credentials WHERE agent_id = $1 ORDER BY created_at DESC, id`, agentID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.Type, &c.SubjectDID, &c.IssuerDID, &c.CredentialHash,
			&c.Document, &c.State, &c.ValidFrom, &c.ValidUntil, &c.LogIndex, &c.CreatedAt); err != nil {
			return nil, classify(err)
		}
		c.AgentID = agentID
		out = append(out, c)
	}
	return out, classify(rows.Err())
}

// MintAgentWithCredentials creates the identity, its first key and its
// credentials in one transaction.
//
// All of it or none of it. §8.2 issues the identity and its credentials in the
// same step, and an identity that exists without the credentials that attest to
// it would occupy an identifier forever while being unverifiable by anyone --
// the worst of both outcomes.
func (db *DB) MintAgentWithCredentials(ctx context.Context, regID string, a Agent, key AgentKey,
	creds []Credential, at time.Time) error {
	return db.InTx(ctx, func(tx pgx.Tx) error {
		cur, err := scanRegistration(tx.QueryRow(ctx,
			`SELECT `+registrationColumns+` FROM registrations WHERE id = $1 FOR UPDATE`, regID))
		if err != nil {
			return err
		}
		if cur.Minted() {
			return errRegistrationClosed(regID, cur.MintedAgentID)
		}
		if !cur.Complete() {
			return errNeedsBothProofs(regID)
		}
		if err := insertAgent(ctx, tx, a, key); err != nil {
			return err
		}
		for _, c := range creds {
			if err := insertCredential(ctx, tx, c); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx,
			`UPDATE registrations SET minted_agent_id = $2, minted_at = $3 WHERE id = $1`,
			regID, a.ID, at)
		return classify(err)
	})
}
