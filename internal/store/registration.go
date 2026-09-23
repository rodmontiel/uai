package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Errors specific to the registration flow. They exist as sentinels because the
// HTTP layer must map each to a distinct refusal from §8.5: a caller has to be
// able to tell "your proof was late" from "your proof named a different agent",
// since only one of those is worth retrying.
var (
	// ErrRegistrationExpired means the challenge window closed. §8.5 maps this
	// to UAI_CHALLENGE_INVALID.
	ErrRegistrationExpired = errors.New("store: registration challenge has expired")
	// ErrProofMismatch means a second proof named a different subject than the
	// first. §8.5 maps this to UAI_PROOF_MISMATCH.
	ErrProofMismatch = errors.New("store: proof does not name the subject this registration already fixed")
	// ErrAlreadyProved means this half of the proof was already submitted. A
	// proof is final: replacing one would let the party that went first change
	// what it vouched for after seeing the other half.
	ErrAlreadyProved = errors.New("store: this half of the registration proof was already submitted")
	// ErrRegistrationClosed means the identity was already minted.
	ErrRegistrationClosed = errors.New("store: registration was already minted")
)

// Registration is a draft identity between the two calls of §8.2.
//
// Nothing in it is trusted. It is what somebody ASKED for; it becomes a record
// only when two independent signatures agree on the same subject and the
// identity is minted.
type Registration struct {
	ID                    string
	LogicalName           string
	Version               string
	AgentType             string
	OwnerID               string
	OwnerDID              string
	OrganizationID        string
	Vendor                string
	ModelFamily           string
	ModelPinned           bool
	Framework             string
	PrimaryJurisdiction   string
	RequestedCapabilities []string
	PolicyVersion         string

	ChallengeOwner string
	ChallengeAgent string
	ExpiresAt      time.Time

	AgentKeyThumbprint string
	OwnerProofSig      json.RawMessage
	OwnerProofKID      string
	OwnerProvedAt      *time.Time
	AgentProofSig      json.RawMessage
	AgentPublicJWK     json.RawMessage
	AgentProvedAt      *time.Time

	MintedAgentID string
	MintedAt      *time.Time
	CreatedAt     time.Time
}

// Complete reports whether both halves of the proof are in.
func (r Registration) Complete() bool { return r.OwnerProvedAt != nil && r.AgentProvedAt != nil }

// Minted reports whether the identity was already created.
func (r Registration) Minted() bool { return r.MintedAgentID != "" }

// CreateOwnerKey registers a key for an owner.
//
// Owner keys are provisioned administratively rather than through a public
// endpoint: the party that vouches for agents cannot itself be self-asserted,
// so §22.2 defines no owner-registration route.
func (db *DB) CreateOwnerKey(ctx context.Context, ownerID string, k KeyRecord) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO owner_keys (id, owner_id, key_id, alg, public_jwk, protection,
		                        valid_from, valid_until, log_index)
		VALUES ($1,$2,$3,$4::signature_alg,$5,$6::key_protection,$7,$8,$9)`,
		k.ID, ownerID, k.KeyID, k.Alg, k.PublicJWK, k.Protection,
		k.ValidFrom, k.ValidUntil, k.LogIndex)
	return classify(err)
}

// OwnerKeys returns an owner's key history, oldest first.
func (db *DB) OwnerKeys(ctx context.Context, ownerID string) ([]KeyRecord, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, owner_id, key_id, alg::text, public_jwk, protection::text,
		       valid_from, valid_until, revoked_at, compromise_declared_at, log_index
		FROM owner_keys WHERE owner_id = $1 ORDER BY valid_from, key_id`, ownerID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []KeyRecord
	for rows.Next() {
		var k KeyRecord
		if err := rows.Scan(&k.ID, &k.SubjectID, &k.KeyID, &k.Alg, &k.PublicJWK, &k.Protection,
			&k.ValidFrom, &k.ValidUntil, &k.RevokedAt, &k.Compromised, &k.LogIndex); err != nil {
			return nil, classify(err)
		}
		out = append(out, k)
	}
	return out, classify(rows.Err())
}

// OwnerByDID loads an owner by its DID.
func (db *DB) OwnerByDID(ctx context.Context, did string) (Owner, error) {
	var o Owner
	var orgID *string
	err := db.pool.QueryRow(ctx, `
		SELECT id, uai_id, did, organization_id, display_name, is_individual,
		       jurisdiction, status::text, restrictions
		FROM owners WHERE did = $1`, did).
		Scan(&o.ID, &o.UAIID, &o.DID, &orgID, &o.DisplayName, &o.IsIndividual,
			&o.Jurisdiction, &o.Status, &o.Restrictions)
	if err != nil {
		return Owner{}, classify(err)
	}
	o.OrganizationID = deref(orgID)
	return o, nil
}

// OpenRegistration stores a draft and its two challenges.
func (db *DB) OpenRegistration(ctx context.Context, r Registration) error {
	var orgID any
	if r.OrganizationID != "" {
		orgID = r.OrganizationID
	}
	caps := r.RequestedCapabilities
	if caps == nil {
		caps = []string{}
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO registrations (id, logical_name, version, agent_type, owner_id, owner_did,
		                           organization_id, vendor, model_family, model_pinned, framework,
		                           primary_jurisdiction, requested_capabilities, policy_version,
		                           challenge_owner, challenge_agent, expires_at)
		VALUES ($1,$2,COALESCE(NULLIF($3,''),'0.0.0'),$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		r.ID, r.LogicalName, r.Version, r.AgentType, r.OwnerID, r.OwnerDID, orgID,
		nullable(r.Vendor), nullable(r.ModelFamily), r.ModelPinned, nullable(r.Framework),
		r.PrimaryJurisdiction, caps, r.PolicyVersion,
		r.ChallengeOwner, r.ChallengeAgent, r.ExpiresAt)
	return classify(err)
}

const registrationColumns = `id, logical_name, version, agent_type, owner_id, owner_did,
	organization_id, vendor, model_family, model_pinned, framework, primary_jurisdiction,
	requested_capabilities, policy_version, challenge_owner, challenge_agent, expires_at,
	agent_key_thumbprint, owner_proof_sig, owner_proof_kid, owner_proved_at,
	agent_proof_sig, agent_public_jwk, agent_proved_at, minted_agent_id, minted_at, created_at`

func scanRegistration(row pgx.Row) (Registration, error) {
	var r Registration
	var orgID, vendor, modelFamily, framework, thumb, ownerKID, mintedID *string
	err := row.Scan(&r.ID, &r.LogicalName, &r.Version, &r.AgentType, &r.OwnerID, &r.OwnerDID,
		&orgID, &vendor, &modelFamily, &r.ModelPinned, &framework, &r.PrimaryJurisdiction,
		&r.RequestedCapabilities, &r.PolicyVersion, &r.ChallengeOwner, &r.ChallengeAgent,
		&r.ExpiresAt, &thumb, &r.OwnerProofSig, &ownerKID, &r.OwnerProvedAt,
		&r.AgentProofSig, &r.AgentPublicJWK, &r.AgentProvedAt, &mintedID, &r.MintedAt, &r.CreatedAt)
	if err != nil {
		return Registration{}, classify(err)
	}
	r.OrganizationID, r.Vendor = deref(orgID), deref(vendor)
	r.ModelFamily, r.Framework = deref(modelFamily), deref(framework)
	r.AgentKeyThumbprint, r.OwnerProofKID, r.MintedAgentID = deref(thumb), deref(ownerKID), deref(mintedID)
	return r, nil
}

// RegistrationByID loads a draft.
func (db *DB) RegistrationByID(ctx context.Context, id string) (Registration, error) {
	return scanRegistration(db.pool.QueryRow(ctx,
		`SELECT `+registrationColumns+` FROM registrations WHERE id = $1`, id))
}

// Proof is one half of a registration proof.
type Proof struct {
	// Thumbprint is the agent key the proof names. Both halves must name the
	// same one; the first to arrive fixes it.
	Thumbprint string
	Signature  json.RawMessage
	// SignerKID is set for the owner half: the owner signs with a key the
	// registry already holds.
	SignerKID string
	// PublicJWK is set for the agent half: the agent's key is being introduced
	// here, so it arrives with the proof rather than being looked up.
	PublicJWK json.RawMessage
	At        time.Time
}

// RecordOwnerProof stores the owner half.
func (db *DB) RecordOwnerProof(ctx context.Context, regID string, p Proof) (Registration, error) {
	return db.recordProof(ctx, regID, p, true)
}

// RecordAgentProof stores the agent half.
func (db *DB) RecordAgentProof(ctx context.Context, regID string, p Proof) (Registration, error) {
	return db.recordProof(ctx, regID, p, false)
}

// recordProof writes one half under a row lock.
//
// The lock is what makes "first proof fixes the subject" true under
// concurrency. Without it, two proofs naming different agent keys could both
// read a NULL thumbprint, both decide they are first, and one would overwrite
// the subject the other had already vouched for.
func (db *DB) recordProof(ctx context.Context, regID string, p Proof, owner bool) (Registration, error) {
	var out Registration
	err := db.InTx(ctx, func(tx pgx.Tx) error {
		cur, err := scanRegistration(tx.QueryRow(ctx,
			`SELECT `+registrationColumns+` FROM registrations WHERE id = $1 FOR UPDATE`, regID))
		if err != nil {
			return err
		}
		switch {
		case cur.Minted():
			return fmt.Errorf("%w: %s", ErrRegistrationClosed, regID)
		case !p.At.Before(cur.ExpiresAt):
			return fmt.Errorf("%w: %s expired at %s", ErrRegistrationExpired, regID,
				cur.ExpiresAt.UTC().Format(time.RFC3339))
		case owner && cur.OwnerProvedAt != nil, !owner && cur.AgentProvedAt != nil:
			return fmt.Errorf("%w: %s", ErrAlreadyProved, regID)
		case cur.AgentKeyThumbprint != "" && cur.AgentKeyThumbprint != p.Thumbprint:
			return fmt.Errorf("%w: registration names %s, proof names %s",
				ErrProofMismatch, cur.AgentKeyThumbprint, p.Thumbprint)
		}

		if owner {
			_, err = tx.Exec(ctx, `
				UPDATE registrations
				   SET agent_key_thumbprint = $2, owner_proof_sig = $3,
				       owner_proof_kid = $4, owner_proved_at = $5
				 WHERE id = $1`, regID, p.Thumbprint, p.Signature, p.SignerKID, p.At)
		} else {
			_, err = tx.Exec(ctx, `
				UPDATE registrations
				   SET agent_key_thumbprint = $2, agent_proof_sig = $3,
				       agent_public_jwk = $4, agent_proved_at = $5
				 WHERE id = $1`, regID, p.Thumbprint, p.Signature, p.PublicJWK, p.At)
		}
		if err != nil {
			return classify(err)
		}
		out, err = scanRegistration(tx.QueryRow(ctx,
			`SELECT `+registrationColumns+` FROM registrations WHERE id = $1`, regID))
		return err
	})
	return out, err
}

// MintAgent creates the identity and closes the registration atomically.
//
// Atomicity is the point: a minted agent whose registration still looks open
// could be minted a second time under a second identifier, giving one proven
// key two identities and breaking the one thing an identifier is for.
func (db *DB) MintAgent(ctx context.Context, regID string, a Agent, key AgentKey, at time.Time) error {
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
		_, err = tx.Exec(ctx,
			`UPDATE registrations SET minted_agent_id = $2, minted_at = $3 WHERE id = $1`,
			regID, a.ID, at)
		return classify(err)
	})
}

// PurgeExpiredRegistrations deletes drafts that were never proven.
//
// Unproven drafts are the one thing in this system that may be deleted: nobody
// ever vouched for them, no identifier was minted from them, and no verifier can
// have relied on them. Keeping them would only accumulate challenges an
// attacker could grind against.
func (db *DB) PurgeExpiredRegistrations(ctx context.Context, before time.Time) (int64, error) {
	tag, err := db.pool.Exec(ctx,
		`DELETE FROM registrations WHERE minted_agent_id IS NULL AND expires_at < $1`, before)
	if err != nil {
		return 0, classify(err)
	}
	return tag.RowsAffected(), nil
}

func errRegistrationClosed(regID, agentID string) error {
	return fmt.Errorf("%w: %s is already %s", ErrRegistrationClosed, regID, agentID)
}

func errNeedsBothProofs(regID string) error {
	return fmt.Errorf("%w: %s still needs both proofs", ErrConflict, regID)
}
