package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rodmontiel/uai/pkg/federation"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// ── this registry ───────────────────────────────────────────────────────────

// Registry is this installation's own identity as a UAI-AS.
type Registry struct {
	ASN             federation.ASN
	DID             string
	Name            string
	OrganizationID  string
	PublicJWK       uaicrypto.JWK
	Endpoint        string
	ProtocolVersion string
	Status          string
	CreatedAt       time.Time
}

// LocalRegistry returns this installation's registry identity.
//
// ErrNotFound means federation has not been configured here, which is a normal
// state and not a failure: a registry that has never peered with anyone is a
// registry doing its job.
func (db *DB) LocalRegistry(ctx context.Context) (Registry, error) {
	var r Registry
	var raw []byte
	var org *string
	err := db.pool.QueryRow(ctx, `
		SELECT uai_asn, registry_did, name, organization_id, public_jwk,
		       federation_endpoint, protocol_version, status, created_at
		  FROM federation_registry`).
		Scan(&r.ASN, &r.DID, &r.Name, &org, &raw, &r.Endpoint,
			&r.ProtocolVersion, &r.Status, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Registry{}, ErrNotFound
		}
		return Registry{}, classify(err)
	}
	if org != nil {
		r.OrganizationID = *org
	}
	if err := json.Unmarshal(raw, &r.PublicJWK); err != nil {
		return Registry{}, fmt.Errorf("store: registry public_jwk: %w", err)
	}
	return r, nil
}

// SetLocalRegistry records this installation's identity, or updates the parts of
// it that may change.
//
// The ASN and the DID are not among those parts. A registry that could renumber
// itself would invalidate every peering that named it and every announcement it
// ever signed, and the peers would find out from signature failures.
func (db *DB) SetLocalRegistry(ctx context.Context, r Registry) error {
	pub, err := json.Marshal(r.PublicJWK)
	if err != nil {
		return err
	}
	var org any
	if r.OrganizationID != "" {
		org = r.OrganizationID
	}
	_, err = db.pool.Exec(ctx, `
		INSERT INTO federation_registry
		    (uai_asn, registry_did, name, organization_id, public_jwk,
		     federation_endpoint, protocol_version, status)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,'ACTIVE')
		ON CONFLICT (only_one) DO UPDATE SET
		    name = EXCLUDED.name,
		    organization_id = EXCLUDED.organization_id,
		    public_jwk = EXCLUDED.public_jwk,
		    federation_endpoint = EXCLUDED.federation_endpoint,
		    protocol_version = EXCLUDED.protocol_version
		WHERE federation_registry.uai_asn = EXCLUDED.uai_asn`,
		int64(r.ASN), r.DID, r.Name, org, string(pub), r.Endpoint, r.ProtocolVersion)
	if err != nil {
		return classify(err)
	}
	// The WHERE above makes a renumbering a no-op rather than an error, which
	// would be the quietest possible way to lose an identity. Read it back.
	got, err := db.LocalRegistry(ctx)
	if err != nil {
		return err
	}
	if got.ASN != r.ASN {
		return fmt.Errorf("%w: this installation is already AS%d; an ASN is not something "+
			"a restart may change, because every peering and every signature names it",
			ErrConflict, got.ASN)
	}
	return nil
}

// ── peers ───────────────────────────────────────────────────────────────────

// Peer is another registry this one has been configured to exchange with.
type Peer struct {
	ID         string
	LocalASN   federation.ASN
	RemoteASN  federation.ASN
	RemoteDID  string
	Endpoint   string
	PublicJWK  uaicrypto.JWK
	Status     string
	LastError  string
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

const peerColumns = `id, local_uai_asn, remote_uai_asn, remote_registry_did,
	remote_endpoint, remote_public_jwk, status, last_error, created_at, last_seen_at`

func scanPeer(row pgx.Row) (Peer, error) {
	var p Peer
	var raw []byte
	var lastErr *string
	if err := row.Scan(&p.ID, &p.LocalASN, &p.RemoteASN, &p.RemoteDID, &p.Endpoint,
		&raw, &p.Status, &lastErr, &p.CreatedAt, &p.LastSeenAt); err != nil {
		return Peer{}, err
	}
	if lastErr != nil {
		p.LastError = *lastErr
	}
	if err := json.Unmarshal(raw, &p.PublicJWK); err != nil {
		return Peer{}, fmt.Errorf("store: peer public_jwk: %w", err)
	}
	return p, nil
}

// CreatePeer records a peering an operator configured.
//
// It starts PENDING. Configuring a peer says "this registry may send me
// federated statements"; only a completed handshake says "and I have checked
// that it holds the key I recorded for it".
func (db *DB) CreatePeer(ctx context.Context, p Peer) error {
	pub, err := json.Marshal(p.PublicJWK)
	if err != nil {
		return err
	}
	_, err = db.pool.Exec(ctx, `
		INSERT INTO federation_peers
		    (id, local_uai_asn, remote_uai_asn, remote_registry_did,
		     remote_endpoint, remote_public_jwk, status)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,'PENDING')`,
		p.ID, int64(p.LocalASN), int64(p.RemoteASN), p.RemoteDID, p.Endpoint, string(pub))
	return classify(err)
}

// PeerByASN returns the peering with one registry.
func (db *DB) PeerByASN(ctx context.Context, asn federation.ASN) (Peer, error) {
	p, err := scanPeer(db.pool.QueryRow(ctx,
		`SELECT `+peerColumns+` FROM federation_peers WHERE remote_uai_asn = $1`, int64(asn)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Peer{}, ErrNotFound
	}
	return p, classify(err)
}

// Peers lists every configured peering, newest first.
func (db *DB) Peers(ctx context.Context) ([]Peer, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT `+peerColumns+` FROM federation_peers ORDER BY created_at DESC`)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// MarkPeer records the outcome of an exchange with a peer.
func (db *DB) MarkPeer(ctx context.Context, asn federation.ASN, status, lastErr string, seen time.Time) error {
	var detail any
	if lastErr != "" {
		detail = lastErr
	}
	tag, err := db.pool.Exec(ctx, `
		UPDATE federation_peers
		   SET status = $2::peer_status, last_error = $3, last_seen_at = $4
		 WHERE remote_uai_asn = $1`, int64(asn), status, detail, seen)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── federated identities ────────────────────────────────────────────────────

// FederatedIdentity is what a peer has told this registry about one of ITS
// identities. It is not an agent of this registry and is never treated as one.
type FederatedIdentity struct {
	OriginASN       federation.ASN
	AgentDID        string
	RemoteStatus    string
	CredentialHash  string
	LastSequence    int64
	SignatureStatus string
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
}

// FederatedIdentityByDID returns what is known about one federated identity.
func (db *DB) FederatedIdentityByDID(ctx context.Context, asn federation.ASN, did string) (FederatedIdentity, error) {
	var f FederatedIdentity
	err := db.pool.QueryRow(ctx, `
		SELECT origin_uai_asn, agent_did, remote_status, credential_hash,
		       last_sequence, signature_status, first_seen_at, last_seen_at
		  FROM federated_identities WHERE origin_uai_asn = $1 AND agent_did = $2`,
		int64(asn), did).
		Scan(&f.OriginASN, &f.AgentDID, &f.RemoteStatus, &f.CredentialHash,
			&f.LastSequence, &f.SignatureStatus, &f.FirstSeenAt, &f.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return FederatedIdentity{}, ErrNotFound
	}
	return f, classify(err)
}

// RecordFederatedIdentity stores an accepted announcement.
//
// The sequence guard is in the WHERE clause as well as in the trigger and in the
// caller. Three checks for one rule is not belt and braces: the caller's check
// is a read followed by a write, and two announcements arriving at once would
// both read the old sequence and both consider themselves newer.
func (db *DB) RecordFederatedIdentity(ctx context.Context, f FederatedIdentity) error {
	tag, err := db.pool.Exec(ctx, `
		INSERT INTO federated_identities
		    (origin_uai_asn, agent_did, remote_status, credential_hash,
		     last_sequence, signature_status, last_seen_at)
		VALUES ($1,$2,$3::agent_status,$4,$5,$6::federation_signature_status, now())
		ON CONFLICT (origin_uai_asn, agent_did) DO UPDATE SET
		    remote_status = EXCLUDED.remote_status,
		    credential_hash = EXCLUDED.credential_hash,
		    last_sequence = EXCLUDED.last_sequence,
		    signature_status = EXCLUDED.signature_status,
		    last_seen_at = now()
		  WHERE federated_identities.last_sequence < EXCLUDED.last_sequence`,
		int64(f.OriginASN), f.AgentDID, f.RemoteStatus, f.CredentialHash,
		f.LastSequence, f.SignatureStatus)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s is already at a sequence at least as new as %d",
			ErrConflict, f.AgentDID, f.LastSequence)
	}
	return nil
}

// FederatedIdentities lists what peers have said, most recently seen first.
func (db *DB) FederatedIdentities(ctx context.Context) ([]FederatedIdentity, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT origin_uai_asn, agent_did, remote_status, credential_hash,
		       last_sequence, signature_status, first_seen_at, last_seen_at
		  FROM federated_identities ORDER BY last_seen_at DESC`)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []FederatedIdentity
	for rows.Next() {
		var f FederatedIdentity
		if err := rows.Scan(&f.OriginASN, &f.AgentDID, &f.RemoteStatus, &f.CredentialHash,
			&f.LastSequence, &f.SignatureStatus, &f.FirstSeenAt, &f.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
