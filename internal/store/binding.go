package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Binding errors.
var (
	// ErrChallengeInvalid covers unknown, expired and already-used challenges.
	// They are one error on purpose: telling them apart would let a caller probe
	// which challenges exist.
	ErrChallengeInvalid = errors.New("store: binding challenge is not usable")
	// ErrNoUnbind means a rebind was attempted with nothing to continue from.
	ErrNoUnbind = errors.New("store: no unbind to continue from")
)

// BindingChallenge is a server-issued, single-use value for one operation.
type BindingChallenge struct {
	ID        string
	AgentID   string
	Operation string
	Challenge string
	Audience  string
	ExpiresAt time.Time
}

// Binding is a recorded BIND, UNBIND or REBIND event.
type Binding struct {
	ID                  string
	AgentID             string
	Operation           string
	SpiffeID            string
	SVIDCertHash        string
	ImageDigest         string
	Audience            string
	Reason              string
	Signature           string
	SignerKID           string
	ContinuityProof     string
	ContinuitySignerKID string
	RuntimeIdentityID   string
	OccurredAt          time.Time
}

// RuntimeIdentity is one workload instance of an agent.
type RuntimeIdentity struct {
	ID          string
	AgentID     string
	SpiffeID    string
	CertHash    string
	ImageDigest string
	Attestor    string
	ExpiresAt   time.Time
}

// IssueBindingChallenge stores a fresh challenge.
func (db *DB) IssueBindingChallenge(ctx context.Context, c BindingChallenge) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO binding_challenges (id, agent_id, operation, challenge, audience, expires_at)
		VALUES ($1,$2,$3::binding_operation,$4,$5,$6)`,
		c.ID, c.AgentID, c.Operation, c.Challenge, c.Audience, c.ExpiresAt)
	return classify(err)
}

// lookupChallenge finds an unconsumed, unexpired challenge under a row lock.
func lookupChallenge(ctx context.Context, tx pgx.Tx, agentID, operation, challenge string,
	now time.Time) (BindingChallenge, error) {
	var c BindingChallenge
	var consumedAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT id, agent_id, operation::text, challenge, audience, expires_at, consumed_at
		  FROM binding_challenges
		 WHERE agent_id = $1 AND operation = $2::binding_operation AND challenge = $3
		 FOR UPDATE`, agentID, operation, challenge).
		Scan(&c.ID, &c.AgentID, &c.Operation, &c.Challenge, &c.Audience, &c.ExpiresAt, &consumedAt)
	if err != nil {
		if errors.Is(classify(err), ErrNotFound) {
			return BindingChallenge{}, ErrChallengeInvalid
		}
		return BindingChallenge{}, classify(err)
	}
	// Checked here and not only by the trigger. The trigger fires on the
	// consuming UPDATE, which happens after the runtime identity is inserted --
	// so a replay would fail on a unique index instead, and report a collision
	// where the real answer is "that challenge was already used".
	if consumedAt != nil {
		return BindingChallenge{}, fmt.Errorf("%w: already used at %s", ErrChallengeInvalid,
			consumedAt.UTC().Format(time.RFC3339))
	}
	if !now.Before(c.ExpiresAt) {
		return BindingChallenge{}, fmt.Errorf("%w: expired at %s", ErrChallengeInvalid,
			c.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return c, nil
}

// RecordBinding consumes the challenge, appends the chain event, stores the
// binding and moves the agent to its new state -- all or nothing.
//
// Atomicity is not a nicety here. A binding recorded without its chain event
// would be a state change invisible to anyone walking the history, and a state
// change without the binding would be a transition nobody signed.
func (db *DB) RecordBinding(ctx context.Context, b Binding, challenge string, eventHash string,
	newStatus string, runtime *RuntimeIdentity, now time.Time) (ChainEvent, error) {

	var out ChainEvent
	err := db.InTx(ctx, func(tx pgx.Tx) error {
		ch, err := lookupChallenge(ctx, tx, b.AgentID, b.Operation, challenge, now)
		if err != nil {
			return err
		}
		head, err := chainHead(ctx, tx, b.AgentID)
		if err != nil {
			return err
		}
		kind := map[string]string{
			"BIND_AGENT": KindBind, "UNBIND_AGENT": KindUnbind, "REBIND_AGENT": KindRebind,
		}[b.Operation]
		ev := ChainEvent{
			ID: b.ID, AgentID: b.AgentID, Sequence: head.Sequence + 1, Kind: kind,
			PreviousEventHash: head.Hash, EventHash: eventHash, OccurredAt: now,
		}
		if err := appendChainEvent(ctx, tx, ev, head); err != nil {
			return err
		}

		var runtimeID any
		if runtime != nil {
			_, err = tx.Exec(ctx, `
				INSERT INTO runtime_identities (id, agent_id, spiffe_id, cert_hash, image_digest,
				                                attestor, bound_at, expires_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				runtime.ID, runtime.AgentID, runtime.SpiffeID, runtime.CertHash,
				nullable(runtime.ImageDigest), nullable(runtime.Attestor), now, runtime.ExpiresAt)
			if err != nil {
				return classify(err)
			}
			runtimeID = runtime.ID
			b.RuntimeIdentityID = runtime.ID
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO agent_bindings (id, agent_id, operation, continuity_proof,
			                            continuity_signer_kid, spiffe_id, svid_cert_hash,
			                            image_digest, audience, reason, signature, signer_kid,
			                            runtime_identity_id, occurred_at)
			VALUES ($1,$2,$3::binding_operation,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			b.ID, b.AgentID, b.Operation, nullable(b.ContinuityProof),
			nullable(b.ContinuitySignerKID), nullable(b.SpiffeID), nullable(b.SVIDCertHash),
			nullable(b.ImageDigest), nullable(b.Audience), nullable(b.Reason),
			b.Signature, b.SignerKID, runtimeID, now)
		if err != nil {
			return classify(err)
		}

		// Release the runtime instances on unbind. §9.2 requires SVID entries to
		// go; keeping them would leave a workload able to present a runtime
		// identity for an agent that is no longer participating.
		if b.Operation == "UNBIND_AGENT" {
			if _, err := tx.Exec(ctx,
				`UPDATE runtime_identities SET released_at = $2
				  WHERE agent_id = $1 AND released_at IS NULL`, b.AgentID, now); err != nil {
				return classify(err)
			}
		}

		if _, err := tx.Exec(ctx, `
			UPDATE binding_challenges SET consumed_at = $2, consumed_by = $3 WHERE id = $1`,
			ch.ID, now, b.ID); err != nil {
			return classify(err)
		}

		if _, err := tx.Exec(ctx, `
			UPDATE agents SET status = $2::agent_status, updated_at = now() WHERE id = $1`,
			b.AgentID, newStatus); err != nil {
			return classify(err)
		}
		out = ev
		return nil
	})
	return out, err
}

// LastUnbind returns when an agent last left, and the chain head at that
// moment.
//
// A rebind has to prove continuity with the identity as it stood at THAT
// instant (§9.3), so both values come from the same row rather than from
// "now" or from the current head.
func (db *DB) LastUnbind(ctx context.Context, agentID string) (at time.Time, previousEventHash string, err error) {
	err = db.pool.QueryRow(ctx, `
		SELECT c.occurred_at, c.previous_event_hash
		  FROM agent_bindings b JOIN agent_chain_events c ON c.id = b.id
		 WHERE b.agent_id = $1 AND b.operation = 'UNBIND_AGENT'
		 ORDER BY c.sequence DESC LIMIT 1`, agentID).Scan(&at, &previousEventHash)
	if err != nil {
		if errors.Is(classify(err), ErrNotFound) {
			return time.Time{}, "", fmt.Errorf("%w: agent %s", ErrNoUnbind, agentID)
		}
		return time.Time{}, "", classify(err)
	}
	return at, previousEventHash, nil
}

// ActiveRuntimes returns an agent's unreleased runtime instances.
func (db *DB) ActiveRuntimes(ctx context.Context, agentID string) ([]RuntimeIdentity, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, agent_id, spiffe_id, cert_hash, image_digest, expires_at
		  FROM runtime_identities
		 WHERE agent_id = $1 AND released_at IS NULL ORDER BY bound_at`, agentID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var out []RuntimeIdentity
	for rows.Next() {
		var r RuntimeIdentity
		var image *string
		if err := rows.Scan(&r.ID, &r.AgentID, &r.SpiffeID, &r.CertHash, &image, &r.ExpiresAt); err != nil {
			return nil, classify(err)
		}
		r.ImageDigest = deref(image)
		out = append(out, r)
	}
	return out, classify(rows.Err())
}

// PurgeExpiredChallenges removes binding challenges nobody answered.
func (db *DB) PurgeExpiredChallenges(ctx context.Context, before time.Time) (int64, error) {
	tag, err := db.pool.Exec(ctx,
		`DELETE FROM binding_challenges WHERE consumed_at IS NULL AND expires_at < $1`, before)
	if err != nil {
		return 0, classify(err)
	}
	return tag.RowsAffected(), nil
}

// AssuranceInputs is the evidence §6.8 weighs, as the registry holds it.
//
// Raw strings rather than a decided level: what these mean is policy, and the
// store's job is to say what is recorded, not what it is worth. The API layer
// turns them into a level with pkg/assurance.
type AssuranceInputs struct {
	// KeyProtections of every currently-valid key, unordered.
	//
	// A list rather than a decided maximum: neither the enum's declaration
	// order nor its alphabet is a strength order -- max() over it would rank
	// TPM2 above HSM -- and which protection is stronger is a policy question
	// that belongs in pkg/assurance, in one place.
	KeyProtections []string
	// Attestor that vouched for the live runtime, "self-declared" when the
	// agent described its own, and "" when nothing is bound.
	Attestor string
	// ImageDigest recorded with that runtime, if any.
	ImageDigest string
	// OwnerVerification is how the owner was established. Constant today:
	// nothing in the schema records domain control or a verified organization
	// credential, which is exactly why every identity is AL0
	// (docs/protocol/13-threat-model.md section 20.5).
	OwnerVerification string
}

// AssuranceEvidence gathers what is known about one agent.
func (db *DB) AssuranceEvidence(ctx context.Context, agentID string, now time.Time) (AssuranceInputs, error) {
	in := AssuranceInputs{OwnerVerification: "SELF_ASSERTED"}

	// Every key that is valid right now. An identity holding an HSM key is
	// HSM-protected even if it also holds a software key it has not retired,
	// and the caller decides that.
	rows, err := db.pool.Query(ctx, `
		SELECT protection::text
		  FROM agent_keys
		 WHERE agent_id = $1
		   AND valid_from <= $2
		   AND (valid_until IS NULL OR valid_until > $2)
		   AND revoked_at IS NULL
		   AND compromise_declared_at IS NULL`, agentID, now)
	if err != nil {
		return in, classify(err)
	}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return in, classify(err)
		}
		in.KeyProtections = append(in.KeyProtections, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, classify(err)
	}

	// The live runtime binding. Released or expired rows are not evidence:
	// an SVID the attestor has stopped vouching for says nothing about now.
	var attestor, image *string
	err = db.pool.QueryRow(ctx, `
		SELECT attestor, image_digest
		  FROM runtime_identities
		 WHERE agent_id = $1 AND released_at IS NULL AND expires_at > $2
		 ORDER BY bound_at DESC
		 LIMIT 1`, agentID, now).Scan(&attestor, &image)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return in, nil
	case err != nil:
		return in, classify(err)
	}
	if attestor != nil {
		in.Attestor = *attestor
	}
	if image != nil {
		in.ImageDigest = *image
	}
	return in, nil
}
