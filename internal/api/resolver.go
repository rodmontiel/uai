package api

import (
	"context"
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/keys"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// StoreResolver resolves verification methods from the database and applies the
// validity rule from pkg/keys.
//
// It resolves per request rather than from a cache. A cached key set would have
// to be invalidated the instant a compromise is declared, and a stale entry
// there means accepting signatures from a key already known to be stolen —
// the one kind of staleness this system cannot afford. Caching belongs behind
// an explicit invalidation path, not behind a TTL.
type StoreResolver struct {
	db *store.DB
}

// NewStoreResolver returns a resolver backed by the database.
func NewStoreResolver(db *store.DB) *StoreResolver { return &StoreResolver{db: db} }

// Resolve returns the public key for a verification method as it was valid at
// a given time.
func (r *StoreResolver) Resolve(kid string, at time.Time) (crypto.PublicKey, error) {
	did, fragment, found := strings.Cut(kid, "#")
	if !found || fragment == "" {
		return nil, fmt.Errorf("%w: %q is not a DID URL with a fragment", keys.ErrKeyNotFound, kid)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	agent, err := r.db.AgentByDID(ctx, did)
	if err != nil {
		return nil, fmt.Errorf("%w: no identity for %s", keys.ErrKeyNotFound, did)
	}
	rows, err := r.db.AgentKeys(ctx, agent.ID)
	if err != nil {
		return nil, err
	}
	return historyFor(did, rows)(kid, at)
}

// ResolveOwner is the owner-side counterpart.
//
// Owners sign the ownership half of a registration proof and, for a lost agent,
// the unbind request (§9.2), so their keys need exactly the same "valid at event
// time" rule: a signature made before a key was revoked stays verifiable, and
// one made after does not.
func (r *StoreResolver) ResolveOwner(ctx context.Context, owner store.Owner, kid string, at time.Time) (crypto.PublicKey, error) {
	did, fragment, found := strings.Cut(kid, "#")
	if !found || fragment == "" {
		return nil, fmt.Errorf("%w: %q is not a DID URL with a fragment", keys.ErrKeyNotFound, kid)
	}
	// The key identifier must name THIS owner. The caller chooses the kid, so
	// without this check the history would be built from one owner's key rows
	// while being labelled with whatever DID the caller wrote — and a signature
	// by any owner would then verify as the owner being claimed.
	if did != owner.DID {
		return nil, fmt.Errorf("%w: key %s does not belong to %s", keys.ErrKeyNotFound, kid, owner.DID)
	}
	rows, err := r.db.OwnerKeys(ctx, owner.ID)
	if err != nil {
		return nil, err
	}
	return historyFor(owner.DID, rows)(kid, at)
}

// historyFor turns stored key rows into the validity-aware resolver of pkg/keys.
func historyFor(did string, rows []store.KeyRecord) func(kid string, at time.Time) (crypto.PublicKey, error) {
	history := keys.NewHistory(did)
	for _, row := range rows {
		pub, err := uaicrypto.PublicFromJWKBytes(row.PublicJWK)
		if err != nil {
			// A malformed stored key is skipped rather than failing the whole
			// resolution: one bad row must not make every other key in the
			// history unusable.
			continue
		}
		k := keys.Key{
			KID: did + "#" + row.KeyID, Public: pub,
			Protection: keys.Protection(row.Protection), ValidFrom: row.ValidFrom,
		}
		if row.ValidUntil != nil {
			k.ValidUntil = *row.ValidUntil
		}
		if row.RevokedAt != nil {
			k.RevokedAt = *row.RevokedAt
		}
		if row.Compromised != nil {
			k.CompromiseDeclaredAt = *row.Compromised
		}
		if row.LogIndex != nil {
			k.LogIndex = *row.LogIndex
		}
		if err := history.Add(k); err != nil {
			continue
		}
	}
	return history.Resolver()
}
