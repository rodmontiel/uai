package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/keys"
)

// jwk is the subset of a JSON Web Key UAI stores.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWK converts a stored public key into a crypto.PublicKey.
func parseJWK(raw json.RawMessage) (crypto.PublicKey, error) {
	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("api: parse jwk: %w", err)
	}
	decode := func(s string) ([]byte, error) {
		// Keys are stored base64url without padding, per RFC 7517.
		return base64.RawURLEncoding.DecodeString(s)
	}
	switch {
	case k.Kty == "OKP" && k.Crv == "Ed25519":
		x, err := decode(k.X)
		if err != nil {
			return nil, fmt.Errorf("api: jwk x: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("api: ed25519 key is %d bytes, want %d", len(x), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(x), nil
	case k.Kty == "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("api: unsupported curve %q", k.Crv)
		}
		xb, err := decode(k.X)
		if err != nil {
			return nil, fmt.Errorf("api: jwk x: %w", err)
		}
		yb, err := decode(k.Y)
		if err != nil {
			return nil, fmt.Errorf("api: jwk y: %w", err)
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("api: jwk point is not on %s", k.Crv)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("api: unsupported key type %q/%q", k.Kty, k.Crv)
	}
}

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

	history := keys.NewHistory(did)
	for _, row := range rows {
		pub, err := parseJWK(row.PublicJWK)
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
	return history.Resolver()(kid, at)
}
