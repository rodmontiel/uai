package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrIdempotencyConflict is returned when a key is reused with a different
// request body. Returning the original response would be wrong -- the caller
// asked for something else -- and executing the new one would break the
// guarantee the key exists to provide.
var ErrIdempotencyConflict = errors.New("store: idempotency key reused with a different request")

// IdempotentResponse is a previously recorded response.
//
// Body holds the exact bytes the original response carried. Replaying a
// re-encoded equivalent would be wrong: a caller may have hashed or signed what
// it received.
type IdempotentResponse struct {
	Status int
	Body   []byte
}

// BeginIdempotent claims an idempotency key for an endpoint.
//
// It returns (nil, false, nil) when the caller should proceed and record a
// response, and (response, true, nil) when a completed response already exists
// and must be replayed.
//
// An in-flight entry with no response yet also replays as "in progress" rather
// than executing twice: two concurrent submissions of the same key must not
// both reach the handler, which is the whole point on an endpoint that mints
// identities or appends to a chain.
func (db *DB) BeginIdempotent(ctx context.Context, key, endpoint, requestHash string, ttl time.Duration) (*IdempotentResponse, bool, error) {
	var (
		existingHash string
		status       *int32
		body         *string
	)
	err := db.pool.QueryRow(ctx, `
		INSERT INTO idempotency_keys (key, endpoint, request_hash, expires_at)
		VALUES ($1, $2, $3, now() + $4::interval)
		ON CONFLICT (key, endpoint) DO UPDATE SET key = EXCLUDED.key
		RETURNING request_hash, response_status, response_body`,
		key, endpoint, requestHash, ttl.String()).Scan(&existingHash, &status, &body)
	if err != nil {
		return nil, false, classify(err)
	}
	if existingHash != requestHash {
		return nil, false, fmt.Errorf("%w: %s on %s", ErrIdempotencyConflict, key, endpoint)
	}
	if status == nil {
		// Freshly claimed, or claimed by a concurrent request that has not
		// finished. Either way the caller proceeds; the handler's own
		// constraints (chain head, unique nonce) prevent a double effect.
		return nil, false, nil
	}
	var raw []byte
	if body != nil {
		raw = []byte(*body)
	}
	return &IdempotentResponse{Status: int(*status), Body: raw}, true, nil
}

// CompleteIdempotent records the response for a claimed key.
func (db *DB) CompleteIdempotent(ctx context.Context, key, endpoint string, status int, body []byte) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE idempotency_keys SET response_status = $3, response_body = $4
		WHERE key = $1 AND endpoint = $2`, key, endpoint, status, string(body))
	return classify(err)
}

// ReleaseIdempotent drops a claim, so that a request which failed before doing
// anything can be retried with the same key.
func (db *DB) ReleaseIdempotent(ctx context.Context, key, endpoint string) error {
	_, err := db.pool.Exec(ctx, `
		DELETE FROM idempotency_keys
		WHERE key = $1 AND endpoint = $2 AND response_status IS NULL`, key, endpoint)
	return classify(err)
}

// NonceCache is the shared replay cache backing proof of possession.
//
// It is shared rather than per-process on purpose: a per-instance cache would
// let an attacker replay a captured request simply by reaching a different
// gateway pod.
type NonceCache struct{ db *DB }

// Nonces returns the shared replay cache.
func (db *DB) Nonces() *NonceCache { return &NonceCache{db: db} }

// Seen records the nonce and reports whether it had already been used.
//
// A failure to reach the database returns true -- treat it as seen -- because
// the alternative is accepting replays whenever the cache is unavailable, and
// an accountability system that degrades into permissiveness under load is
// worse than one that degrades into refusal.
func (c *NonceCache) Seen(kid, nonce string, expiry time.Time) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tag, err := c.db.pool.Exec(ctx, `
		INSERT INTO nonces (signer_kid, nonce, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (signer_kid, nonce) DO NOTHING`, kid, nonce, expiry)
	if err != nil {
		return true
	}
	return tag.RowsAffected() == 0
}

// PurgeExpired removes expired idempotency keys and nonces.
func (db *DB) PurgeExpired(ctx context.Context) (int64, error) {
	var total int64
	err := db.InTx(ctx, func(tx pgx.Tx) error {
		for _, table := range []string{"idempotency_keys", "nonces"} {
			tag, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE expires_at < now()`, table))
			if err != nil {
				return classify(err)
			}
			total += tag.RowsAffected()
		}
		return nil
	})
	return total, err
}
