package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

type ctxKey int

const (
	ctxBody ctxKey = iota
	ctxPoP
	ctxIdempotencyKey
)

// maxBody caps a request body. The signature covers a content digest, so an
// unbounded body would let an unauthenticated caller exhaust memory before the
// signature is ever checked.
const maxBody = 1 << 20 // 1 MiB

// Body returns the request body captured by the middleware.
//
// Handlers read it from the context rather than from r.Body because the
// signature is verified over the exact bytes, and re-reading a consumed stream
// would give a handler something different from what was verified.
func Body(r *http.Request) []byte {
	b, _ := r.Context().Value(ctxBody).([]byte)
	return b
}

// PoPParams returns the verified proof-of-possession parameters.
func PoPParams(r *http.Request) (pop.Params, bool) {
	p, ok := r.Context().Value(ctxPoP).(pop.Params)
	return p, ok
}

// IdempotencyKey returns the key claimed for this request.
func IdempotencyKey(r *http.Request) string {
	k, _ := r.Context().Value(ctxIdempotencyKey).(string)
	return k
}

// CaptureBody reads and caps the body, making it available to later middleware
// and to the handler.
func CaptureBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxBody, []byte{})))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		_ = r.Body.Close()
		if err != nil {
			WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", "The request body could not be read.")
			return
		}
		if len(body) > maxBody {
			WriteProblem(w, r, http.StatusRequestEntityTooLarge, "UAI_BODY_TOO_LARGE",
				"The request body exceeds the 1 MiB limit.")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxBody, body)))
	})
}

// RequirePoP verifies an RFC 9421 message signature in the given domain.
//
// Identity for everything downstream comes from here. A handler must never read
// an agent identifier from the body: the body is written by the caller, and
// trusting it would reduce attribution to a string comparison (INV-002).
func RequirePoP(db *store.DB, domain uaicrypto.Domain, scheme string) func(http.Handler) http.Handler {
	resolver := NewStoreResolver(db)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			params, err := pop.VerifyRequest(r, Body(r), pop.VerifyOptions{
				Domain:  domain,
				Resolve: resolver.Resolve,
				Nonces:  db.Nonces(),
				Scheme:  scheme,
			})
			if err != nil {
				WritePoPError(w, r, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxPoP, params)))
		})
	}
}

// recorder captures a handler's response so it can be stored for replay.
type recorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (rec *recorder) WriteHeader(status int) {
	rec.status = status
	rec.ResponseWriter.WriteHeader(status)
}

func (rec *recorder) Write(b []byte) (int, error) {
	rec.body.Write(b)
	return rec.ResponseWriter.Write(b)
}

// RequireIdempotency enforces the Idempotency-Key header and replays a
// completed response for a repeated key.
//
// Only successful responses are recorded. Replaying a failure would strand a
// caller on a transient error forever: they would retry with the same key, as
// the header invites, and receive the stored failure instead of a fresh attempt.
func RequireIdempotency(db *store.DB, endpoint string) func(http.Handler) http.Handler {
	const ttl = 24 * time.Hour
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("Idempotency-Key")
			if len(key) < 8 {
				WriteProblem(w, r, http.StatusBadRequest, "UAI_IDEMPOTENCY_KEY_REQUIRED",
					"This endpoint requires an Idempotency-Key header of at least 8 characters.",
					WithRemediation("Generate a unique key per logical request and reuse it when retrying."))
				return
			}
			// The column carries the sha256_digest domain, which requires the
			// "sha256:" wire prefix. Storing bare hex fails the constraint.
			sum := sha256.Sum256(Body(r))
			requestHash := "sha256:" + hex.EncodeToString(sum[:])
			prior, replay, err := db.BeginIdempotent(r.Context(), key, endpoint, requestHash, ttl)
			if err != nil {
				WriteStoreError(w, r, err)
				return
			}
			if replay {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Idempotency-Replayed", "true")
				w.WriteHeader(prior.Status)
				_, _ = w.Write(prior.Body)
				return
			}

			rec := &recorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), ctxIdempotencyKey, key)))

			if rec.status >= 200 && rec.status < 300 {
				if err := db.CompleteIdempotent(r.Context(), key, endpoint, rec.status, rec.body.Bytes()); err != nil {
					// The request already succeeded; failing to record it only
					// costs idempotency on a retry, so it is logged, not surfaced.
					problemLog(r, "record idempotent response", err)
				}
				return
			}
			if err := db.ReleaseIdempotent(r.Context(), key, endpoint); err != nil {
				problemLog(r, "release idempotency claim", err)
			}
		})
	}
}

// Chain applies middleware in the order given, outermost first.
func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// ErrBodyNotJSON is returned when a body cannot be decoded.
var ErrBodyNotJSON = errors.New("api: request body is not valid JSON")
