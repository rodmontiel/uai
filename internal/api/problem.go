// Package api is the HTTP surface of the UAI services.
//
// Two rules shape everything here:
//
//   - A refusal explains itself. Every error is an RFC 9457 problem document
//     carrying the decision and policy version when a policy was involved, so a
//     caller can audit or reproduce the refusal instead of guessing.
//   - Nothing is attributed without proof. Identity comes from a verified
//     signature, never from a header or a body field a caller can write.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/keys"
	"github.com/rodmontiel/uai/pkg/pop"
)

// Problem is an RFC 9457 problem document.
type Problem struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Detail        string `json:"detail,omitempty"`
	Instance      string `json:"instance,omitempty"`
	DecisionID    string `json:"decision_id,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	CaseID        string `json:"case_id,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	TraceID       string `json:"trace_id,omitempty"`
	// ChainHead is returned with UAI_CHAIN_CONFLICT so the caller can retry
	// without a second round trip.
	ChainHead *ChainHead `json:"chain_head,omitempty"`
}

// ChainHead is the current tip of an agent's event chain.
type ChainHead struct {
	Hash     string `json:"hash"`
	Sequence int64  `json:"sequence"`
}

const problemBase = "https://uai.world/problems/"

// WriteProblem renders a problem document.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string, opts ...func(*Problem)) {
	p := Problem{
		Type:     problemBase + slug(code),
		Title:    code,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
	}
	for _, o := range opts {
		o(&p)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		slog.Error("write problem", "err", err)
	}
}

// WithRemediation adds a hint about what the caller should do next.
func WithRemediation(s string) func(*Problem) {
	return func(p *Problem) { p.Remediation = s }
}

// WithChainHead attaches the current chain head to a conflict.
func WithChainHead(h ChainHead) func(*Problem) {
	return func(p *Problem) { p.ChainHead = &h }
}

// WriteJSON renders a successful response.
func WriteJSON(w http.ResponseWriter, status int, v any) []byte {
	body, err := json.Marshal(v)
	if err != nil {
		slog.Error("marshal response", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return nil
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
	return body
}

// slug turns UAI_IDENTITY_REVOKED into identity-revoked for the problem type URI.
func slug(code string) string {
	out := make([]rune, 0, len(code))
	for _, r := range code {
		switch {
		case r == '_':
			out = append(out, '-')
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
		default:
			out = append(out, r)
		}
	}
	s := string(out)
	if len(s) > 4 && s[:4] == "uai-" {
		s = s[4:]
	}
	return s
}

// WriteStoreError maps a persistence error to the right refusal.
//
// The mapping matters: a stale chain head is an ordinary race that the caller
// retries, while an append-only violation means something tried an operation
// the protocol forbids, and the two must not look alike in a log.
func WriteStoreError(w http.ResponseWriter, r *http.Request, err error) {
	var conflict *store.ChainConflictError
	switch {
	case errors.As(err, &conflict):
		WriteProblem(w, r, http.StatusConflict, "UAI_CHAIN_CONFLICT",
			conflict.Error(),
			WithChainHead(ChainHead{Hash: conflict.Actual.Hash, Sequence: conflict.Actual.Sequence}),
			WithRemediation("Refetch the chain head, rebuild previous_event_hash and resubmit."))
	case errors.Is(err, store.ErrIdempotencyConflict):
		WriteProblem(w, r, http.StatusConflict, "UAI_IDEMPOTENCY_CONFLICT", err.Error(),
			WithRemediation("Use a new Idempotency-Key for a different request body."))
	case errors.Is(err, store.ErrNotFound):
		WriteProblem(w, r, http.StatusNotFound, "UAI_NOT_FOUND", err.Error())
	case errors.Is(err, store.ErrAppendOnly):
		WriteProblem(w, r, http.StatusForbidden, "UAI_APPEND_ONLY", err.Error(),
			WithRemediation("This record cannot be modified. Append a new one instead."))
	case errors.Is(err, store.ErrKeyNotUnique):
		WriteProblem(w, r, http.StatusConflict, "UAI_KEY_NOT_UNIQUE", err.Error(),
			WithRemediation("Generate a new key for this identity. Two identities sharing a key "+
				"make a signature unable to say which of them made the statement, and a "+
				"revocation of one would leave the other operating under the same key."))
	case errors.Is(err, store.ErrConflict):
		WriteProblem(w, r, http.StatusConflict, "UAI_CONFLICT", err.Error())
	default:
		slog.Error("unhandled store error", "err", err, "path", r.URL.Path)
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL",
			"The request could not be completed.")
	}
}

// WritePoPError maps a proof-of-possession failure to the right refusal.
//
// The cases are kept distinct because a caller must be able to tell "your
// signature is wrong" from "your identity is revoked": one is a bug to fix, the
// other is a decision to accept.
func WritePoPError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, pop.ErrNoSignature):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_REQUIRED",
			"This endpoint requires an RFC 9421 message signature. An agent identifier in a header or body is not proof of possession.",
			WithRemediation("Sign the request with the key registered for this identity."))
	case errors.Is(err, pop.ErrReplay):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_REPLAY_DETECTED", err.Error())
	case errors.Is(err, pop.ErrStale):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_TIMESTAMP_OUT_OF_WINDOW", err.Error())
	case errors.Is(err, pop.ErrTagMismatch):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_DOMAIN_MISMATCH", err.Error())
	case errors.Is(err, pop.ErrDigestMismatch):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_CONTENT_DIGEST_MISMATCH", err.Error())
	case errors.Is(err, pop.ErrComponentNotCovered), errors.Is(err, pop.ErrMissingComponent):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_COVERAGE_INSUFFICIENT", err.Error(),
			WithRemediation("Cover @method, @target-uri, content-digest, uai-agent-id and uai-nonce."))
	case errors.Is(err, keys.ErrCompromised):
		WriteProblem(w, r, http.StatusForbidden, "UAI_KEY_COMPROMISED", err.Error())
	case errors.Is(err, keys.ErrRevoked), errors.Is(err, keys.ErrExpired), errors.Is(err, keys.ErrNotYetValid):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_KEY_NOT_VALID_AT_THAT_TIME", err.Error())
	case errors.Is(err, keys.ErrKeyNotFound):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_UNKNOWN_KEY", err.Error())
	default:
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_INVALID", err.Error())
	}
}
