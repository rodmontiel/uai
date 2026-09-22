package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/attest"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// Server is the UAI HTTP surface.
type Server struct {
	db       *store.DB
	resolver *StoreResolver
	scheme   string
	now      func() time.Time
}

// Option configures a Server.
type Option func(*Server)

// WithScheme sets the URL scheme used to rebuild the absolute target URI of an
// incoming request. A server-side request has a relative URL, and getting this
// wrong makes every signature verify against the wrong resource.
func WithScheme(s string) Option { return func(srv *Server) { srv.scheme = s } }

// WithClock overrides the clock, for tests.
func WithClock(f func() time.Time) Option { return func(srv *Server) { srv.now = f } }

// NewServer builds the HTTP surface.
func NewServer(db *store.DB, opts ...Option) *Server {
	s := &Server{db: db, resolver: NewStoreResolver(db), scheme: "https", now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Routes returns the mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Attestation: proof of possession AND an idempotency key. The order is
	// deliberate -- the body is captured first so the signature covers exactly
	// the bytes the handler will read, and the idempotency claim is taken only
	// after the caller has proven who they are, so an unauthenticated caller
	// cannot burn another party's keys.
	mux.Handle("POST /v1/actions/attest", Chain(
		http.HandlerFunc(s.attest),
		CaptureBody,
		RequirePoP(s.db, uaicrypto.DomainAttestation, s.scheme),
		RequireIdempotency(s.db, "POST /v1/actions/attest"),
	))

	mux.Handle("GET /v1/agents/{id}", Chain(http.HandlerFunc(s.getAgent), CaptureBody))
	mux.Handle("GET /v1/agents/{id}/events", Chain(http.HandlerFunc(s.getEvents), CaptureBody))
	mux.Handle("GET /v1/actions/{eventId}", Chain(http.HandlerFunc(s.getAction), CaptureBody))

	// Public and unauthenticated by design: verification must survive being
	// linked from a public page.
	mux.Handle("GET /v1/verify/{uaiId}", Chain(http.HandlerFunc(s.verify), CaptureBody))

	return mux
}

// decode parses a JSON body.
func decode[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	if err := json.Unmarshal(Body(r), &v); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", "The request body is not valid JSON.")
		return v, false
	}
	return v, true
}

// agentFromPoP returns the DID the verified signature belongs to.
//
// Identity comes from here and nowhere else. Reading it from the body would
// make attribution a string comparison, which is exactly what INV-002 forbids.
func agentFromPoP(r *http.Request) (string, bool) {
	p, ok := PoPParams(r)
	if !ok {
		return "", false
	}
	did, _, found := strings.Cut(p.KeyID, "#")
	return did, found
}

// parseUAIIDQuiet parses without writing a response, for the verification
// endpoint which answers 200 for every input.
func parseUAIIDQuiet(raw string) (uaiid.ID, error) { return uaiid.Parse(raw) }

// parseUAIID validates a path identifier.
func parseUAIID(w http.ResponseWriter, r *http.Request, raw string) (uaiid.ID, bool) {
	id, err := uaiid.Parse(raw)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_MALFORMED_IDENTIFIER", err.Error())
		return uaiid.ID{}, false
	}
	return id, true
}

// statusRefusal turns an agent status into a refusal, or returns false when the
// agent may act.
func statusRefusal(w http.ResponseWriter, r *http.Request, a store.Agent) bool {
	switch a.Status {
	case "REVOKED":
		WriteProblem(w, r, http.StatusForbidden, "UAI_IDENTITY_REVOKED",
			"Identity "+a.DID+" was revoked by a governance decision.",
			WithRemediation("Revocation means UAI participants no longer honor this identity's credentials."))
		return true
	case "QUARANTINED":
		WriteProblem(w, r, http.StatusForbidden, "UAI_IDENTITY_QUARANTINED",
			"Identity "+a.DID+" is under a preventive, reversible quarantine. This is not a finding of fault.")
		return true
	case "UNBOUND":
		WriteProblem(w, r, http.StatusForbidden, "UAI_IDENTITY_UNBOUND",
			"Identity "+a.DID+" is not currently participating in UAI.",
			WithRemediation("Rebind the agent before attesting further actions."))
		return true
	}
	return false
}

// attestationFromBody parses and structurally validates an attestation.
func attestationFromBody(w http.ResponseWriter, r *http.Request) (attest.Attestation, bool) {
	a, ok := decode[attest.Attestation](w, r)
	if !ok {
		return a, false
	}
	if err := a.Validate(); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_ATTESTATION_INVALID", err.Error())
		return a, false
	}
	return a, true
}
