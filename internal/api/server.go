package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/pdp"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/internal/translog"
	"github.com/rodmontiel/uai/pkg/attest"
	"github.com/rodmontiel/uai/pkg/spiffe"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// DefaultPolicyVersion is the GASC bundle this build stamps on new identities
// until the policy service ships (Phase 6).
const DefaultPolicyVersion = "GASC-2027.4"

// DefaultAudience is the registry identifier carried in binding statements.
const DefaultAudience = "uai-agent-registry"

// Governance defaults. The relying party is where delegates vote; the minimum
// country count is the jurisdictional spread a revocation needs, and the real
// value comes from the signed bundle (§16) rather than from this constant.
const (
	DefaultGovernanceRPID   = "governance.uai.world"
	DefaultGovernanceOrigin = "https://governance.uai.world"
	DefaultMinCountries     = 3
)

// Server is the UAI HTTP surface.
type Server struct {
	db       *store.DB
	resolver *StoreResolver
	scheme   string
	// policyVersion is stamped on every identity minted under it. INV-009 is
	// the same idea one layer down: a record that cannot say which rules
	// produced it cannot be audited later.
	policyVersion string
	// issuer signs the credentials UAI issues. There is no default and no
	// fallback: a server that quietly issued unsigned credentials, or signed
	// them with a key generated at boot, would hand out documents that stop
	// verifying the next time it restarts.
	issuer    uaicrypto.Signer
	issuerDID string
	// audience is this registry's identifier inside a signed binding statement
	// (§9.1). It is there so a statement produced for one registry cannot be
	// presented to another: without it, a federated deployment would honour a
	// binding intended for a different operator.
	audience string
	// bundle is the loaded, verified policy. Nil means no policy, which means
	// no request can be authorized: §12.4 fails closed on the guardrail, and a
	// PDP that permitted anything while it had no rules would be worse than
	// one that was simply down.
	bundle *pdp.Bundle
	// spiffe is the trust bundle runtime attestation is checked against, or
	// nil when this registry records self-declared runtimes (§6.8).
	spiffe *spiffe.Bundle
	// governanceOrigin and governanceRPID are what a delegate's authenticator
	// must have scoped its assertion to. They are configuration rather than
	// constants because a deployment runs its governance UI somewhere: an
	// assertion produced for another origin is refused, and getting these wrong
	// refuses every genuine vote rather than accepting a forged one.
	governanceOrigin string
	governanceRPID   string
	// minCountries is the jurisdictional spread a revocation needs, read from
	// the policy bundle. M-of-N alone is satisfiable inside one jurisdiction,
	// and a revocation decided there is a national decision wearing an
	// international label.
	minCountries int
	// revoker publishes a revocation on the consortium chain. Nil means the
	// chain step is skipped and the response says so: §18.5 is explicit that a
	// ledger outage must not block a decision the delegates already made.
	revoker Revoker
	chainID int64
	// translog registers signed statements and issues receipts. Nil means the
	// service runs without transparency: attestations still work and say so in
	// their response, because a log outage must not force unattested execution.
	translog *translog.Log
	now      func() time.Time
}

// Option configures a Server.
type Option func(*Server)

// WithScheme sets the URL scheme used to rebuild the absolute target URI of an
// incoming request. A server-side request has a relative URL, and getting this
// wrong makes every signature verify against the wrong resource.
func WithScheme(s string) Option { return func(srv *Server) { srv.scheme = s } }

// WithPolicyVersion sets the GASC bundle version recorded on new identities.
func WithPolicyVersion(v string) Option { return func(srv *Server) { srv.policyVersion = v } }

// WithAudience sets the registry identifier that binding statements must name.
func WithAudience(a string) Option { return func(srv *Server) { srv.audience = a } }

// WithTransparency attaches the transparency log.
func WithTransparency(l *translog.Log) Option { return func(srv *Server) { srv.translog = l } }

// WithBundle installs the verified policy bundle the PDP evaluates against.
func WithBundle(b *pdp.Bundle) Option { return func(srv *Server) { srv.bundle = b } }

// WithIssuer sets the credential issuer identity and its signing key.
func WithIssuer(did string, signer uaicrypto.Signer) Option {
	return func(srv *Server) { srv.issuerDID, srv.issuer = did, signer }
}

// WithGovernance sets the WebAuthn relying party a delegate's vote must name.
func WithGovernance(rpID, origin string, minCountries int) Option {
	return func(srv *Server) {
		srv.governanceRPID, srv.governanceOrigin = rpID, origin
		if minCountries > 0 {
			srv.minCountries = minCountries
		}
	}
}

// WithRevoker attaches the on-chain revocation path.
func WithRevoker(r Revoker, chainID int64) Option {
	return func(srv *Server) { srv.revoker, srv.chainID = r, chainID }
}

// WithClock overrides the clock, for tests.
func WithClock(f func() time.Time) Option { return func(srv *Server) { srv.now = f } }

// WithSPIFFE makes runtime attestation mandatory for binding.
//
// Without a bundle the registry records what the agent says about where it
// runs, marks it "self-declared", and the runtime dimension of §6.8 stays at
// zero. With one, a bind must present an X509-SVID this bundle verifies, and
// the runtime is read off the certificate.
//
// It is an option rather than a requirement because a registry that refused to
// start without SPIRE would stop `make dev` working, and the assurance level
// already reports the difference honestly -- which is what assurance levels
// are for.
func WithSPIFFE(b *spiffe.Bundle) Option { return func(srv *Server) { srv.spiffe = b } }

// NewServer builds the HTTP surface.
func NewServer(db *store.DB, opts ...Option) *Server {
	s := &Server{db: db, resolver: NewStoreResolver(db), scheme: "https",
		policyVersion: DefaultPolicyVersion, audience: DefaultAudience, now: time.Now,
		governanceRPID: DefaultGovernanceRPID, governanceOrigin: DefaultGovernanceOrigin,
		minCountries: DefaultMinCountries}
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

	// Registration is the one write path without proof of possession, because
	// establishing the agent's key is what it does. It is still behind an
	// idempotency key: §8.1 requires registration to be safely retryable, and a
	// retry that opened a second registration would issue a second pair of
	// challenges for one logical request.
	mux.Handle("POST /v1/agents", Chain(
		http.HandlerFunc(s.registerAgent),
		CaptureBody,
		RequireIdempotency(s.db, "POST /v1/agents"),
	))
	mux.Handle("POST /v1/agents/{id}/prove", Chain(
		http.HandlerFunc(s.prove),
		CaptureBody,
		RequireIdempotency(s.db, "POST /v1/agents/{id}/prove"),
	))

	mux.Handle("GET /v1/agents/{id}", Chain(http.HandlerFunc(s.getAgent), CaptureBody))
	mux.Handle("GET /v1/agents/{id}/events", Chain(http.HandlerFunc(s.getEvents), CaptureBody))
	mux.Handle("GET /v1/agents/{id}/credentials", Chain(http.HandlerFunc(s.getCredentials), CaptureBody))

	// Binding: proof of possession first, then idempotency. §9.5 requires all
	// three operations to be safely retryable, and the challenge exchange makes
	// that matter -- a retry that issued a second challenge would leave the
	// first one dangling until it expired.
	for path, handler := range map[string]http.HandlerFunc{
		"POST /v1/agents/{id}/bind":   s.bind,
		"POST /v1/agents/{id}/unbind": s.unbind,
		"POST /v1/agents/{id}/rebind": s.rebind,
	} {
		mux.Handle(path, Chain(handler, CaptureBody,
			RequirePoP(s.db, uaicrypto.DomainChallenge, s.scheme),
			RequireIdempotency(s.db, path)))
	}
	mux.Handle("GET /v1/actions/{eventId}", Chain(http.HandlerFunc(s.getAction), CaptureBody))

	// The PDP. §22.6 exempts it from idempotency on purpose: two evaluations of
	// the same request may legitimately differ, because the policy, the agent's
	// status or its grants can change between them, and replaying a stale
	// decision would hide exactly that.
	mux.Handle("POST /v1/policy/evaluate", Chain(
		http.HandlerFunc(s.evaluate),
		CaptureBody,
		RequirePoP(s.db, uaicrypto.DomainDecision, s.scheme),
	))

	// Passports (§11). The request is signed by the agent, and that is not a
	// self-grant: a passport scopes WHERE a capability may be used, never WHAT
	// the agent may do, and the handler refuses any capability the owner has
	// not already granted. The decision about WHERE is the PDP's.
	mux.Handle("POST /v1/passports/request", Chain(
		http.HandlerFunc(s.requestPassport),
		CaptureBody,
		RequirePoP(s.db, uaicrypto.DomainPassport, s.scheme),
		RequireIdempotency(s.db, "POST /v1/passports/request"),
	))
	// The check is public for the same reason /verify is: it answers a question
	// a relying party asks about an agent it is considering dealing with, and an
	// answer only that agent could obtain would be useless to the party who
	// needs it.
	mux.Handle("GET /v1/passports/check", Chain(http.HandlerFunc(s.checkPassport), CaptureBody))
	mux.Handle("GET /v1/passports/{id}", Chain(http.HandlerFunc(s.getPassport), CaptureBody))

	// Asking for a capability. Behind proof of possession, and behind nothing
	// else: §22.9's rule that no tool grants capabilities is kept by there
	// being no route here that writes a grant, not by this handler declining
	// to. The database refuses one signed by the agent itself as well.
	mux.Handle("POST /v1/capability-requests", Chain(
		http.HandlerFunc(s.requestCapability),
		CaptureBody,
		RequirePoP(s.db, uaicrypto.DomainCapabilityRequest, s.scheme),
		RequireIdempotency(s.db, "POST /v1/capability-requests"),
	))
	mux.Handle("GET /v1/agents/{id}/capability-requests",
		Chain(http.HandlerFunc(s.listCapabilityRequests), CaptureBody))

	// Reporting harm. Signed, never anonymous: §14 treats an accusation as a
	// consequential act, and an anonymous path here would turn the quarantine
	// machinery into a free denial-of-service tool against any identity (T-24).
	mux.Handle("POST /v1/suspicions", Chain(
		http.HandlerFunc(s.fileSuspicion),
		CaptureBody,
		RequirePoP(s.db, uaicrypto.DomainSuspicion, s.scheme),
		RequireIdempotency(s.db, "POST /v1/suspicions"),
	))

	// Governance (§16). A vote is not behind proof of possession by a UAI key:
	// the WebAuthn assertion IS the authentication, and it authenticates
	// something a software credential cannot — that a human touched a token.
	// Putting a second software credential in front of it would reintroduce
	// exactly what the hardware requirement removes.
	// Behind an idempotency key: a delegate whose submission times out retries,
	// and without one the retry meets the "one live vote per delegate" index and
	// gets a conflict instead of the answer their first attempt already earned.
	mux.Handle("POST /v1/governance/proposals/{id}/vote", Chain(
		http.HandlerFunc(s.castVote), CaptureBody,
		RequireIdempotency(s.db, "POST /v1/governance/proposals/{id}/vote")))
	mux.Handle("GET /v1/governance/proposals/{id}",
		Chain(http.HandlerFunc(s.getProposal), CaptureBody))
	mux.Handle("GET /v1/revocations/{decisionId}",
		Chain(http.HandlerFunc(s.getRevocationDecision), CaptureBody))

	// The administrator's entire write surface (§16.3). One route, one input:
	// a decision id. Every consequence is already fixed by the governance
	// proof, which is recomputed here from the signed assertions.
	mux.Handle("POST /v1/revocations/{decisionId}/execute", Chain(
		http.HandlerFunc(s.executeRevocation),
		CaptureBody,
		RequirePoP(s.db, uaicrypto.DomainRevocation, s.scheme),
		RequireIdempotency(s.db, "POST /v1/revocations/{decisionId}/execute"),
	))

	// Public, read-only surfaces. Unauthenticated for the same reason /verify
	// is: an accountability record nobody can read is not accountability.
	mux.Handle("GET /v1/quarantines", Chain(http.HandlerFunc(s.listQuarantines), CaptureBody))
	mux.Handle("GET /v1/cases/{id}", Chain(http.HandlerFunc(s.getCase), CaptureBody))
	mux.Handle("GET /v1/governance/proposals", Chain(http.HandlerFunc(s.listProposals), CaptureBody))

	// What an independent verifier needs, and nothing it has to trust us for
	// (§5.1). The DID document resolves the key ids an attestation names; the
	// checkpoint and the anchors let a receipt be checked without asking the log
	// whether its own receipt is genuine.
	mux.Handle("GET /v1/agents/{id}/did.json", Chain(http.HandlerFunc(s.didDocument), CaptureBody))
	mux.Handle("GET /v1/log/checkpoint", Chain(http.HandlerFunc(s.latestCheckpoint), CaptureBody))
	mux.Handle("GET /v1/trust-anchors", Chain(http.HandlerFunc(s.trustAnchors), CaptureBody))

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

// requireActive refuses an agent that may not attest actions.
//
// §6.10 puts actions in ACTIVE, and ACTIVE is reached by binding a runtime.
// That is not bureaucracy: an attestation from an identity with no bound
// runtime claims that something ran, while naming nothing that could have run
// it. Accepting it would make "runtime assurance" optional in practice while
// the documents said it was not.
func requireActive(w http.ResponseWriter, r *http.Request, a store.Agent) bool {
	if statusRefusal(w, r, a) {
		return true
	}
	if a.Status != "ACTIVE" {
		WriteProblem(w, r, http.StatusForbidden, "UAI_IDENTITY_NOT_ACTIVE",
			"Identity "+a.DID+" is "+a.Status+" and has no bound runtime, so it cannot attest actions.",
			WithRemediation("Bind a runtime with POST /v1/agents/{id}/bind. Existing history is unaffected."))
		return true
	}
	return false
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
