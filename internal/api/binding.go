package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// BindingChallengeTTL is the lifetime of a binding challenge (§9.1).
const BindingChallengeTTL = 300 * time.Second

// SVIDTTL is how long a bound runtime identity is considered current. §6.5
// targets 5 minutes in production; the MVP uses one hour.
const SVIDTTL = time.Hour

// BindRequest is the body of the three binding operations.
//
// Sent empty (no challenge), it asks for one. Sent with a challenge and a
// signature, it performs the operation. Same endpoint, two steps, exactly as
// §9.1 draws it — the agent cannot sign a statement until the registry has told
// it which value to sign over.
type BindRequest struct {
	Challenge    string `json:"challenge,omitempty"`
	SpiffeID     string `json:"svid_spiffe_id,omitempty"`
	SVIDCertHash string `json:"svid_cert_hash,omitempty"`
	ImageDigest  string `json:"image_digest,omitempty"`
	Reason       string `json:"reason,omitempty"`
	// PreviousEventHash and ContinuityProof are the rebind-only members of
	// §9.3. The proof is a full signature rather than an opaque string: a
	// continuity proof that cannot name the key that made it is unverifiable.
	PreviousEventHash string               `json:"previous_event_hash,omitempty"`
	ContinuityProof   *uaicrypto.Signature `json:"continuity_proof,omitempty"`
	Signature         *uaicrypto.Signature `json:"signature,omitempty"`
}

// BindingChallengeResponse is the 202 that opens an operation.
type BindingChallengeResponse struct {
	Challenge string `json:"challenge"`
	Operation string `json:"operation"`
	Audience  string `json:"audience"`
	ExpiresIn int    `json:"expires_in"`
}

// BindResult is the 200 of a completed operation.
type BindResult struct {
	Status     string `json:"status"`
	BindingID  string `json:"binding_id"`
	Sequence   int64  `json:"sequence"`
	EventHash  string `json:"event_hash"`
	RuntimeID  string `json:"runtime_identity_id,omitempty"`
	OccurredAt string `json:"occurred_at"`
}

// bind, unbind and rebind share one handler: the three differ in which states
// they accept, what the statement must carry and what state they produce, and
// spelling that out once keeps the three from drifting apart.
func (s *Server) bind(w http.ResponseWriter, r *http.Request)   { s.binding(w, r, challenge.OpBind) }
func (s *Server) unbind(w http.ResponseWriter, r *http.Request) { s.binding(w, r, challenge.OpUnbind) }
func (s *Server) rebind(w http.ResponseWriter, r *http.Request) { s.binding(w, r, challenge.OpRebind) }

// transition describes one operation's place in the state machine of §6.10.
type transition struct {
	from   map[string]bool
	to     string
	reason string
}

var transitions = map[string]transition{
	// VERIFIED is the state §6.10 names, and REGISTERED is accepted because the
	// credential chain that promotes an identity to VERIFIED is validated by a
	// service that does not exist yet (Phase 4 remainder). Accepting UNBOUND
	// here instead of on rebind would let an agent skip the continuity proof.
	challenge.OpBind: {
		from: map[string]bool{"REGISTERED": true, "VERIFIED": true, "ACTIVE": true},
		to:   "ACTIVE", reason: "bind",
	},
	challenge.OpUnbind: {
		from: map[string]bool{"ACTIVE": true, "REGISTERED": true, "VERIFIED": true},
		to:   "UNBOUND", reason: "unbind",
	},
	challenge.OpRebind: {
		from: map[string]bool{"UNBOUND": true},
		to:   "ACTIVE", reason: "rebind",
	},
}

func (s *Server) binding(w http.ResponseWriter, r *http.Request, operation string) {
	id, ok := parseUAIID(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	// Identity comes from the verified signature, never from the path. Without
	// this an agent holding a valid key could unbind somebody else.
	signerDID, ok := agentFromPoP(r)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_REQUIRED",
			"This endpoint requires an RFC 9421 message signature.")
		return
	}
	agent, err := s.db.AgentByUAIID(r.Context(), id.String())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	if !s.mayActFor(agent, signerDID) {
		WriteProblem(w, r, http.StatusForbidden, "UAI_IDENTITY_MISMATCH",
			"The signing key does not belong to "+agent.DID+" or to its owner.",
			WithRemediation("§9.2 allows the owner's key for a lost agent; nobody else's."))
		return
	}
	// A revoked identity performs no lifecycle operations. Quarantine is
	// preventive and reversible, but binding while quarantined would undo the
	// containment it exists to provide.
	if agent.Status == "REVOKED" || agent.Status == "QUARANTINED" {
		statusRefusal(w, r, agent)
		return
	}

	req, ok := decode[BindRequest](w, r)
	if !ok {
		return
	}
	t := transitions[operation]
	if !t.from[agent.Status] {
		WriteProblem(w, r, http.StatusConflict, "UAI_INVALID_STATE_TRANSITION",
			"Identity "+agent.DID+" is "+agent.Status+"; a "+t.reason+" is not available from there.",
			WithRemediation("The state machine of §6.10 is enforced server-side; the client never asserts a target state."))
		return
	}

	if req.Challenge == "" {
		s.issueBindingChallenge(w, r, agent, operation)
		return
	}
	s.completeBinding(w, r, agent, operation, req)
}

// mayActFor reports whether a signer may run a lifecycle operation for an agent.
func (s *Server) mayActFor(agent store.Agent, signerDID string) bool {
	if signerDID == agent.DID {
		return true
	}
	// §9.2: the owner's key is accepted for the case of a lost agent. An agent
	// that cannot sign would otherwise be stuck participating forever, which
	// turns "you may leave at any time" into a promise with an asterisk.
	owner, err := s.db.OwnerByDID(context.Background(), signerDID)
	return err == nil && owner.ID == agent.OwnerID
}

func (s *Server) issueBindingChallenge(w http.ResponseWriter, r *http.Request,
	agent store.Agent, operation string) {

	value, err := challenge.New()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not issue a challenge.")
		return
	}
	cid, err := uaiid.NewULID()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not issue a challenge.")
		return
	}
	c := store.BindingChallenge{
		ID: "bch-" + cid.String(), AgentID: agent.ID, Operation: operation,
		Challenge: value, Audience: s.audience, ExpiresAt: s.now().Add(BindingChallengeTTL),
	}
	if err := s.db.IssueBindingChallenge(r.Context(), c); err != nil {
		WriteStoreError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, BindingChallengeResponse{
		Challenge: value, Operation: operation, Audience: s.audience,
		ExpiresIn: int(BindingChallengeTTL.Seconds()),
	})
}

func (s *Server) completeBinding(w http.ResponseWriter, r *http.Request, agent store.Agent,
	operation string, req BindRequest) {

	if req.Signature == nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"A challenge must be answered with a signature over the binding statement.")
		return
	}
	now := s.now()
	stmt := challenge.Binding{
		Challenge: req.Challenge, Operation: operation, UAIID: agent.UAIID, Audience: s.audience,
		SpiffeID: req.SpiffeID, SVIDCertHash: req.SVIDCertHash, ImageDigest: req.ImageDigest,
		Reason: req.Reason, PreviousEventHash: req.PreviousEventHash,
	}
	if err := stmt.Validate(); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", err.Error())
		return
	}

	pub, err := s.resolver.Resolve(req.Signature.KID, now)
	if err != nil {
		WritePoPError(w, r, err)
		return
	}
	if err := challenge.VerifyBinding(pub, stmt, *req.Signature); err != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_PROOF_INVALID", err.Error())
		return
	}

	binding := store.Binding{
		AgentID: agent.ID, Operation: operation, SpiffeID: req.SpiffeID,
		SVIDCertHash: req.SVIDCertHash, ImageDigest: req.ImageDigest, Audience: s.audience,
		Reason: req.Reason, Signature: req.Signature.Value, SignerKID: req.Signature.KID,
	}
	if operation == challenge.OpRebind {
		if ok := s.verifyContinuity(w, r, agent, stmt, req, &binding); !ok {
			return
		}
	}

	eventID, err := uaiid.NewULID()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not allocate an event.")
		return
	}
	binding.ID = eventID.String()
	hash, err := uaicrypto.DigestObject(uaicrypto.DomainChallenge, struct {
		Event     string            `json:"event_id"`
		Statement challenge.Binding `json:"statement"`
		Signature string            `json:"signature"`
	}{binding.ID, stmt, req.Signature.Value})
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", err.Error())
		return
	}

	var runtime *store.RuntimeIdentity
	if operation == challenge.OpBind {
		// The runtime is established BEFORE anything is written. When this
		// registry verifies runtimes, a bind that cannot present an SVID
		// attesting this identity does not happen at all -- it does not happen
		// and get recorded as weaker.
		attested, refused := s.runtimeFor(r, agent.UAIID, req, now)
		if refused != nil {
			refused.write(w, r)
			return
		}
		rid, err := uaiid.NewULID()
		if err != nil {
			WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not allocate a runtime identity.")
			return
		}
		runtime = &store.RuntimeIdentity{
			ID: "rt-" + rid.String(), AgentID: agent.ID, SpiffeID: attested.SpiffeID,
			CertHash: attested.CertHash, ImageDigest: attested.ImageDigest,
			Attestor: attested.Attestor, ExpiresAt: attested.ExpiresAt,
		}
	}

	ev, err := s.db.RecordBinding(r.Context(), binding, req.Challenge,
		uaicrypto.FormatDigest(hash), transitions[operation].to, runtime, now)
	if err != nil {
		writeBindingError(w, r, err)
		return
	}
	result := BindResult{
		Status: transitions[operation].to, BindingID: binding.ID, Sequence: ev.Sequence,
		EventHash: ev.EventHash, OccurredAt: ev.OccurredAt.UTC().Format(time.RFC3339),
	}
	if runtime != nil {
		result.RuntimeID = runtime.ID
	}
	WriteJSON(w, http.StatusOK, result)
}

// verifyContinuity enforces §9.3.
//
// Without it, "unbind, rotate the key, rebind" would be a laundering path for a
// stolen identity: whoever holds the current key could walk an identity out of
// UAI and back in under a key nobody ever vouched for. The proof must come from
// a key that was valid AT THE MOMENT OF UNBINDING, which is why the key is
// resolved as of that instant rather than as of now — a key whose compromise was
// declared retroactively to before the unbind is not valid then, and the rebind
// fails exactly as it should.
func (s *Server) verifyContinuity(w http.ResponseWriter, r *http.Request, agent store.Agent,
	stmt challenge.Binding, req BindRequest, binding *store.Binding) bool {

	if req.ContinuityProof == nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_CONTINUITY_REQUIRED",
			"A rebind must carry a continuity proof signed by a key that was valid when the agent unbound.",
			WithRemediation("Without it, unbinding and rebinding under a new key would launder a stolen identity."))
		return false
	}
	unboundAt, previousHash, err := s.db.LastUnbind(r.Context(), agent.ID)
	if err != nil {
		writeBindingError(w, r, err)
		return false
	}
	// The statement must reference the chain as it stood before the unbind
	// (§9.3), so the gap is visible in the chain rather than papered over.
	if stmt.PreviousEventHash != previousHash {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_CONTINUITY_BROKEN",
			"previous_event_hash must be the last event before unbinding.",
			WithChainHead(ChainHead{Hash: previousHash}))
		return false
	}
	pub, err := s.resolver.Resolve(req.ContinuityProof.KID, unboundAt)
	if err != nil {
		WritePoPError(w, r, err)
		return false
	}
	if err := challenge.VerifyBinding(pub, stmt, *req.ContinuityProof); err != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_CONTINUITY_INVALID", err.Error(),
			WithRemediation("The continuity proof must be made by a key that was valid at unbind time."))
		return false
	}
	binding.ContinuityProof = req.ContinuityProof.Value
	binding.ContinuitySignerKID = req.ContinuityProof.KID
	return true
}

func writeBindingError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrChallengeInvalid):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_CHALLENGE_INVALID", err.Error(),
			WithRemediation("Request a fresh challenge; each one is single-use and lives "+BindingChallengeTTL.String()+"."))
	case errors.Is(err, store.ErrNoUnbind):
		WriteProblem(w, r, http.StatusConflict, "UAI_INVALID_STATE_TRANSITION", err.Error())
	default:
		WriteStoreError(w, r, err)
	}
}
