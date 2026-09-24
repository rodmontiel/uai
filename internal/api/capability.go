package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// CapabilityRequestTTL is how long a pending request stays open.
//
// It expires rather than waiting forever because a request an owner never saw
// is not consent, and one still pending months later is a decision nobody made
// that would otherwise keep looking like a decision about to be made.
const CapabilityRequestTTL = 30 * 24 * time.Hour

// CapabilityRequestBody is the body of POST /v1/capability-requests.
type CapabilityRequestBody struct {
	Capability    string `json:"capability"`
	Justification string `json:"justification"`
	Purpose       string `json:"purpose,omitempty"`
	Resource      string `json:"resource,omitempty"`
}

// CapabilityRequestView is what the agent gets back.
//
// There is no field here an agent could read as "and therefore you may now do
// it". State is always PENDING on creation, and Note says in words what the
// absent field says structurally.
type CapabilityRequestView struct {
	RequestID   string    `json:"request_id"`
	Capability  string    `json:"capability"`
	State       string    `json:"state"`
	Granted     bool      `json:"granted"`
	RequestedAt time.Time `json:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Note        string    `json:"note"`
}

// capabilityRequestNote is returned on every response from this endpoint.
//
// §22.9: no MCP tool grants capabilities. The tool that reaches this handler is
// the one an agent would call if it wanted more privilege, so this is the exact
// place where an implementation would be tempted to be helpful, and the exact
// place where being helpful is a confused-deputy generator (T-11/T-13).
const capabilityRequestNote = "This is a request, not a grant. It creates a pending item for the " +
	"owner to decide out of band. Nothing in this API can approve it, including this endpoint."

// requestCapability files a request for a capability the agent does not hold.
func (s *Server) requestCapability(w http.ResponseWriter, r *http.Request) {
	signerDID, ok := agentFromPoP(r)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_REQUIRED",
			"This endpoint requires an RFC 9421 message signature.")
		return
	}
	body, ok := decode[CapabilityRequestBody](w, r)
	if !ok {
		return
	}
	if body.Capability == "" || body.Justification == "" {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"A capability request needs a capability and a justification.",
			WithRemediation("The justification is what an owner reads when deciding. Without it "+
				"they would be approving a capability name."))
		return
	}
	agent, err := s.db.AgentByDID(r.Context(), signerDID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	// A revoked, quarantined or unbound identity may not ask for more. The
	// refusal is the same one that blocks its actions: an identity that may not
	// act has no standing to request a wider ability to act.
	if statusRefusal(w, r, agent) {
		return
	}

	id, err := uaiid.NewULID()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not allocate a request id.")
		return
	}
	now := s.now().UTC()
	req := store.CapabilityRequest{
		ID: "capreq-" + id.String(), AgentID: agent.ID, OwnerID: agent.OwnerID,
		Capability: body.Capability, Justification: body.Justification,
		Purpose: body.Purpose, Resource: body.Resource,
		RequestedByDID: agent.DID, RequestedAt: now, ExpiresAt: now.Add(CapabilityRequestTTL),
	}
	if err := s.db.CreateCapabilityRequest(r.Context(), req); err != nil {
		// A conflict here has exactly one cause and a useful answer, so it is
		// named rather than passed through. WriteStoreError would surface the
		// index name, which tells a caller nothing they can act on and tells a
		// stranger the shape of our schema.
		if errors.Is(err, store.ErrConflict) {
			WriteProblem(w, r, http.StatusConflict, "UAI_CAPABILITY_REQUEST_OPEN",
				"This agent already has an open request for "+body.Capability+".",
				WithRemediation("The owner has not decided it yet. Asking again does not make it "+
					"more likely to be approved, and repeated asking is itself a signal."))
			return
		}
		WriteStoreError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, CapabilityRequestView{
		RequestID: req.ID, Capability: req.Capability, State: "PENDING",
		Granted: false, RequestedAt: req.RequestedAt, ExpiresAt: req.ExpiresAt,
		Note: capabilityRequestNote,
	})
}

// listCapabilityRequests answers GET /v1/agents/{id}/capability-requests.
func (s *Server) listCapabilityRequests(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUAIID(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	agent, err := s.db.AgentByUAIID(r.Context(), id.String())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	reqs, err := s.db.CapabilityRequests(r.Context(), agent.ID, 0)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	out := make([]CapabilityRequestView, 0, len(reqs))
	for _, q := range reqs {
		out = append(out, CapabilityRequestView{
			RequestID: q.ID, Capability: q.Capability, State: q.State,
			Granted:     q.State == "APPROVED",
			RequestedAt: q.RequestedAt.UTC(), ExpiresAt: q.ExpiresAt.UTC(),
			Note: capabilityRequestNote,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"agent": agent.UAIID, "requests": out})
}

// SuspicionBody is the body of POST /v1/suspicions.
//
// It is exactly the HarmSuspicion of spec/schemas/harm-suspicion.schema.json.
// The wire shape is the schema's, not one invented here: a committed schema that
// no endpoint accepts describes nothing, and a third party implementing against
// it would find that out only when their first report was rejected.
//
// Signature covers the whole report and is what survives in the row. The RFC
// 9421 signature on the HTTP call authenticates the caller for this request
// only; it cannot be re-checked from a database row months later, and an
// accusation that cannot be re-attributed to whoever made it is an accusation
// nobody has to answer for.
type SuspicionBody struct {
	SuspicionID string `json:"suspicion_id"`
	ReportedAt  string `json:"reported_at"`
	Reporter    struct {
		DID            string `json:"did"`
		Type           string `json:"type"`
		CredentialHash string `json:"credential_hash,omitempty"`
	} `json:"reporter"`
	Subject struct {
		AgentDID string `json:"agent_did"`
		OwnerDID string `json:"owner_did"`
	} `json:"subject"`
	RelatedEvents  []string `json:"related_events,omitempty"`
	HarmCategories []struct {
		Category string `json:"category"`
		Severity int    `json:"severity"`
	} `json:"harm_categories"`
	Guardrail struct {
		Rule          string `json:"rule,omitempty"`
		PolicyVersion string `json:"policy_version,omitempty"`
		BundleHash    string `json:"bundle_hash,omitempty"`
	} `json:"guardrail,omitempty"`
	EvidenceCommitments   []string            `json:"evidence_commitments,omitempty"`
	Confidence            float64             `json:"confidence"`
	AffectedJurisdictions []string            `json:"affected_jurisdictions,omitempty"`
	Signature             uaicrypto.Signature `json:"signature"`
}

// SigningBytes returns the canonical bytes the reporter signs: the report with
// the signature MEMBER REMOVED, per §10.4.
func (b SuspicionBody) SigningBytes() ([]byte, error) {
	return uaicrypto.CanonicalizeWithout(b, "signature")
}

// suspicionNote is returned with every filed report.
const suspicionNote = "A suspicion opens an investigation; it decides nothing. It is attributed to " +
	"the signer, who can be asked to answer for it, and reports of the same conduct by the same " +
	"reporter are one report, not corroboration."

// fileSuspicion records a signed harm report (§14.1).
//
// The report is signed and the signer is recorded, always. §14 treats accusation
// as a consequential act: an anonymous path in would make the quarantine
// machinery a free denial-of-service tool against any identity (T-24), which is
// why this endpoint is behind proof of possession even though reading the
// resulting case is public.
func (s *Server) fileSuspicion(w http.ResponseWriter, r *http.Request) {
	params, ok := PoPParams(r)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_REQUIRED",
			"A suspicion must be signed. There is no anonymous path into this endpoint.")
		return
	}
	callerDID, _ := agentFromPoP(r)
	body, ok := decode[SuspicionBody](w, r)
	if !ok {
		return
	}
	if body.Reporter.DID == "" {
		body.Reporter.DID = callerDID
	}
	// The reporter named in the report must be the party that signed the call.
	// Without this, a caller could file accusations under someone else's name --
	// and the row would then attribute the act to a party that never made it.
	if body.Reporter.DID != callerDID {
		WriteProblem(w, r, http.StatusForbidden, "UAI_IDENTITY_MISMATCH",
			"The report names "+body.Reporter.DID+" as reporter but was signed by "+callerDID+".",
			WithRemediation("A report is filed by whoever signs it."))
		return
	}
	if len(body.HarmCategories) == 0 {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"A suspicion must name at least one harm category with a severity.")
		return
	}
	if body.Confidence < 0 || body.Confidence > 1 {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"Confidence is a value between 0 and 1.")
		return
	}
	if body.Reporter.Type == "" {
		body.Reporter.Type = "AUTOMATED_GUARDRAIL"
	}
	if body.Subject.AgentDID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"A suspicion must name the agent it is about.")
		return
	}

	// The detached signature over the report, verified against the reporter's
	// key as it was valid when the report was made.
	at := time.Unix(params.Created, 0)
	if params.Created == 0 {
		at = s.now()
	}
	pub, err := s.resolver.Resolve(body.Signature.KID, at)
	if err != nil {
		WritePoPError(w, r, err)
		return
	}
	signed, err := body.SigningBytes()
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", "The report is not canonicalizable.")
		return
	}
	if err := uaicrypto.Verify(pub, uaicrypto.DomainSuspicion, signed, body.Signature); err != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_SUSPICION_SIGNATURE_INVALID", err.Error())
		return
	}

	agent, err := s.db.AgentByDID(r.Context(), body.Subject.AgentDID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	categories, err := json.Marshal(body.HarmCategories)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", "harm_categories is not encodable.")
		return
	}
	id := body.SuspicionID
	if id == "" {
		allocated, err := uaiid.NewULID()
		if err != nil {
			WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not allocate a report id.")
			return
		}
		id = allocated.String()
	}

	filed, corroboration, err := s.db.FileSuspicion(r.Context(), store.Suspicion{
		ID: "susp-" + id, AgentID: agent.ID, OwnerID: agent.OwnerID,
		ReporterDID: body.Reporter.DID, ReporterType: body.Reporter.Type,
		RelatedEventIDs: orEmpty(body.RelatedEvents), HarmCategories: categories,
		GuardrailRule: body.Guardrail.Rule, PolicyVersion: body.Guardrail.PolicyVersion,
		BundleHash: body.Guardrail.BundleHash, EvidenceCommitments: orEmpty(body.EvidenceCommitments),
		Confidence: body.Confidence, AffectedJurisdictions: orEmpty(body.AffectedJurisdictions),
		DedupKey:  dedupKey(agent.UAIID, body),
		Signature: body.Signature.Value, SignerKID: body.Signature.KID, CreatedAt: s.now().UTC(),
	})
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	// What the policy says this warrants, and doing it. The escalation never
	// fails the report: a suspicion that was recorded but could not be escalated
	// is still on file, and losing the report because the follow-up failed
	// would be the worst of both.
	escalation, escErr := s.escalate(r.Context(), agent, body, filed, s.now().UTC())
	if escErr != nil {
		problemLog(r, "escalate suspicion", escErr)
		escalation = Escalation{Effect: "PENDING_REVIEW",
			Note: "The report is recorded. The automatic follow-up did not complete and is " +
				"flagged for an investigator."}
	}

	WriteJSON(w, http.StatusAccepted, map[string]any{
		"suspicion_id": filed,
		"subject":      agent.UAIID,
		"state":        "RECEIVED",
		"escalation":   escalation,
		// The count is the number of DISTINCT reporters of the same conduct. It
		// is reported because it is the number that matters to whoever triages,
		// and because inflating it is what a coordinated accuser would try.
		"distinct_reporters": corroboration,
		"note":               suspicionNote,
	})
}

// dedupKey is the (agent, rule, events) identity of a report.
//
// Reports that share it are one report with several reporters, not several
// reports. Merging on it is what stops one adversary manufacturing
// corroboration by filing the same accusation from many identities.
func dedupKey(uaiID string, b SuspicionBody) string {
	key := uaiID + "|" + b.Guardrail.Rule
	for _, ev := range b.RelatedEvents {
		key += "|" + ev
	}
	return key
}
