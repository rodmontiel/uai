package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/credential"
	"github.com/rodmontiel/uai/pkg/passport"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// PassportTTL is 6 months (§11.3). A passport expires rather than lasting as
// long as the identity because jurisdictional authorization is granted under a
// specific GASC version and has to be re-evaluated when that version moves.
const PassportTTL = 182 * 24 * time.Hour

// PassportCapability is one requested capability + constraints.
type PassportCapability = passport.AuthorizedCapability

// PassportRequestBody is the body of POST /v1/passports/request.
type PassportRequestBody struct {
	AllowedJurisdictions    []string             `json:"allowed_jurisdictions"`
	RestrictedJurisdictions []string             `json:"restricted_jurisdictions,omitempty"`
	Capabilities            []PassportCapability `json:"capabilities"`
	Justification           string               `json:"justification"`
}

// requestPassport issues an AgentPassportCredential when policy allows it (§11.5).
//
// The agent may ask for its own passport, and that is not a self-grant, because
// a passport cannot widen WHAT an agent may do — only WHERE. Every capability it
// scopes must already be granted to the agent by its owner, and the check below
// refuses the request otherwise. The decision about WHERE is made by the PDP
// against the signed GASC bundle, not by this handler and not by the agent.
func (s *Server) requestPassport(w http.ResponseWriter, r *http.Request) {
	if s.bundle == nil {
		WriteProblem(w, r, http.StatusServiceUnavailable, "UAI_POLICY_UNAVAILABLE",
			"No policy bundle is loaded, so no passport can be authorized.",
			WithRemediation("This is a fail-closed refusal, not a verdict about the request."))
		return
	}
	signerDID, ok := agentFromPoP(r)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_REQUIRED",
			"This endpoint requires an RFC 9421 message signature.")
		return
	}
	body, ok := decode[PassportRequestBody](w, r)
	if !ok {
		return
	}
	if len(body.AllowedJurisdictions) == 0 || len(body.Capabilities) == 0 {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"A passport request names the jurisdictions it is for and the capabilities it scopes.")
		return
	}
	if body.Justification == "" {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"A passport request needs a justification: it is what a human reviewer reads when "+
				"the policy asks for one.")
		return
	}
	agent, err := s.db.AgentByDID(r.Context(), signerDID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	if requireActive(w, r, agent) {
		return
	}

	now := s.now().UTC()
	// Derived once, from evidence, and then used for every decision and every
	// document this request produces. A passport records the level at issuance
	// -- that is the point of recording it -- but it must record the level the
	// registry could demonstrate, not the default written at registration.
	al := s.assuranceFor(r.Context(), agent.ID, now).Level.String()
	granted, err := s.db.CapabilityGrants(r.Context(), agent.ID, now)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	// The safety property that makes an agent-initiated request safe: a
	// passport scopes WHERE, never WHAT. Without this check, an agent could
	// name a capability it was never granted and end up holding a document
	// that authorizes it somewhere.
	if missing := notGranted(body.Capabilities, granted); len(missing) > 0 {
		WriteProblem(w, r, http.StatusForbidden, "UAI_CAPABILITY_NOT_GRANTED",
			"The request scopes "+strings.Join(missing, ", ")+", which this agent does not hold.",
			WithRemediation("A passport says where a capability may be used. It cannot grant one. "+
				"Ask the owner for the capability first: POST /v1/capability-requests."))
		return
	}

	// §11.5: the PDP evaluates eligibility. The question it is asked is not
	// "may this agent have a passport" -- there is no such capability, and
	// inventing one would turn the passport into a privilege to be granted
	// before it can be used to scope privileges.
	//
	// The question is narrower and self-consistent: WOULD THE GUARDRAIL HONOUR
	// THIS PASSPORT? Every (capability, jurisdiction) pair the passport would
	// assert is evaluated as an action taken under it. A passport asserting a
	// pair the guardrail would refuse to act on is a document that means
	// nothing, and issuing one would tell an operator they are covered for
	// something that will be denied the first time they try it.
	prospective := map[string]any{
		"state":                    string(passport.StateValid),
		"allowed_jurisdictions":    upper(body.AllowedJurisdictions),
		"restricted_jurisdictions": upper(body.RestrictedJurisdictions),
		"authorized_capabilities":  capabilityNames(body.Capabilities),
	}
	effect, reason, evalErr := s.strictestOver(r.Context(), agent, al, body, granted, prospective)
	if evalErr != nil {
		problemLog(r, "passport eligibility evaluation failed", evalErr)
		effect, reason = "DENY", "evaluation_failed"
	}

	id, err := uaiid.NewULID()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not allocate a passport id.")
		return
	}
	passportID := "urn:uai:passport:" + id.String()
	// The decision is persisted like any other, so the passport can name the
	// evaluation that produced it and an auditor can go and read that record
	// rather than take the passport's word for its own authorization.
	decisionID, err := s.recordPassportDecision(r.Context(), agent, body, effect, reason,
		evalErr != nil, now)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}

	switch effect {
	case "ALLOW", "ALLOW_WITH_MONITORING":
		// issue below
	case "REQUIRE_HUMAN_APPROVAL":
		// 202 and a REQUESTED row. The passport does not exist yet and the
		// response says so in the state: a pending review that answered 201
		// would hand back a document nobody approved.
		if err := s.db.CreatePassport(r.Context(), store.PassportRecord{
			ID: passportID, AgentID: agent.ID, State: string(passport.StateRequested),
			AllowedJurisdictions:    upper(body.AllowedJurisdictions),
			RestrictedJurisdictions: upper(body.RestrictedJurisdictions),
			AssuranceLevel:          al, PolicyVersion: s.bundle.Version(),
			PolicyBundleHash: s.bundle.Hash(), DecisionID: decisionID,
			Capabilities: body.Capabilities,
			ValidFrom:    now, ValidUntil: now.Add(PassportTTL),
		}); err != nil {
			WriteStoreError(w, r, err)
			return
		}
		WriteJSON(w, http.StatusAccepted, map[string]any{
			"passport_id": passportID, "state": string(passport.StateRequested),
			"policy": map[string]any{"version": s.bundle.Version(), "bundle_hash": s.bundle.Hash(),
				"decision_id": decisionID},
			"reason": reason,
			"note": "The policy requires a human to approve this passport. Nothing is authorized " +
				"until one does; this response is a receipt for the request, not a passport.",
		})
		return
	default:
		WriteProblem(w, r, http.StatusForbidden, "UAI_PASSPORT_DENIED",
			"The policy refused this passport: "+reason,
			WithRemediation("Refused under policy "+s.bundle.Version()+
				". The decision record is "+decisionID+"."))
		return
	}

	p := passport.Passport{
		ID: passportID, Agent: agent.DID,
		AllowedJurisdictions:    upper(body.AllowedJurisdictions),
		RestrictedJurisdictions: upper(body.RestrictedJurisdictions),
		AuthorizedCapabilities:  body.Capabilities, AssuranceLevel: al,
		PolicyVersion: s.bundle.Version(), PolicyBundleHash: s.bundle.Hash(),
		State: passport.StateValid, ValidFrom: now, ValidUntil: now.Add(PassportTTL),
	}
	owner, err := s.db.OwnerByID(r.Context(), agent.OwnerID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	p.Owner = owner.DID
	if err := p.Validate(); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_PASSPORT_INVALID", err.Error())
		return
	}

	until := p.ValidUntil
	cred, err := credential.New(credential.TypePassport, passportID, s.issuerDID,
		credential.PassportSubject{
			ID: agent.DID, Owner: owner.DID,
			AllowedJurisdictions: p.AllowedJurisdictions, RestrictedJurisdictions: p.RestrictedJurisdictions,
			AuthorizedCapabilities: p.AuthorizedCapabilities, AssuranceLevel: p.AssuranceLevel,
			PolicyVersion: p.PolicyVersion, PolicyBundleHash: p.PolicyBundleHash,
			DecisionID: decisionID, State: string(passport.StateValid),
		}, now, &until)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "The passport could not be built.")
		return
	}
	signed, err := credential.Issue(s.issuer, cred, now)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "The passport could not be signed.")
		return
	}
	hash, err := signed.Hash()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "The passport could not be hashed.")
		return
	}
	credID := "urn:uuid:passport-" + id.String()
	if err := s.db.CreateCredential(r.Context(), store.Credential{
		ID: credID, Type: credential.TypePassport, SubjectDID: agent.DID, IssuerDID: s.issuerDID,
		AgentID: agent.ID, OwnerID: agent.OwnerID, OrganizationID: agent.OrganizationID,
		CredentialHash: hash, Document: mustJSON(signed), State: "VALID",
		ValidFrom: now, ValidUntil: &until,
	}); err != nil {
		WriteStoreError(w, r, err)
		return
	}
	stored := credID
	if err := s.db.CreatePassport(r.Context(), store.PassportRecord{
		ID: passportID, AgentID: agent.ID, CredentialID: stored, CredentialHash: hash,
		State:                string(passport.StateValid),
		AllowedJurisdictions: p.AllowedJurisdictions, RestrictedJurisdictions: p.RestrictedJurisdictions,
		AssuranceLevel: p.AssuranceLevel, PolicyVersion: p.PolicyVersion,
		PolicyBundleHash: p.PolicyBundleHash, DecisionID: decisionID,
		ValidFrom: now, ValidUntil: until, Capabilities: p.AuthorizedCapabilities,
	}); err != nil {
		WriteStoreError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"passport_id": passportID, "state": string(passport.StateValid),
		"credential": signed, "credential_hash": hash,
		"valid_from": now, "valid_until": until,
		"policy": map[string]any{"version": p.PolicyVersion, "bundle_hash": p.PolicyBundleHash,
			"decision_id": decisionID},
		"note": "A passport says where this agent may act. It says nothing about whether any " +
			"particular action is safe: every action is still evaluated on its own.",
	})
}

// checkPassport runs the §11.6 checklist and reports the outcome.
//
// A GET, and unauthenticated: it changes nothing, and it answers a question a
// relying party asks about an agent it is considering dealing with. An answer
// only the agent itself could obtain would be useless to the party that needs
// it, and one that required a body could not be linked or cached.
func (s *Server) checkPassport(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	body := struct {
		Subject    string
		Capability string
		Targets    []string
		RiskClass  string
	}{
		Subject:    query.Get("subject"),
		Capability: query.Get("capability"),
		RiskClass:  query.Get("risk_class"),
	}
	for _, raw := range strings.Split(query.Get("targets"), ",") {
		if t := strings.TrimSpace(raw); t != "" {
			body.Targets = append(body.Targets, t)
		}
	}
	if body.Capability == "" {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"A passport check names the capability and the target jurisdictions it is for.")
		return
	}
	id, ok := parseUAIID(w, r, body.Subject)
	if !ok {
		return
	}
	agent, err := s.db.AgentByUAIID(r.Context(), id.String())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	now := s.now().UTC()

	rec, err := s.db.LivePassport(r.Context(), agent.ID)
	var p *passport.Passport
	switch {
	case err == nil:
		p = rec.Passport(agent.Status, now)
	case errors.Is(err, store.ErrNotFound):
		p = nil // Check reports UAI_PASSPORT_REQUIRED
	default:
		WriteStoreError(w, r, err)
		return
	}

	used := 0
	if p != nil {
		if used, err = s.db.ActionsInLastHour(r.Context(), agent.ID, body.Capability, now); err != nil {
			WriteStoreError(w, r, err)
			return
		}
	}
	result := passport.Check(p, passport.Request{
		Capability: body.Capability, Targets: body.Targets, RiskClass: body.RiskClass,
		AgentAssurance: s.assuranceFor(r.Context(), agent.ID, now).Level.String(),
		// The stored credential was verified when it was issued and its hash is
		// recorded; a caller holding the credential itself should verify the
		// proof and not take our word for it, which is what the credential_hash
		// in the response is for.
		SignatureValid: p != nil, IssuerTrusted: p != nil,
		ActionsLastHour: used,
	}, now)

	out := map[string]any{
		"subject": agent.UAIID, "capability": body.Capability, "targets": orEmpty(body.Targets),
		"effect": string(result.Effect), "allowed": result.Allowed(),
		"reason": result.Reason, "as_of": now,
		"note": "This is a passport scope check, not a verdict about the action. A passport in " +
			"scope does not authorize an action; the guardrail still evaluates it.",
	}
	if result.Code != "" {
		out["code"] = result.Code
	}
	if p != nil {
		out["passport_id"] = p.ID
		out["state_at_decision"] = string(result.StatusAtDecision)
		out["credential_hash"] = result.CredentialHash
		out["policy_version"] = p.PolicyVersion
	}
	WriteJSON(w, http.StatusOK, out)
}

// getPassport returns one passport's scope, without the credential.
func (s *Server) getPassport(w http.ResponseWriter, r *http.Request) {
	rec, err := s.db.PassportByID(r.Context(), r.PathValue("id"))
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	agent, err := s.db.AgentByUAIID(r.Context(), rec.AgentDID)
	status := ""
	if err == nil {
		status = agent.Status
	} else {
		// Fall back to the agent's DID lookup: the passport row carries it, and
		// a passport rendered without its agent's status could report VALID for
		// an identity that was revoked (§11.4).
		if a, aErr := s.db.AgentByDID(r.Context(), rec.AgentDID); aErr == nil {
			status = a.Status
		}
	}
	WriteJSON(w, http.StatusOK, rec.Passport(status, s.now().UTC()))
}

// notGranted returns the requested capabilities the agent does not hold.
func notGranted(requested []PassportCapability, granted []string) []string {
	have := make(map[string]bool, len(granted))
	for _, g := range granted {
		have[g] = true
	}
	var missing []string
	for _, c := range requested {
		if !have[c.Capability] {
			missing = append(missing, c.Capability)
		}
	}
	sort.Strings(missing)
	return missing
}

func upper(codes []string) []string {
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		out = append(out, strings.ToUpper(strings.TrimSpace(c)))
	}
	sort.Strings(out)
	return out
}

// strictestOver evaluates every (capability, jurisdiction) pair the passport
// would assert and returns the strictest effect among them.
//
// Strictest, not "any allow": a passport is one document covering the whole
// set, so it can only be as permissive as its least permissive pair. Issuing on
// a majority would hand back a passport that is wrong about part of its own
// scope, and the part it is wrong about is the part that matters.
func (s *Server) strictestOver(ctx context.Context, agent store.Agent, assuranceLevel string,
	body PassportRequestBody, granted []string, prospective map[string]any) (string, string, error) {

	rank := map[string]int{
		"ALLOW": 0, "ALLOW_WITH_MONITORING": 1, "REQUIRE_HUMAN_APPROVAL": 2,
		"QUARANTINE": 3, "DENY": 4,
	}
	worst, worstReason := "ALLOW", "within_policy"
	origin := agent.PrimaryJurisdiction

	for _, c := range body.Capabilities {
		for _, target := range upper(body.AllowedJurisdictions) {
			decision, err := s.bundle.Evaluate(ctx, map[string]any{
				"identity": map[string]any{
					"did": agent.DID, "assurance_level": assuranceLevel, "status": agent.Status,
				},
				"runtime": map[string]any{"bound": true},
				"action": map[string]any{
					"capability": c.Capability, "purpose": body.Justification,
				},
				"jurisdiction": map[string]any{
					"origin": origin, "targets": []string{target},
					"cross_border": target != origin,
				},
				"capabilities": map[string]any{"granted": granted},
				"passport":     prospective,
			})
			if err != nil {
				return "DENY", "evaluation_failed", err
			}
			if rank[decision.Effect] > rank[worst] {
				// The reason names the pair, because "denied" without saying
				// which capability in which jurisdiction leaves the operator to
				// guess which of N x M combinations to change.
				worst = decision.Effect
				worstReason = decision.Reason + " (" + c.Capability + " in " + target + ")"
			}
		}
	}
	return worst, worstReason, nil
}

// capabilityNames is the capability list the policy input carries.
func capabilityNames(capabilities []PassportCapability) []string {
	out := make([]string, 0, len(capabilities))
	for _, c := range capabilities {
		out = append(out, c.Capability)
	}
	return out
}

// recordPassportDecision persists the eligibility evaluation as an ordinary
// decision record, so INV-009 holds for it like for any other: a record that
// cannot say which policy decided cannot be audited.
func (s *Server) recordPassportDecision(ctx context.Context, agent store.Agent,
	body PassportRequestBody, effect, reason string, degraded bool, now time.Time) (string, error) {

	id, err := uaiid.NewULID()
	if err != nil {
		return "", err
	}
	decisionID := id.String()
	return decisionID, s.db.RecordDecision(ctx, store.Decision{
		ID: decisionID, AgentID: agent.ID, Capability: "passport.issue",
		Purpose: body.Justification, Effect: effect,
		Jurisdiction: mustJSON(map[string]any{
			"origin": agent.PrimaryJurisdiction, "targets": upper(body.AllowedJurisdictions),
			"cross_border": true}),
		Checks:        mustJSON(map[string]string{"reason": reason}),
		PolicyVersion: s.bundle.Version(), BundleHash: s.bundle.Hash(),
		Degraded: degraded, EvaluatedAt: now,
	})
}

// mustJSON marshals a value that has already been validated.
func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return raw
}

// passportInput renders an agent's live passport for the policy engine, or nil
// when it has none.
//
// Read from the registry rather than accepted from the caller. A passport is an
// authorization, and an authorization a caller can state about itself is not an
// authorization -- it is a request being granted by whoever asked.
//
// The state is derived from the agent's own status as well as the passport row
// (§11.4), so a quarantined agent cannot act on a passport that still says
// VALID in storage.
func (s *Server) passportInput(ctx context.Context, agent store.Agent, now time.Time) map[string]any {
	rec, err := s.db.LivePassport(ctx, agent.ID)
	if err != nil {
		// Including ErrNotFound: an agent with no passport contributes no
		// passport to the input, and the fail-closed rule in the bundle then
		// denies any cross-border action. A synthetic "absent" object would
		// give the rules something to match on that is not a fact.
		return nil
	}
	p := rec.Passport(agent.Status, now)
	return map[string]any{
		"state":                    string(p.State),
		"allowed_jurisdictions":    p.AllowedJurisdictions,
		"restricted_jurisdictions": p.RestrictedJurisdictions,
		"authorized_capabilities":  capabilityNames(p.AuthorizedCapabilities),
		"credential_hash":          p.CredentialHash,
		"policy_version":           p.PolicyVersion,
	}
}
