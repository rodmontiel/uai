package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/rodmontiel/uai/internal/pdp"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// EvaluateRequest is the body of POST /v1/policy/evaluate.
//
// It is what the agent is ABOUT to do. The identity is never taken from here:
// it comes from the verified signature, like everywhere else.
type EvaluateRequest struct {
	Action struct {
		Capability string `json:"capability"`
		Purpose    string `json:"purpose"`
		Resource   string `json:"resource,omitempty"`
	} `json:"action"`
	Jurisdiction struct {
		Origin      string   `json:"origin"`
		Targets     []string `json:"targets,omitempty"`
		CrossBorder bool     `json:"cross_border"`
		Basis       string   `json:"basis,omitempty"`
	} `json:"jurisdiction"`
	HarmAssessment []map[string]any `json:"harm_assessment,omitempty"`
	Passport       map[string]any   `json:"passport,omitempty"`
}

// DecisionRecord is the signed answer (§12.3.1).
type DecisionRecord struct {
	DecisionID     string              `json:"decision_id"`
	AgentDID       string              `json:"agent_did"`
	Requested      map[string]any      `json:"requested"`
	Jurisdiction   map[string]any      `json:"jurisdiction"`
	Policy         DecisionPolicy      `json:"policy"`
	Checks         map[string]string   `json:"checks"`
	RulesFired     []string            `json:"rules_fired"`
	HarmAssessment []map[string]any    `json:"harm_assessment,omitempty"`
	Decision       string              `json:"decision"`
	Reason         string              `json:"reason"`
	Conditions     map[string]any      `json:"conditions,omitempty"`
	Degraded       bool                `json:"degraded"`
	StalenessSecs  int                 `json:"bundle_staleness_seconds"`
	EvaluatedAt    time.Time           `json:"evaluated_at"`
	Signature      uaicrypto.Signature `json:"signature"`
}

// DecisionPolicy names the exact rules that produced a decision.
//
// Both members are mandatory and that is INV-009 in structural form: a record
// that cannot say which policy decided cannot be audited, replayed, or argued
// with.
type DecisionPolicy struct {
	Version    string `json:"version"`
	BundleHash string `json:"bundle_hash"`
}

// evaluate is the Policy Decision Point (§12.3).
func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	if s.bundle == nil {
		// Fail closed. A PDP with no policy has no basis to permit anything,
		// and "we could not load the rules" must never read as "no objection".
		WriteProblem(w, r, http.StatusServiceUnavailable, "UAI_POLICY_UNAVAILABLE",
			"No policy bundle is loaded, so no request can be authorized.",
			WithRemediation("This is a fail-closed refusal, not a verdict about the request."))
		return
	}
	signerDID, ok := agentFromPoP(r)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_REQUIRED",
			"This endpoint requires an RFC 9421 message signature.")
		return
	}
	req, ok := decode[EvaluateRequest](w, r)
	if !ok {
		return
	}
	agent, err := s.db.AgentByDID(r.Context(), signerDID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}

	now := s.now()
	runtimes, err := s.db.ActiveRuntimes(r.Context(), agent.ID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	grants, err := s.db.CapabilityGrants(r.Context(), agent.ID, now)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}

	input := map[string]any{
		"identity": map[string]any{
			"did": agent.DID, "assurance_level": agent.AssuranceLevel, "status": agent.Status,
		},
		"runtime": map[string]any{"bound": len(runtimes) > 0},
		"action": map[string]any{
			"capability": req.Action.Capability, "purpose": req.Action.Purpose,
			"resource": req.Action.Resource,
		},
		"jurisdiction": map[string]any{
			"origin": req.Jurisdiction.Origin, "targets": targetsOf(req),
			"cross_border": req.Jurisdiction.CrossBorder,
		},
		"capabilities": map[string]any{"granted": grants},
	}
	if len(req.HarmAssessment) > 0 {
		input["harm_assessment"] = req.HarmAssessment
	}
	if req.Passport != nil {
		input["passport"] = req.Passport
	}

	decision, evalErr := s.bundle.Evaluate(r.Context(), input)
	// An evaluation failure is recorded as a DENY rather than dropped. The
	// record is the evidence that a request was refused and why, and a refusal
	// nobody wrote down is indistinguishable from a request nobody made.
	if evalErr != nil {
		problemLog(r, "policy evaluation failed", evalErr)
	}

	id, err := uaiid.NewULID()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not allocate a decision id.")
		return
	}
	record := DecisionRecord{
		DecisionID: id.String(), AgentDID: agent.DID,
		Requested: map[string]any{
			"capability": req.Action.Capability, "purpose": req.Action.Purpose,
			"resource": req.Action.Resource,
		},
		Jurisdiction: map[string]any{
			"origin": req.Jurisdiction.Origin, "targets": targetsOf(req),
			"cross_border": req.Jurisdiction.CrossBorder, "basis": req.Jurisdiction.Basis,
		},
		Policy: DecisionPolicy{Version: s.bundle.Version(), BundleHash: s.bundle.Hash()},
		Checks: map[string]string{
			"identity": "PASS",
			"runtime":  passIf(len(runtimes) > 0),
			// The remaining three are answered by the bundle rather than by a
			// separate pass here, so the record reports where the answer came
			// from instead of implying an independent check that did not run.
			"capability": byBundle(decision, "gasc.capability."),
			"passport":   byBundle(decision, "gasc.passport."),
			"guardrail":  guardrailCheck(decision.Effect),
		},
		RulesFired: decision.RulesFired, HarmAssessment: req.HarmAssessment,
		Decision: decision.Effect, Reason: decision.Reason, Conditions: decision.Conditions,
		Degraded: evalErr != nil, StalenessSecs: int(s.bundle.Staleness(now).Seconds()),
		EvaluatedAt: now.UTC().Truncate(time.Millisecond),
	}
	if s.issuer == nil {
		WriteProblem(w, r, http.StatusServiceUnavailable, "UAI_POLICY_UNAVAILABLE",
			"No decision signing key is configured.")
		return
	}
	sig, err := uaicrypto.SignObject(s.issuer, uaicrypto.DomainDecision, unsignedDecision(record))
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", err.Error())
		return
	}
	record.Signature = sig

	if err := s.storeDecision(r, agent.ID, record); err != nil {
		WriteStoreError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, record)
}

// unsignedDecision is the document the signature covers.
func unsignedDecision(d DecisionRecord) DecisionRecord {
	d.Signature = uaicrypto.Signature{}
	return d
}

func (s *Server) storeDecision(r *http.Request, agentID string, d DecisionRecord) error {
	jurisdiction, err := json.Marshal(d.Jurisdiction)
	if err != nil {
		return err
	}
	checks, err := json.Marshal(d.Checks)
	if err != nil {
		return err
	}
	conditions, err := json.Marshal(orEmptyObject(d.Conditions))
	if err != nil {
		return err
	}
	harm, err := json.Marshal(orEmptyArray(d.HarmAssessment))
	if err != nil {
		return err
	}
	return s.db.RecordDecision(r.Context(), store.Decision{
		ID: d.DecisionID, AgentID: agentID, Capability: d.Requested["capability"].(string),
		Purpose: d.Requested["purpose"].(string), Resource: d.Requested["resource"].(string),
		Jurisdiction: jurisdiction, Checks: checks, RulesFired: d.RulesFired,
		HarmAssessment: harm, Effect: d.Decision, Conditions: conditions,
		Degraded: d.Degraded, StalenessSecs: d.StalenessSecs,
		PolicyVersion: d.Policy.Version, BundleHash: d.Policy.BundleHash,
		Signature: d.Signature.Value, SignerKID: d.Signature.KID, EvaluatedAt: d.EvaluatedAt,
	})
}

func targetsOf(req EvaluateRequest) []string {
	if req.Jurisdiction.Targets == nil {
		return []string{}
	}
	return req.Jurisdiction.Targets
}

func passIf(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// byBundle reports what the bundle concluded for a family of rules, rather than
// asserting a check this service did not itself perform.
func byBundle(d pdp.Decision, prefix string) string {
	for _, rule := range d.RulesFired {
		if len(rule) >= len(prefix) && rule[:len(prefix)] == prefix {
			return "FAIL"
		}
	}
	return "PASS"
}

func guardrailCheck(effect string) string {
	switch effect {
	case pdp.EffectAllow:
		return "PASS"
	case pdp.EffectAllowMonitoring, pdp.EffectRequireApproval:
		return "PASS_WITH_CONDITIONS"
	default:
		return "FAIL"
	}
}

func orEmptyObject(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func orEmptyArray(a []map[string]any) []map[string]any {
	if a == nil {
		return []map[string]any{}
	}
	return a
}
