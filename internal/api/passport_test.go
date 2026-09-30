package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/passport"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// TestAnAgentCannotWriteItsOwnPassportIntoTheDecision is the regression test
// for the worst defect this phase found.
//
// POST /v1/policy/evaluate used to take `passport` from the request body. An
// agent sent {"passport":{"state":"VALID","allowed_jurisdictions":["KP"]}} and a
// DENY for passport_required became an ALLOW: the caller was writing its own
// authorization state into the question it was asking. That is INV-002 at the
// PDP, and it was found by running the SDK against a real gateway rather than
// by reading the handler.
func TestAnAgentCannotWriteItsOwnPassportIntoTheDecision(t *testing.T) {
	e := setup(t)
	e.grant(t, "route.optimize")

	// Honest: no passport exists, so a cross-border action is denied.
	honest := crossBorder("route.optimize", "KP")
	if got := e.decide(t, honest); got.Decision != "DENY" {
		t.Fatalf("a cross-border action with no passport was %q, want DENY", got.Decision)
	}

	// The attack: a passport the agent simply asserts about itself.
	var forged map[string]any
	raw, err := json.Marshal(honest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &forged); err != nil {
		t.Fatal(err)
	}
	forged["passport"] = map[string]any{
		"state":                   "VALID",
		"allowed_jurisdictions":   []string{"KP"},
		"authorized_capabilities": []string{"route.optimize"},
	}
	rec := e.postSignedDomain(t, "/v1/policy/evaluate", forged, uaicrypto.DomainDecision)
	var record api.DecisionRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Decision != "DENY" {
		t.Fatalf("an agent granted itself a passport in the request body: %q (%s)",
			record.Decision, record.Reason)
	}
}

// TestTheRegistryPassportIsTheOneThatCounts: with a real passport on file, the
// same call is allowed for a jurisdiction it covers and refused for one it does
// not — and a body field cannot change either answer.
func TestTheRegistryPassportIsTheOneThatCounts(t *testing.T) {
	e := setup(t)
	e.grant(t, "route.optimize")
	e.issuePassport(t, []string{"AR", "DE"}, []string{"KP"}, "route.optimize")

	if got := e.decide(t, crossBorder("route.optimize", "DE")); got.Decision != "ALLOW" {
		t.Fatalf("a jurisdiction the passport covers was %q: %s", got.Decision, got.Reason)
	}
	if got := e.decide(t, crossBorder("route.optimize", "KP")); got.Decision != "DENY" {
		t.Fatalf("an explicitly restricted jurisdiction was %q", got.Decision)
	}
	// A capability the passport does not scope, in a jurisdiction it does.
	e.grant(t, "crm.customer.read")
	if got := e.decide(t, crossBorder("crm.customer.read", "DE")); got.Decision != "DENY" {
		t.Fatalf("a capability outside the passport was %q", got.Decision)
	}
}

// TestAPassportCannotScopeAnUngrantedCapability is the property that makes an
// agent-initiated passport request safe: a passport says WHERE, never WHAT.
func TestAPassportCannotScopeAnUngrantedCapability(t *testing.T) {
	e := setup(t)
	rec := e.postSignedDomain(t, "/v1/passports/request", api.PassportRequestBody{
		AllowedJurisdictions: []string{"AR", "DE"},
		Capabilities:         []api.PassportCapability{{Capability: "payments.transfer"}},
		Justification:        "move funds for customers abroad",
	}, uaicrypto.DomainPassport)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403: an agent scoped a capability it was never granted\n%s",
			rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_CAPABILITY_NOT_GRANTED" {
		t.Fatalf("title = %q, want UAI_CAPABILITY_NOT_GRANTED", title)
	}
}

// TestAPassportOnlyAssertsWhatTheGuardrailWouldHonour: the eligibility check
// evaluates every (capability, jurisdiction) pair the passport would cover, so
// it cannot assert a pair the policy would refuse to act on.
func TestAPassportOnlyAssertsWhatTheGuardrailWouldHonour(t *testing.T) {
	e := setup(t)
	e.grant(t, "route.optimize")
	rec := e.postSignedDomain(t, "/v1/passports/request", api.PassportRequestBody{
		// KP is in the allowed list AND in the restricted one. The passport
		// would be internally contradictory, and issuing it would hand back a
		// document that denies what it also permits.
		AllowedJurisdictions:    []string{"AR", "KP"},
		RestrictedJurisdictions: []string{"KP"},
		Capabilities:            []api.PassportCapability{{Capability: "route.optimize"}},
		Justification:           "deliver everywhere",
	}, uaicrypto.DomainPassport)
	if rec.Code == http.StatusCreated {
		t.Fatalf("a self-contradictory passport was issued: %s", rec.Body)
	}
}

// TestTheCheckEndpointNeedsNoKey: the party who needs the answer is whoever is
// dealing with the agent, not the agent.
func TestTheCheckEndpointNeedsNoKey(t *testing.T) {
	e := setup(t)
	e.grant(t, "route.optimize")
	e.issuePassport(t, []string{"AR", "DE"}, []string{"KP"}, "route.optimize")

	req := httptest.NewRequest(http.MethodGet,
		"http://api.uai.test/v1/passports/check?subject="+e.agent.UAIID+
			"&capability=route.optimize&targets=DE", nil)
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 with no signature: %s", rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["allowed"] != true {
		t.Fatalf("a passport in scope was refused: %v", out)
	}
	if out["note"] == nil {
		t.Error("the answer does not say that a passport in scope is not an authorization")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func crossBorder(capability, target string) api.EvaluateRequest {
	r := evalRequest(capability)
	r.Jurisdiction.Targets = []string{target}
	r.Jurisdiction.CrossBorder = true
	r.Jurisdiction.Basis = "resource_location"
	return r
}

func (e *env) decide(t *testing.T, req api.EvaluateRequest) api.DecisionRecord {
	t.Helper()
	rec := e.postSignedDomain(t, "/v1/policy/evaluate", req, uaicrypto.DomainDecision)
	var record api.DecisionRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &record); err != nil {
		t.Fatalf("%v: %s", err, rec.Body)
	}
	return record
}

// issuePassport writes a VALID passport directly, which is what an issuance
// service does. The request path is exercised separately; here the question is
// what the PDP reads, not how the row got there.
func (e *env) issuePassport(t *testing.T, allowed, restricted []string, capabilities ...string) {
	t.Helper()
	now := time.Now().UTC()
	scoped := make([]passport.AuthorizedCapability, 0, len(capabilities))
	for _, c := range capabilities {
		scoped = append(scoped, passport.AuthorizedCapability{Capability: c, MinAssurance: "UAI-AL0"})
	}
	if err := e.db.CreatePassport(context.Background(), store.PassportRecord{
		ID: "urn:uai:passport:" + ulid("P"), AgentID: e.agent.ID,
		State: string(passport.StateValid), AllowedJurisdictions: allowed,
		RestrictedJurisdictions: restricted, AssuranceLevel: "UAI-AL0",
		PolicyVersion: "GASC-2027.4", PolicyBundleHash: "sha256:" + repeat64('a'),
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(24 * time.Hour),
		Capabilities: scoped,
	}); err != nil {
		t.Fatal(err)
	}
}

func repeat64(c byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = c
	}
	return string(out)
}
