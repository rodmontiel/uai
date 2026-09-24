package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// TestACapabilityRequestIsNeverAGrant is the §22.9 hard rule at the API
// surface.
//
// The endpoint an agent would call if it wanted more privilege is the exact
// place where an implementation is tempted to be helpful, and the exact place
// where being helpful is a confused-deputy generator (T-11/T-13).
func TestACapabilityRequestIsNeverAGrant(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	before, err := e.db.CapabilityGrants(ctx, e.agent.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	rec := e.postSignedDomain(t, "/v1/capability-requests", api.CapabilityRequestBody{
		Capability: "payments.transfer", Justification: "issue refunds to customers",
	}, uaicrypto.DomainCapabilityRequest)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("request: %d %s", rec.Code, rec.Body)
	}
	var view api.CapabilityRequestView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.State != "PENDING" || view.Granted {
		t.Fatalf("the response reads as a grant: %+v", view)
	}
	if view.Note == "" {
		t.Error("the response does not say in words what the fields say structurally")
	}

	// The set of capabilities the agent holds must be unchanged. This is the
	// assertion that would catch a handler that "helpfully" granted while
	// reporting PENDING.
	after, err := e.db.CapabilityGrants(ctx, e.agent.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the agent gained a capability by asking: %v -> %v", before, after)
	}

	// And the guardrail still refuses the action the request was about.
	decision := e.postSignedDomain(t, "/v1/policy/evaluate",
		evalRequest("payments.transfer"), uaicrypto.DomainDecision)
	var record api.DecisionRecord
	if err := json.Unmarshal(decision.Body.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Decision != "DENY" {
		t.Fatalf("a pending request changed the decision to %q", record.Decision)
	}
}

// TestAskingTwiceIsRefused: re-asking in a loop until an owner approves out of
// fatigue is a social attack on a human, and the database refuses to host it
// rather than leaving the rate limit as the only defence.
func TestAskingTwiceIsRefused(t *testing.T) {
	e := setup(t)
	body := api.CapabilityRequestBody{Capability: "payments.transfer", Justification: "refunds"}

	if rec := e.postSignedDomain(t, "/v1/capability-requests", body,
		uaicrypto.DomainCapabilityRequest); rec.Code != http.StatusAccepted {
		t.Fatalf("first request: %d %s", rec.Code, rec.Body)
	}
	rec := e.postSignedDomain(t, "/v1/capability-requests", body, uaicrypto.DomainCapabilityRequest)
	if rec.Code == http.StatusAccepted {
		t.Fatal("a second open request for the same capability was accepted")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409", rec.Code)
	}
}

// TestARequestNeedsAJustification: without one, an owner would be approving a
// capability name.
func TestARequestNeedsAJustification(t *testing.T) {
	e := setup(t)
	rec := e.postSignedDomain(t, "/v1/capability-requests",
		api.CapabilityRequestBody{Capability: "payments.transfer"},
		uaicrypto.DomainCapabilityRequest)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

// TestASignatureFromAnotherDomainIsRefused. The tag is inside the signed bytes,
// so a challenge response cannot be presented as a capability request.
func TestASignatureFromAnotherDomainIsRefused(t *testing.T) {
	e := setup(t)
	rec := e.postSignedDomain(t, "/v1/capability-requests",
		api.CapabilityRequestBody{Capability: "payments.transfer", Justification: "refunds"},
		uaicrypto.DomainChallenge)
	if rec.Code == http.StatusAccepted {
		t.Fatal("a signature made in the challenge domain was accepted as a capability request")
	}
}
