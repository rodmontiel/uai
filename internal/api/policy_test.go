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

func (e *env) evaluate(t *testing.T, req api.EvaluateRequest) (*int, api.DecisionRecord) {
	t.Helper()
	rec := e.postSignedDomain(t, "/v1/policy/evaluate", req, uaicrypto.DomainDecision)
	var out api.DecisionRecord
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("not a decision record: %s", rec.Body)
		}
	}
	code := rec.Code
	return &code, out
}

func evalRequest(capability string) api.EvaluateRequest {
	var r api.EvaluateRequest
	r.Action.Capability = capability
	r.Action.Purpose = "delivery_optimization"
	r.Jurisdiction.Origin = "AR"
	r.Jurisdiction.Basis = "owner_jurisdiction"
	return r
}

func (e *env) grant(t *testing.T, capability string) {
	t.Helper()
	if err := e.db.GrantCapability(context.Background(), "grant-"+ulid("G"), e.agent.ID,
		capability, "did:uai:owner:"+ulid("W"), time.Now().Add(-time.Hour), nil); err != nil {
		t.Fatal(err)
	}
}

// TestEveryDecisionNamesItsPolicy is INV-009 at the API surface: no record
// leaves this endpoint without the version and the bundle hash that produced
// it, whatever the outcome.
func TestEveryDecisionNamesItsPolicy(t *testing.T) {
	e := setup(t)
	e.grant(t, "route.optimize")

	for _, tc := range []struct {
		name       string
		capability string
		want       string
	}{
		{"an allowed action", "route.optimize", "ALLOW"},
		// A denial is recorded exactly as carefully as a permission. A guardrail
		// that only writes down refusals cannot answer "what was permitted and
		// why", which is the question that matters after an incident.
		{"a denied action", "payments.transfer", "DENY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, d := e.evaluate(t, evalRequest(tc.capability))
			if *code != http.StatusOK {
				t.Fatalf("status %d", *code)
			}
			if d.Decision != tc.want {
				t.Errorf("decision = %s (%s), want %s", d.Decision, d.Reason, tc.want)
			}
			if d.Policy.Version == "" || d.Policy.BundleHash == "" {
				t.Fatalf("INV-009: record carries version %q, hash %q", d.Policy.Version, d.Policy.BundleHash)
			}
			if d.Policy.Version != e.bundle.Version() || d.Policy.BundleHash != e.bundle.Hash() {
				t.Errorf("record names %s/%s, bundle is %s/%s",
					d.Policy.Version, d.Policy.BundleHash, e.bundle.Version(), e.bundle.Hash())
			}

			// The record is signed, and the signature covers the decision.
			unsigned := d
			unsigned.Signature = uaicrypto.Signature{}
			if err := uaicrypto.VerifyObject(e.pdpPub, uaicrypto.DomainDecision, unsigned, d.Signature); err != nil {
				t.Fatalf("decision signature must verify: %v", err)
			}
			tampered := unsigned
			tampered.Decision = "ALLOW"
			tampered.Policy.BundleHash = "sha256:" + nonce() + nonce()
			if err := uaicrypto.VerifyObject(e.pdpPub, uaicrypto.DomainDecision, tampered, d.Signature); err == nil {
				t.Error("the policy reference is not covered by the decision signature")
			}

			// And it is persisted, because a decision nobody wrote down is
			// indistinguishable from a request nobody made.
			stored, err := e.db.DecisionByID(context.Background(), d.DecisionID)
			if err != nil {
				t.Fatalf("decision was not recorded: %v", err)
			}
			if stored.Effect != tc.want || stored.PolicyVersion != d.Policy.Version ||
				stored.BundleHash != d.Policy.BundleHash {
				t.Errorf("stored record disagrees with the response: %+v", stored)
			}
		})
	}
}

// TestGrantsAreReadFromTheRegistry: the PDP does not take the caller's word for
// what it is allowed to do.
func TestGrantsAreReadFromTheRegistry(t *testing.T) {
	e := setup(t)
	code, denied := e.evaluate(t, evalRequest("route.optimize"))
	if *code != http.StatusOK {
		t.Fatalf("status %d", *code)
	}
	if denied.Decision != "DENY" || denied.Reason != "capability_not_granted" {
		t.Fatalf("an ungranted capability was %s (%s)", denied.Decision, denied.Reason)
	}

	e.grant(t, "route.optimize")
	code, allowed := e.evaluate(t, evalRequest("route.optimize"))
	if *code != http.StatusOK {
		t.Fatalf("status %d", *code)
	}
	if allowed.Decision != "ALLOW" {
		t.Fatalf("a granted capability was %s (%s)", allowed.Decision, allowed.Reason)
	}
}

// TestPolicyEndpointRequiresProof: an unauthenticated caller cannot ask the PDP
// what somebody else is allowed to do.
func TestPolicyEndpointRequiresProof(t *testing.T) {
	e := setup(t)
	rec := e.postUnsigned(t, "/v1/policy/evaluate", evalRequest("route.optimize"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401: %s", rec.Code, rec.Body)
	}
}

// TestNoBundleFailsClosed: a PDP with no policy permits nothing.
func TestNoBundleFailsClosed(t *testing.T) {
	e := setup(t)
	bare := api.NewServer(e.db, api.WithScheme("http")).Routes()
	rec := e.postSignedDomainTo(t, bare, "/v1/policy/evaluate",
		evalRequest("route.optimize"), uaicrypto.DomainDecision)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503: %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_POLICY_UNAVAILABLE" {
		t.Errorf("title = %q, want UAI_POLICY_UNAVAILABLE", title)
	}
}
