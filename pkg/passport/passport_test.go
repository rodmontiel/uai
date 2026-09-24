package passport_test

import (
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/passport"
)

func valid() *passport.Passport {
	return &passport.Passport{
		ID: "urn:uai:passport:01J", Agent: "did:uai:agent:01J", Owner: "did:uai:owner:01J",
		AllowedJurisdictions:    []string{"AR", "BR", "DE", "ES"},
		RestrictedJurisdictions: []string{"KP", "IR"},
		AuthorizedCapabilities: []passport.AuthorizedCapability{
			{Capability: "cloud.securitygroup.update", MinAssurance: "UAI-AL3",
				Constraints: passport.Constraints{MaxActionsPerHour: 20, RequiresHumanApprovalAbove: "HIGH"}},
			{Capability: "crm.customer.read", MinAssurance: "UAI-AL2"},
		},
		AssuranceLevel: "UAI-AL3", PolicyVersion: "GASC-2027.4",
		PolicyBundleHash: "sha256:aa", State: passport.StateValid,
		ValidFrom:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ValidUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func ok() passport.Request {
	return passport.Request{
		Capability: "crm.customer.read", Targets: []string{"DE"}, RiskClass: "LOW",
		AgentAssurance: "UAI-AL3", SignatureValid: true, IssuerTrusted: true,
	}
}

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// TestEveryFailurePathDenies walks §11.6 one step at a time. Each case breaks
// exactly one precondition and asserts the code, because a check that denied
// for the right reason by accident would pass a test that only looked at the
// effect -- and the code is what an operator reads to fix the problem.
func TestEveryFailurePathDenies(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*passport.Passport, *passport.Request)
		want string
	}{
		{"no passport at all", func(p *passport.Passport, _ *passport.Request) { *p = passport.Passport{} }, ""},
		{"proof did not verify", func(_ *passport.Passport, r *passport.Request) { r.SignatureValid = false },
			"UAI_PASSPORT_INVALID"},
		{"issuer not trusted", func(_ *passport.Passport, r *passport.Request) { r.IssuerTrusted = false },
			"UAI_PASSPORT_INVALID"},
		{"expired", func(p *passport.Passport, _ *passport.Request) {
			p.ValidUntil = now.Add(-time.Hour)
		}, "UAI_PASSPORT_EXPIRED"},
		{"not yet valid", func(p *passport.Passport, _ *passport.Request) {
			p.ValidFrom = now.Add(time.Hour)
		}, "UAI_PASSPORT_EXPIRED"},
		{"suspended", func(p *passport.Passport, _ *passport.Request) { p.State = passport.StateSuspended },
			"UAI_PASSPORT_SUSPENDED"},
		{"quarantined", func(p *passport.Passport, _ *passport.Request) { p.State = passport.StateQuarantined },
			"UAI_PASSPORT_SUSPENDED"},
		{"revoked", func(p *passport.Passport, _ *passport.Request) { p.State = passport.StateRevoked },
			"UAI_PASSPORT_SUSPENDED"},
		{"no target declared", func(_ *passport.Passport, r *passport.Request) { r.Targets = nil },
			"UAI_JURISDICTION_NOT_ALLOWED"},
		{"target not in the allowed set", func(_ *passport.Passport, r *passport.Request) {
			r.Targets = []string{"US"}
		}, "UAI_JURISDICTION_NOT_ALLOWED"},
		{"target explicitly restricted", func(_ *passport.Passport, r *passport.Request) {
			r.Targets = []string{"KP"}
		}, "UAI_JURISDICTION_RESTRICTED"},
		{"capability not in the passport", func(_ *passport.Passport, r *passport.Request) {
			r.Capability = "payments.transfer"
		}, "UAI_CAPABILITY_NOT_IN_PASSPORT"},
		{"assurance below the capability minimum", func(_ *passport.Passport, r *passport.Request) {
			r.Capability, r.AgentAssurance = "cloud.securitygroup.update", "UAI-AL1"
		}, "UAI_ASSURANCE_INSUFFICIENT"},
		{"unknown assurance level satisfies no minimum", func(_ *passport.Passport, r *passport.Request) {
			r.Capability, r.AgentAssurance = "cloud.securitygroup.update", "UAI-AL-NEW"
		}, "UAI_ASSURANCE_INSUFFICIENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r := valid(), ok()
			tc.mut(p, &r)
			var got passport.Result
			if tc.want == "" { // the "no passport" case
				got = passport.Check(nil, r, now)
				if got.Code != "UAI_PASSPORT_REQUIRED" {
					t.Fatalf("code = %q, want UAI_PASSPORT_REQUIRED", got.Code)
				}
				return
			}
			got = passport.Check(p, r, now)
			if got.Allowed() {
				t.Fatalf("a broken precondition was allowed: %+v", got)
			}
			if got.Code != tc.want {
				t.Fatalf("code = %q, want %q (%s)", got.Code, tc.want, got.Reason)
			}
		})
	}
}

// TestRestrictedIsReportedOverUnlisted pins the one deliberate deviation from
// the order printed in §11.6. Both facts deny; the stronger one is reported.
func TestRestrictedIsReportedOverUnlisted(t *testing.T) {
	p := valid()
	p.AllowedJurisdictions = []string{"AR"} // KP is now both unlisted and restricted
	r := ok()
	r.Targets = []string{"KP"}
	got := passport.Check(p, r, now)
	if got.Code != "UAI_JURISDICTION_RESTRICTED" {
		t.Fatalf("code = %q, want UAI_JURISDICTION_RESTRICTED", got.Code)
	}
}

// TestCrossBorderIsAlwaysObserved asserts the end of §11.6: a clean check ends
// in ALLOW_WITH_MONITORING, never a bare ALLOW. Crossing a boundary is the
// condition the passport exists to make legible.
func TestCrossBorderIsAlwaysObserved(t *testing.T) {
	got := passport.Check(valid(), ok(), now)
	if !got.Allowed() {
		t.Fatalf("a passport in scope denied: %+v", got)
	}
	if got.Effect != passport.EffectAllowMonitoring {
		t.Fatalf("effect = %q, want ALLOW_WITH_MONITORING", got.Effect)
	}
	if got.StatusAtDecision != passport.StateValid {
		t.Fatalf("status at decision = %q, want VALID", got.StatusAtDecision)
	}
}

// TestConstraintsOnlyRaiseTheBar: step 9 can turn an allow into "ask a human".
// It must never turn a denial into an allow, which is asserted by running the
// rate ceiling against a request that fails an earlier step.
func TestConstraintsOnlyRaiseTheBar(t *testing.T) {
	r := ok()
	r.Capability, r.ActionsLastHour = "cloud.securitygroup.update", 20
	if got := passport.Check(valid(), r, now); got.Effect != passport.EffectRequireApproval {
		t.Fatalf("at the ceiling the effect is %q, want REQUIRE_HUMAN_APPROVAL", got.Effect)
	}
	r.ActionsLastHour = 19
	if got := passport.Check(valid(), r, now); !got.Allowed() {
		t.Fatalf("below the ceiling: %+v", got)
	}

	// Same rate state, but the jurisdiction is restricted. The denial wins.
	r.Targets, r.ActionsLastHour = []string{"IR"}, 0
	if got := passport.Check(valid(), r, now); got.Allowed() {
		t.Fatalf("a restricted jurisdiction was allowed under a satisfied rate constraint: %+v", got)
	}
}

// TestRiskAboveThresholdNeedsAHuman covers the second constraint, including the
// unknown-risk case: an unrecognised risk class must escalate, not pass.
func TestRiskAboveThresholdNeedsAHuman(t *testing.T) {
	for _, tc := range []struct {
		risk string
		want passport.Effect
	}{
		{"LOW", passport.EffectAllowMonitoring},
		{"MODERATE", passport.EffectAllowMonitoring},
		{"HIGH", passport.EffectRequireApproval},
		{"CRITICAL", passport.EffectRequireApproval},
		{"SOMETHING_NEW", passport.EffectRequireApproval},
	} {
		r := ok()
		r.Capability, r.RiskClass = "cloud.securitygroup.update", tc.risk
		if got := passport.Check(valid(), r, now); got.Effect != tc.want {
			t.Errorf("risk %s: effect = %q, want %q", tc.risk, got.Effect, tc.want)
		}
	}
}

// TestJurisdictionCodesAreCaseInsensitive: "de" and "DE" are one jurisdiction.
func TestJurisdictionCodesAreCaseInsensitive(t *testing.T) {
	r := ok()
	r.Targets = []string{"de"}
	if got := passport.Check(valid(), r, now); !got.Allowed() {
		t.Fatalf("lowercase country code denied: %+v", got)
	}
	r.Targets = []string{"kp"}
	if got := passport.Check(valid(), r, now); got.Code != "UAI_JURISDICTION_RESTRICTED" {
		t.Fatalf("lowercase restricted code = %q, want UAI_JURISDICTION_RESTRICTED", got.Code)
	}
}

// TestValidateRefusesAnAmbiguousPassport: a jurisdiction that is both allowed
// and restricted would be resolved differently by different verifiers.
func TestValidateRefusesAnAmbiguousPassport(t *testing.T) {
	p := valid()
	p.AllowedJurisdictions = append(p.AllowedJurisdictions, "KP")
	if err := p.Validate(); err == nil {
		t.Fatal("a passport that both allows and restricts KP was accepted")
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("a coherent passport was rejected: %v", err)
	}
}
