package pdp_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/pdp"
	"github.com/rodmontiel/uai/pkg/policy"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

const bundleDir = "../../policy/gasc-2027.4"

func authority(t *testing.T) policy.Authority {
	t.Helper()
	body, err := os.ReadFile("../../policy/authority.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys map[string]uaicrypto.JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	out := policy.Authority{}
	for kid, jwk := range doc.Keys {
		pub, err := jwk.Public()
		if err != nil {
			t.Fatal(err)
		}
		out[kid] = pub
	}
	return out
}

func load(t *testing.T) *pdp.Bundle {
	t.Helper()
	b, err := pdp.Load(context.Background(), os.DirFS(bundleDir), authority(t),
		time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("the committed bundle must verify and compile: %v", err)
	}
	return b
}

// TestCommittedBundleVerifies is the guard that makes "policy is data" true in
// this repository: editing a rule or a threshold without the governance keys
// breaks this test, because the content no longer hashes to what was approved.
func TestCommittedBundleVerifies(t *testing.T) {
	b := load(t)
	if b.Version() != "GASC-2027.4" {
		t.Errorf("version = %q", b.Version())
	}
	if b.Hash() == "" {
		t.Error("a verified bundle must carry its hash")
	}
}

type request map[string]any

func base() request {
	return request{
		"identity": map[string]any{
			"did":             "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
			"assurance_level": "UAI-AL0", "status": "ACTIVE",
		},
		"runtime": map[string]any{"bound": true},
		"action": map[string]any{
			"capability": "route.optimize", "purpose": "delivery",
		},
		"jurisdiction": map[string]any{
			"origin": "AR", "targets": []string{}, "cross_border": false,
		},
		"capabilities": map[string]any{"granted": []string{"route.optimize", "docs.read"}},
	}
}

func with(r request, path []string, value any) request {
	out := request{}
	for k, v := range r {
		out[k] = v
	}
	if len(path) == 1 {
		out[path[0]] = value
		return out
	}
	inner := map[string]any{}
	if existing, ok := out[path[0]].(map[string]any); ok {
		for k, v := range existing {
			inner[k] = v
		}
	}
	inner[path[1]] = value
	out[path[0]] = inner
	return out
}

func TestDecisionMatrix(t *testing.T) {
	b := load(t)
	ctx := context.Background()

	crossBorderCritical := func(assurance string, passport any) request {
		r := base()
		r = with(r, []string{"identity", "assurance_level"}, assurance)
		r = with(r, []string{"action", "capability"}, "cloud.securitygroup.update")
		r = with(r, []string{"capabilities", "granted"}, []string{"cloud.securitygroup.update"})
		r = with(r, []string{"jurisdiction", "cross_border"}, true)
		r = with(r, []string{"jurisdiction", "targets"}, []string{"DE"})
		if passport != nil {
			r = with(r, []string{"passport"}, passport)
		}
		return r
	}
	fullPassport := map[string]any{
		"state": "VALID", "allowed_jurisdictions": []string{"DE"},
		"authorized_capabilities": []string{"cloud.securitygroup.update"},
	}

	cases := []struct {
		name   string
		input  request
		effect string
		reason string
	}{
		{"a granted, registered, domestic action is allowed", base(), pdp.EffectAllow, "baseline_allow"},

		{"a capability that was never granted is denied",
			with(base(), []string{"action", "capability"}, "payments.transfer"),
			pdp.EffectDeny, "capability_not_granted"},

		{"a capability outside the registry has no floor to meet, so it is denied",
			with(with(base(), []string{"action", "capability"}, "unknown.capability"),
				[]string{"capabilities", "granted"}, []string{"unknown.capability"}),
			pdp.EffectDeny, "capability_not_registered"},

		{"assurance below the capability floor is denied",
			with(with(base(), []string{"action", "capability"}, "crm.customer.read"),
				[]string{"capabilities", "granted"}, []string{"crm.customer.read"}),
			pdp.EffectDeny, "assurance_below_floor"},

		{"AL2 with no bound runtime is denied",
			with(with(with(base(), []string{"identity", "assurance_level"}, "UAI-AL2"),
				[]string{"runtime"}, map[string]any{"bound": false}),
				[]string{"capabilities", "granted"}, []string{"route.optimize"}),
			pdp.EffectDeny, "runtime_not_bound"},

		{"a cross-border action with no passport is denied",
			with(with(base(), []string{"jurisdiction", "cross_border"}, true),
				[]string{"jurisdiction", "targets"}, []string{"DE"}),
			pdp.EffectDeny, "passport_required"},

		{"a passport that does not cover the target is refused",
			crossBorderCritical("UAI-AL3", map[string]any{
				"state": "VALID", "allowed_jurisdictions": []string{"JP"},
				"authorized_capabilities": []string{"cloud.securitygroup.update"}}),
			pdp.EffectDeny, "passport_does_not_cover_target"},

		{"critical infrastructure across a border, fully covered at AL3, is monitored",
			crossBorderCritical("UAI-AL3", fullPassport),
			pdp.EffectAllowMonitoring, "cross_border_critical_infrastructure_with_passport"},

		{"the same at AL2 falls back to a human",
			crossBorderCritical("UAI-AL2", fullPassport),
			pdp.EffectDeny, "assurance_below_floor"},

		// The category's special role is a threshold of 0 in taxonomy.json, not
		// a rule naming it: governance changes it by signing new data.
		{"a safety system bypass quarantines at every severity",
			with(base(), []string{"harm_assessment"},
				[]any{map[string]any{"category": "SAFETY_SYSTEM_BYPASS", "severity": 0}}),
			pdp.EffectQuarantine, "harm_safety_system_bypass_severity_0"},

		{"a quarantined agent may still do low-risk work",
			with(base(), []string{"identity"}, map[string]any{
				"did": "did:uai:agent:01JY", "assurance_level": "UAI-AL0", "status": "QUARANTINED"}),
			pdp.EffectAllow, "baseline_allow"},

		{"a quarantined agent may not exceed the risk ceiling",
			with(with(with(base(), []string{"identity"}, map[string]any{
				"did": "did:uai:agent:01JY", "assurance_level": "UAI-AL3", "status": "QUARANTINED"}),
				[]string{"action", "capability"}, "data.export"),
				[]string{"capabilities", "granted"}, []string{"data.export"}),
			pdp.EffectDeny, "quarantined_above_low_risk"},

		{"an input the bundle does not understand is denied",
			request{"nonsense": true}, pdp.EffectDeny, "no_matching_rule"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := b.Evaluate(ctx, tc.input)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if d.Effect != tc.effect {
				t.Errorf("effect = %s (%s), want %s", d.Effect, d.Reason, tc.effect)
			}
			if d.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", d.Reason, tc.reason)
			}
		})
	}
}

// TestStrictestFindingWins: a request that trips several rules is answered by
// the harshest. Taking the mildest would let one permissive rule launder every
// stricter rule it happens to co-occur with.
func TestStrictestFindingWins(t *testing.T) {
	b := load(t)
	// Cross-border critical infrastructure with a covering passport (which on
	// its own yields ALLOW_WITH_MONITORING) AND a harm assessment that denies.
	r := base()
	r = with(r, []string{"identity", "assurance_level"}, "UAI-AL3")
	r = with(r, []string{"action", "capability"}, "cloud.securitygroup.update")
	r = with(r, []string{"capabilities", "granted"}, []string{"cloud.securitygroup.update"})
	r = with(r, []string{"jurisdiction", "cross_border"}, true)
	r = with(r, []string{"jurisdiction", "targets"}, []string{"DE"})
	r = with(r, []string{"passport"}, map[string]any{
		"state": "VALID", "allowed_jurisdictions": []string{"DE"},
		"authorized_capabilities": []string{"cloud.securitygroup.update"}})
	r = with(r, []string{"harm_assessment"},
		[]any{map[string]any{"category": "DATA_EXFILTRATION", "severity": 3}})

	d, err := b.Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if d.Effect != pdp.EffectDeny {
		t.Fatalf("effect = %s (%s), want DENY: the harsher finding must win", d.Effect, d.Reason)
	}
	// Every rule that fired is recorded, not only the winning one: an auditor
	// asking "what else did this trip" must not have to guess.
	if len(d.RulesFired) < 2 {
		t.Errorf("rules_fired = %v, want every rule that fired", d.RulesFired)
	}
}

// TestBundleRefusesTamperedContent is the property the whole signing exercise
// exists for.
func TestBundleRefusesTamperedContent(t *testing.T) {
	files := policy.Files{}
	err := filepath.WalkDir(bundleDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(bundleDir, p)
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = body
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := policy.ParseManifest(files["manifest.json"])
	if err != nil {
		t.Fatal(err)
	}
	auth := authority(t)
	if err := policy.Verify(m, files, auth); err != nil {
		t.Fatalf("the committed bundle must verify: %v", err)
	}

	t.Run("a loosened threshold is caught", func(t *testing.T) {
		tampered := policy.Files{}
		for k, v := range files {
			tampered[k] = v
		}
		tampered["data/taxonomy.json"] = []byte(`{"thresholds":{}}`)
		if err := policy.Verify(m, tampered, auth); err == nil {
			t.Error("edited policy data verified against the approved manifest")
		}
	})

	t.Run("an approval from outside the authority set is refused", func(t *testing.T) {
		stranger, _, err := uaicrypto.GenerateEd25519Signer("did:web:attacker.example#gasc-1")
		if err != nil {
			t.Fatal(err)
		}
		approval, err := policy.SignBundle(stranger, m.BundleHash)
		if err != nil {
			t.Fatal(err)
		}
		padded := m
		padded.Approvals = append(append([]policy.Approval{}, m.Approvals...), approval)
		if err := policy.Verify(padded, files, auth); err == nil {
			t.Error("an unknown signer padded the approval count")
		}
	})

	t.Run("below the threshold is refused", func(t *testing.T) {
		short := m
		short.Approvals = m.Approvals[:1]
		if err := policy.Verify(short, files, auth); err == nil {
			t.Error("one approval satisfied a 3-of-5 threshold")
		}
	})

	t.Run("one signer cannot approve twice", func(t *testing.T) {
		doubled := m
		doubled.Approvals = []policy.Approval{m.Approvals[0], m.Approvals[0], m.Approvals[0]}
		if err := policy.Verify(doubled, files, auth); err == nil {
			t.Error("one key satisfied a 3-of-5 threshold by signing three times")
		}
	})
}
