package uai_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
	uai "github.com/rodmontiel/uai/sdk/go"
)

// gateway is a stub that answers the three calls Act makes.
type gateway struct {
	decision  string
	reason    string
	attested  []map[string]any
	evaluated int
	attestErr int // status to answer /attest with, 0 means 201
}

func (g *gateway) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/policy/evaluate":
			g.evaluated++
			effect := g.decision
			if effect == "" {
				effect = "ALLOW"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision_id": "01JD", "decision": effect, "reason": g.reason,
				"policy":      map[string]any{"version": "GASC-2027.4", "bundle_hash": "sha256:aa"},
				"rules_fired": []string{"capability_envelope"},
			})
		case "/v1/actions/attest":
			var body map[string]any
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("attestation body: %v", err)
			}
			g.attested = append(g.attested, body)
			if g.attestErr != 0 {
				w.WriteHeader(g.attestErr)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"title": "UAI_IDENTITY_NOT_ACTIVE", "status": g.attestErr,
					"detail": "no runtime bound"})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"event_id": "evt-1", "event_hash": "sha256:cc", "sequence": 2,
				"transparency": "LOGGED"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"events": []any{}, "head": map[string]any{"hash": "sha256:bb", "sequence": 1}})
		}
	})
}

func newClient(t *testing.T, g *gateway) (*uai.Client, func()) {
	t.Helper()
	srv := httptest.NewServer(g.handler(t))
	signer, _, err := uaicrypto.GenerateEd25519Signer("did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := uai.New(srv.URL, "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM", signer,
		uai.WithOwnerDID("did:uai:owner:01JY8R9ZB0"))
	if err != nil {
		t.Fatal(err)
	}
	return c, srv.Close
}

func intent() uai.Intent {
	return uai.Intent{
		Capability: "route.optimize", Purpose: "delivery_optimization",
		Jurisdiction: uai.Jurisdiction{Origin: "AR", Basis: "owner_jurisdiction"},
	}
}

// TestFailuresAreAttestedToo is the reason the SDK owns the call rather than
// exposing attest() and trusting the integrator to remember. An accountability
// record that contains only successes is an advertisement.
func TestFailuresAreAttestedToo(t *testing.T) {
	g := &gateway{}
	c, done := newClient(t, g)
	defer done()

	boom := errors.New("the routing service refused the request")
	rec, err := c.Act(context.Background(), intent(), func(context.Context) (any, error) {
		return nil, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Act returned %v, want the work's own error", err)
	}
	if rec.Outcome != "FAILURE" {
		t.Fatalf("outcome = %q, want FAILURE", rec.Outcome)
	}
	if len(g.attested) != 1 {
		t.Fatalf("%d attestations, want 1: a failure that goes unrecorded is a failure nobody can audit",
			len(g.attested))
	}
	if g.attested[0]["outcome"] != "FAILURE" {
		t.Errorf("attested outcome = %v, want FAILURE", g.attested[0]["outcome"])
	}
	if rec.AttestError != nil {
		t.Errorf("attest error: %v", rec.AttestError)
	}
}

// TestAPanicIsAttestedAndReRaised: the SDK must not change what the agent does,
// and must not lose the record of the worst thing that can happen to it.
func TestAPanicIsAttestedAndReRaised(t *testing.T) {
	g := &gateway{}
	c, done := newClient(t, g)
	defer done()

	defer func() {
		p := recover()
		if p == nil {
			t.Fatal("the panic was swallowed; the agent's own error handling would never run")
		}
		if len(g.attested) != 1 || g.attested[0]["outcome"] != "FAILURE" {
			t.Fatalf("the panic was not attested as FAILURE: %v", g.attested)
		}
	}()
	_, _ = c.Act(context.Background(), intent(), func(context.Context) (any, error) {
		panic("the model produced an unparseable plan")
	})
}

// TestADenialStopsTheWorkAndIsRecorded: the closure must never run, and the
// refusal must appear in the agent's own chain. A refusal nobody wrote down is
// indistinguishable from a request nobody made.
func TestADenialStopsTheWorkAndIsRecorded(t *testing.T) {
	g := &gateway{decision: "DENY", reason: "capability_not_granted"}
	c, done := newClient(t, g)
	defer done()

	ran := false
	rec, err := c.Act(context.Background(), intent(), func(context.Context) (any, error) {
		ran = true
		return "done", nil
	})
	if ran {
		t.Fatal("the work ran after a DENY")
	}
	var denied *uai.Denied
	if !errors.As(err, &denied) {
		t.Fatalf("err = %v, want *uai.Denied", err)
	}
	if denied.Decision.Reason != "capability_not_granted" {
		t.Errorf("reason = %q", denied.Decision.Reason)
	}
	if rec.Outcome != "ABORTED_BY_POLICY" {
		t.Errorf("outcome = %q, want ABORTED_BY_POLICY", rec.Outcome)
	}
	if len(g.attested) != 1 || g.attested[0]["outcome"] != "ABORTED_BY_POLICY" {
		t.Fatalf("the refusal was not recorded: %v", g.attested)
	}
}

// TestRequireHumanApprovalIsNotAnAllow. Treating it as a conditional yes is how
// a human-in-the-loop requirement quietly becomes a log line.
func TestRequireHumanApprovalIsNotAnAllow(t *testing.T) {
	for _, effect := range []string{"REQUIRE_HUMAN_APPROVAL", "QUARANTINE", "DENY"} {
		g := &gateway{decision: effect}
		c, done := newClient(t, g)
		ran := false
		_, err := c.Act(context.Background(), intent(), func(context.Context) (any, error) {
			ran = true
			return nil, nil
		})
		done()
		if ran {
			t.Errorf("%s ran the work", effect)
		}
		var denied *uai.Denied
		if !errors.As(err, &denied) {
			t.Errorf("%s did not produce a refusal: %v", effect, err)
		}
	}
}

// TestPolicyUnreachableFailsClosed: "we could not ask" must never read as "no
// objection" (§12.4).
func TestPolicyUnreachableFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"title":"UAI_POLICY_UNAVAILABLE","status":503}`)
	}))
	defer srv.Close()
	signer, _, _ := uaicrypto.GenerateEd25519Signer("did:uai:agent:01J#key-1")
	c, err := uai.New(srv.URL, "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM", signer)
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	if _, err := c.Act(context.Background(), intent(), func(context.Context) (any, error) {
		ran = true
		return nil, nil
	}); err == nil {
		t.Fatal("an unreachable PDP produced no error")
	}
	if ran {
		t.Fatal("the work ran while the guardrail was unreachable")
	}
}

// TestContentNeverLeavesTheProcess: the input and the output are committed
// locally, and only the commitment is sent.
func TestContentNeverLeavesTheProcess(t *testing.T) {
	const secret = "customer@example.com"
	g := &gateway{}
	c, done := newClient(t, g)
	defer done()

	rec, err := c.Act(context.Background(), uai.Intent{
		Capability: "crm.customer.read", Purpose: "support",
		Jurisdiction: uai.Jurisdiction{Origin: "AR"},
		Input:        map[string]any{"email": secret},
	}, func(context.Context) (any, error) {
		return map[string]any{"records": 1}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(g.attested[0])
	if strings.Contains(string(raw), secret) {
		t.Fatalf("the content was transmitted:\n%s", raw)
	}
	commitment, _ := g.attested[0]["input_commitment"].(string)
	if !strings.HasPrefix(commitment, "sha256:") {
		t.Fatalf("input_commitment = %q", commitment)
	}
	if len(rec.InputSalt) != 32 || len(rec.OutputSalt) != 32 {
		t.Fatalf("salts = %d/%d bytes, want 32 each", len(rec.InputSalt), len(rec.OutputSalt))
	}
	// The salt the caller kept must actually open the commitment. If it did
	// not, the record would be permanently unopenable and nobody would find out
	// until the day it mattered.
	sum, err := uaicrypto.CommitObject(rec.InputSalt, map[string]any{"email": secret})
	if err != nil {
		t.Fatal(err)
	}
	if uaicrypto.FormatDigest(sum) != commitment {
		t.Fatal("the returned salt does not open the commitment that was sent")
	}
}

// TestASaltIsNeverReused across two actions with identical content.
func TestASaltIsNeverReused(t *testing.T) {
	g := &gateway{}
	c, done := newClient(t, g)
	defer done()

	same := uai.Intent{Capability: "crm.customer.read", Purpose: "support",
		Jurisdiction: uai.Jurisdiction{Origin: "AR"}, Input: "YES"}
	work := func(context.Context) (any, error) { return "NO", nil }

	first, err := c.Act(context.Background(), same, work)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Act(context.Background(), same, work)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.InputSalt) == string(second.InputSalt) {
		t.Fatal("the same salt was used twice: opening one commitment would let anyone test " +
			"guesses against the other")
	}
	if g.attested[0]["input_commitment"] == g.attested[1]["input_commitment"] {
		t.Fatal("identical content produced identical commitments, which is what the salt exists " +
			"to prevent")
	}
}

// TestAnUnrecordedActionSaysSo: the work is done and the evidence is missing,
// and a caller that is not told is running unattested without knowing it.
func TestAnUnrecordedActionSaysSo(t *testing.T) {
	g := &gateway{attestErr: http.StatusForbidden}
	c, done := newClient(t, g)
	defer done()

	rec, err := c.Act(context.Background(), intent(), func(context.Context) (any, error) {
		return "done", nil
	})
	if err != nil {
		t.Fatalf("the work succeeded, so Act must return the work's result: %v", err)
	}
	if rec.AttestError == nil {
		t.Fatal("the attestation failed and the record does not say so")
	}
	if !uai.IsCode(rec.AttestError, "UAI_IDENTITY_NOT_ACTIVE") {
		t.Errorf("AttestError = %v, want a typed UAI_IDENTITY_NOT_ACTIVE", rec.AttestError)
	}
	if rec.EventHash != "" {
		t.Error("an event hash was reported for an attestation that was refused")
	}
}

// TestTheChainIsTrackedNotGuessed: after one attestation the next one names it
// as its predecessor, without a second round trip.
func TestTheChainIsTrackedNotGuessed(t *testing.T) {
	g := &gateway{}
	c, done := newClient(t, g)
	defer done()

	work := func(context.Context) (any, error) { return nil, nil }
	if _, err := c.Act(context.Background(), intent(), work); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Act(context.Background(), intent(), work); err != nil {
		t.Fatal(err)
	}
	if got := g.attested[0]["previous_event_hash"]; got != "sha256:bb" {
		t.Errorf("first previous_event_hash = %v, want the head we fetched", got)
	}
	if got := g.attested[1]["previous_event_hash"]; got != "sha256:cc" {
		t.Errorf("second previous_event_hash = %v, want the first event's hash", got)
	}
}

// TestNoForceOption is a design assertion: there is no argument to Act that
// turns a refusal into execution. If one is ever added, this fails.
func TestNoForceOption(t *testing.T) {
	g := &gateway{decision: "DENY"}
	c, done := newClient(t, g)
	defer done()
	if _, err := c.Act(context.Background(), intent(),
		func(context.Context) (any, error) { return nil, nil }); err == nil {
		t.Fatal("a DENY produced no error")
	}
	if g.evaluated != 1 {
		t.Errorf("the PDP was consulted %d times, want exactly once", g.evaluated)
	}
}
