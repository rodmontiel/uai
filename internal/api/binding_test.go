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
	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// bindEnv drives the two-step binding exchange over a PoP-signed request.
func (e *env) openBinding(t *testing.T, op, path string) api.BindingChallengeResponse {
	t.Helper()
	rec := e.postSigned(t, path, api.BindRequest{})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("open %s: %d %s", op, rec.Code, rec.Body)
	}
	var ch api.BindingChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Challenge == "" || ch.Audience == "" {
		t.Fatalf("challenge response is incomplete: %+v", ch)
	}
	return ch
}

func (e *env) completeBinding(t *testing.T, path string, stmt challenge.Binding,
	signer uaicrypto.Signer, extra func(*api.BindRequest)) *httptest.ResponseRecorder {
	t.Helper()
	sig, err := challenge.SignBinding(signer, stmt)
	if err != nil {
		t.Fatal(err)
	}
	req := api.BindRequest{
		Challenge: stmt.Challenge, SpiffeID: stmt.SpiffeID, SVIDCertHash: stmt.SVIDCertHash,
		ImageDigest: stmt.ImageDigest, Reason: stmt.Reason,
		PreviousEventHash: stmt.PreviousEventHash, Signature: &sig,
	}
	if extra != nil {
		extra(&req)
	}
	return e.postSigned(t, path, req)
}

func bindStatement(e *env, ch api.BindingChallengeResponse, op string) challenge.Binding {
	b := challenge.Binding{
		Challenge: ch.Challenge, Operation: op, UAIID: e.agent.UAIID, Audience: ch.Audience,
	}
	if op == challenge.OpBind {
		b.SpiffeID = "spiffe://uai.world/agents/" + e.agent.UAIID + "/i/" + nonce()[:8]
		b.SVIDCertHash = "sha256:" + nonce() + nonce()
	}
	return b
}

func decodeBindResult(t *testing.T, rec *httptest.ResponseRecorder) api.BindResult {
	t.Helper()
	var out api.BindResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("not a bind result: %s", rec.Body)
	}
	return out
}

// TestBindingLifecycleIsOneChain is §9.4: the chain does not restart across a
// bind cycle, and the gap is visible in it.
func TestBindingLifecycleIsOneChain(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	ch := e.openBinding(t, challenge.OpBind, "/v1/agents/"+e.agent.UAIID+"/bind")
	rec := e.completeBinding(t, "/v1/agents/"+e.agent.UAIID+"/bind",
		bindStatement(e, ch, challenge.OpBind), e.signer, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body)
	}
	bound := decodeBindResult(t, rec)
	if bound.Status != "ACTIVE" || bound.RuntimeID == "" {
		t.Fatalf("a bind must produce ACTIVE and a runtime identity: %+v", bound)
	}

	// An action, so the chain has something between the bind and the unbind.
	head, err := e.db.ChainHead(ctx, e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec := e.post(t, e.attestation(t, head.Hash, head.Sequence+1), "idem-"+ulid("I")); rec.Code != http.StatusCreated {
		t.Fatalf("attest after bind: %d %s", rec.Code, rec.Body)
	}

	uch := e.openBinding(t, challenge.OpUnbind, "/v1/agents/"+e.agent.UAIID+"/unbind")
	ustmt := challenge.Binding{Challenge: uch.Challenge, Operation: challenge.OpUnbind,
		UAIID: e.agent.UAIID, Audience: uch.Audience, Reason: "decommissioned"}
	rec = e.completeBinding(t, "/v1/agents/"+e.agent.UAIID+"/unbind", ustmt, e.signer, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", rec.Code, rec.Body)
	}
	if got := decodeBindResult(t, rec).Status; got != "UNBOUND" {
		t.Fatalf("status after unbind = %q, want UNBOUND", got)
	}

	// §9.2: unbinding is not deletion. The runtime is released, the history is not.
	runtimes, err := e.db.ActiveRuntimes(ctx, e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runtimes) != 0 {
		t.Errorf("%d runtime identities survived the unbind", len(runtimes))
	}

	events, err := e.db.ChainEvents(ctx, e.agent.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	kinds := make([]string, len(events))
	for i, ev := range events {
		kinds[i] = ev.Kind
	}
	want := []string{store.KindRegister, store.KindBind, store.KindAction, store.KindUnbind}
	if len(kinds) != len(want) {
		t.Fatalf("chain is %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("chain is %v, want %v", kinds, want)
		}
	}
	// One unbroken chain across every kind of event: that is what lets a
	// verifier see the agent was not participating between two actions.
	if err := e.db.VerifyChain(ctx, e.agent.ID); err != nil {
		t.Fatalf("chain must verify across a bind cycle: %v", err)
	}
}

// TestUnboundAgentCannotAttest closes the gap §6.10 always required.
func TestUnboundAgentCannotAttest(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	uch := e.openBinding(t, challenge.OpUnbind, "/v1/agents/"+e.agent.UAIID+"/unbind")
	rec := e.completeBinding(t, "/v1/agents/"+e.agent.UAIID+"/unbind",
		challenge.Binding{Challenge: uch.Challenge, Operation: challenge.OpUnbind,
			UAIID: e.agent.UAIID, Audience: uch.Audience}, e.signer, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", rec.Code, rec.Body)
	}
	head, err := e.db.ChainHead(ctx, e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec = e.post(t, e.attestation(t, head.Hash, head.Sequence+1), "idem-"+ulid("I"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an unbound agent attested: %d %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_IDENTITY_UNBOUND" {
		t.Errorf("title = %q, want UAI_IDENTITY_UNBOUND", title)
	}
}

// TestRebindRequiresContinuity is §9.3: "unbind, rotate, rebind" must not
// launder a stolen identity.
func TestRebindRequiresContinuity(t *testing.T) {
	e := setup(t)
	uch := e.openBinding(t, challenge.OpUnbind, "/v1/agents/"+e.agent.UAIID+"/unbind")
	if rec := e.completeBinding(t, "/v1/agents/"+e.agent.UAIID+"/unbind",
		challenge.Binding{Challenge: uch.Challenge, Operation: challenge.OpUnbind,
			UAIID: e.agent.UAIID, Audience: uch.Audience}, e.signer, nil); rec.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", rec.Code, rec.Body)
	}
	_, previous, err := e.db.LastUnbind(context.Background(), e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}

	path := "/v1/agents/" + e.agent.UAIID + "/rebind"

	t.Run("without a continuity proof", func(t *testing.T) {
		ch := e.openBinding(t, challenge.OpRebind, path)
		rec := e.completeBinding(t, path, challenge.Binding{
			Challenge: ch.Challenge, Operation: challenge.OpRebind, UAIID: e.agent.UAIID,
			Audience: ch.Audience, PreviousEventHash: previous}, e.signer, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("a rebind without continuity succeeded: %d %s", rec.Code, rec.Body)
		}
		if title := problemTitle(t, rec); title != "UAI_CONTINUITY_REQUIRED" {
			t.Errorf("title = %q, want UAI_CONTINUITY_REQUIRED", title)
		}
	})

	t.Run("with a proof from a key UAI never knew", func(t *testing.T) {
		// This is the laundering attempt: a fresh key claiming continuity.
		stranger, _, err := uaicrypto.GenerateEd25519Signer(e.agent.DID + "#key-9")
		if err != nil {
			t.Fatal(err)
		}
		ch := e.openBinding(t, challenge.OpRebind, path)
		stmt := challenge.Binding{Challenge: ch.Challenge, Operation: challenge.OpRebind,
			UAIID: e.agent.UAIID, Audience: ch.Audience, PreviousEventHash: previous}
		rec := e.completeBinding(t, path, stmt, e.signer, func(req *api.BindRequest) {
			sig, err := challenge.SignBinding(stranger, stmt)
			if err != nil {
				t.Fatal(err)
			}
			req.ContinuityProof = &sig
		})
		if rec.Code == http.StatusOK {
			t.Fatal("an unknown key produced an accepted continuity proof")
		}
	})

	t.Run("pointing at the wrong predecessor", func(t *testing.T) {
		ch := e.openBinding(t, challenge.OpRebind, path)
		stmt := challenge.Binding{Challenge: ch.Challenge, Operation: challenge.OpRebind,
			UAIID: e.agent.UAIID, Audience: ch.Audience,
			PreviousEventHash: "sha256:" + nonce() + nonce()}
		rec := e.completeBinding(t, path, stmt, e.signer, func(req *api.BindRequest) {
			sig, _ := challenge.SignBinding(e.signer, stmt)
			req.ContinuityProof = &sig
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("a rebind with the wrong predecessor succeeded: %d %s", rec.Code, rec.Body)
		}
		if title := problemTitle(t, rec); title != "UAI_CONTINUITY_BROKEN" {
			t.Errorf("title = %q, want UAI_CONTINUITY_BROKEN", title)
		}
	})

	t.Run("with a genuine proof", func(t *testing.T) {
		ch := e.openBinding(t, challenge.OpRebind, path)
		stmt := challenge.Binding{Challenge: ch.Challenge, Operation: challenge.OpRebind,
			UAIID: e.agent.UAIID, Audience: ch.Audience, PreviousEventHash: previous}
		rec := e.completeBinding(t, path, stmt, e.signer, func(req *api.BindRequest) {
			sig, err := challenge.SignBinding(e.signer, stmt)
			if err != nil {
				t.Fatal(err)
			}
			req.ContinuityProof = &sig
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("a genuine rebind failed: %d %s", rec.Code, rec.Body)
		}
		if got := decodeBindResult(t, rec).Status; got != "ACTIVE" {
			t.Errorf("status after rebind = %q, want ACTIVE", got)
		}
	})
}

// TestCompromisedKeyCannotVouchForContinuity is the point of resolving the
// continuity key AS OF the unbind rather than as of now.
func TestCompromisedKeyCannotVouchForContinuity(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	uch := e.openBinding(t, challenge.OpUnbind, "/v1/agents/"+e.agent.UAIID+"/unbind")
	if rec := e.completeBinding(t, "/v1/agents/"+e.agent.UAIID+"/unbind",
		challenge.Binding{Challenge: uch.Challenge, Operation: challenge.OpUnbind,
			UAIID: e.agent.UAIID, Audience: uch.Audience}, e.signer, nil); rec.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", rec.Code, rec.Body)
	}
	unboundAt, previous, err := e.db.LastUnbind(ctx, e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}

	// The owner discovers the theft and declares the compromise as of BEFORE
	// the unbind. Everything the stolen key did from that moment stops counting,
	// including the unbind it performed — so it can no longer vouch for
	// continuity and the identity cannot be walked back in.
	if _, err := e.db.Pool().Exec(ctx,
		`UPDATE agent_keys SET compromise_declared_at = $2 WHERE agent_id = $1`,
		e.agent.ID, unboundAt.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	path := "/v1/agents/" + e.agent.UAIID + "/rebind"
	rec := e.postSigned(t, path, api.BindRequest{})
	// The compromised key cannot even open the exchange any more, which is the
	// same refusal arriving one step earlier.
	if rec.Code == http.StatusAccepted {
		var ch api.BindingChallengeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
			t.Fatal(err)
		}
		stmt := challenge.Binding{Challenge: ch.Challenge, Operation: challenge.OpRebind,
			UAIID: e.agent.UAIID, Audience: ch.Audience, PreviousEventHash: previous}
		rec = e.completeBinding(t, path, stmt, e.signer, func(req *api.BindRequest) {
			sig, _ := challenge.SignBinding(e.signer, stmt)
			req.ContinuityProof = &sig
		})
	}
	if rec.Code == http.StatusOK {
		t.Fatal("a key compromised before the unbind vouched for continuity")
	}
}

// TestBindingChallengeIsSingleUse: a captured statement must not be replayable.
func TestBindingChallengeIsSingleUse(t *testing.T) {
	e := setup(t)
	path := "/v1/agents/" + e.agent.UAIID + "/bind"
	ch := e.openBinding(t, challenge.OpBind, path)
	stmt := bindStatement(e, ch, challenge.OpBind)
	if rec := e.completeBinding(t, path, stmt, e.signer, nil); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body)
	}
	rec := e.completeBinding(t, path, stmt, e.signer, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a consumed challenge was accepted again: %d %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_CHALLENGE_INVALID" {
		t.Errorf("title = %q, want UAI_CHALLENGE_INVALID", title)
	}
}

// TestInvalidTransitionsAreRefused: the state machine is enforced server-side.
func TestInvalidTransitionsAreRefused(t *testing.T) {
	e := setup(t)
	// The fixture agent is ACTIVE, so it has nothing to rebind from.
	rec := e.postSigned(t, "/v1/agents/"+e.agent.UAIID+"/rebind", api.BindRequest{})
	if rec.Code != http.StatusConflict {
		t.Fatalf("rebind from ACTIVE: %d %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_INVALID_STATE_TRANSITION" {
		t.Errorf("title = %q, want UAI_INVALID_STATE_TRANSITION", title)
	}
}

// TestBindingRequiresTheRightIdentity: holding a valid key is not permission to
// act for somebody else.
func TestBindingRequiresTheRightIdentity(t *testing.T) {
	e := setup(t)
	other := setup(t)
	// A signature by another agent's key, aimed at this agent's binding.
	rec := other.postSignedTo(t, e.srv, "/v1/agents/"+e.agent.UAIID+"/bind", api.BindRequest{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("another agent opened this agent's binding: %d %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_IDENTITY_MISMATCH" {
		t.Errorf("title = %q, want UAI_IDENTITY_MISMATCH", title)
	}
}
