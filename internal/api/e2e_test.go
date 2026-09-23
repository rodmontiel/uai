package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/attest"
	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// TestRegisterBindAttestEndToEnd is the Phase 4 acceptance criterion of
// docs/protocol/19-roadmap.md, written as a test rather than asserted in a
// status table: "Register → bind → attest works end to end".
//
// It starts from an owner and a key pair and ends with an attested action whose
// chain walks back to the registration event, touching no fixture shortcut on
// the way.
func TestRegisterBindAttestEndToEnd(t *testing.T) {
	e := setupReg(t)
	ctx := context.Background()

	// ── the agent generates its own key. UAI never does: a registry that can
	// generate your key can impersonate you. ────────────────────────────────
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkBytes := json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, b64url(pub)))
	jwk, err := uaicrypto.ParseJWK(jwkBytes)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := jwk.ThumbprintString()
	if err != nil {
		t.Fatal(err)
	}

	// ── 1. register: two signatures naming the same subject ─────────────────
	ch := e.open(t)
	preMint := uaicrypto.NewEd25519Signer(priv, "did:key:pending#key-1")
	if rec := e.proveOwner(t, ch, thumbprint); rec.Code != http.StatusAccepted {
		t.Fatalf("owner proof: %d %s", rec.Code, rec.Body)
	}
	rec := e.proveAgent(t, ch, preMint, jwkBytes, thumbprint)
	if rec.Code != http.StatusCreated {
		t.Fatalf("agent proof: %d %s", rec.Code, rec.Body)
	}
	var minted api.RegisteredAgent
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	if minted.Status != "REGISTERED" {
		t.Fatalf("status after registration = %q, want REGISTERED", minted.Status)
	}

	// The same private key, now under the identifier UAI minted for it.
	agentSigner := uaicrypto.NewEd25519Signer(priv, minted.DID+"#key-1")
	signedPost := func(path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "http://api.uai.test"+path,
			strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "idem-"+nonce())
		domain := uaicrypto.DomainChallenge
		if strings.HasSuffix(path, "/attest") {
			domain = uaicrypto.DomainAttestation
		}
		if err := pop.SignRequest(agentSigner, req, raw, domain, minted.UAIID, nonce()); err != nil {
			t.Fatal(err)
		}
		out := httptest.NewRecorder()
		e.srv.ServeHTTP(out, req)
		return out
	}

	// ── a registered agent may NOT attest yet: no runtime is bound ──────────
	head, err := e.db.ChainHead(ctx, agentIDOf(t, e.db, minted.UAIID))
	if err != nil {
		t.Fatal(err)
	}
	early := signedPost("/v1/actions/attest",
		mustAttest(t, agentSigner, minted, head.Hash, head.Sequence+1))
	if early.Code != http.StatusForbidden {
		t.Fatalf("a registered-but-unbound agent attested: %d %s", early.Code, early.Body)
	}
	if title := problemTitle(t, early); title != "UAI_IDENTITY_NOT_ACTIVE" {
		t.Fatalf("title = %q, want UAI_IDENTITY_NOT_ACTIVE", title)
	}

	// ── 2. bind: tie the identity to where it is running ────────────────────
	bindPath := "/v1/agents/" + minted.UAIID + "/bind"
	rec = signedPost(bindPath, api.BindRequest{})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("open bind: %d %s", rec.Code, rec.Body)
	}
	var bch api.BindingChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &bch); err != nil {
		t.Fatal(err)
	}
	stmt := challenge.Binding{
		Challenge: bch.Challenge, Operation: challenge.OpBind, UAIID: minted.UAIID,
		Audience:     bch.Audience,
		SpiffeID:     "spiffe://uai.world/agents/" + minted.UAIID + "/i/" + nonce()[:8],
		SVIDCertHash: "sha256:" + nonce() + nonce(),
	}
	sig, err := challenge.SignBinding(agentSigner, stmt)
	if err != nil {
		t.Fatal(err)
	}
	rec = signedPost(bindPath, api.BindRequest{
		Challenge: stmt.Challenge, SpiffeID: stmt.SpiffeID,
		SVIDCertHash: stmt.SVIDCertHash, Signature: &sig,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body)
	}
	var bound api.BindResult
	if err := json.Unmarshal(rec.Body.Bytes(), &bound); err != nil {
		t.Fatal(err)
	}
	if bound.Status != "ACTIVE" || bound.RuntimeID == "" {
		t.Fatalf("bind result = %+v, want ACTIVE with a runtime", bound)
	}

	// ── 3. attest ───────────────────────────────────────────────────────────
	rec = signedPost("/v1/actions/attest",
		mustAttest(t, agentSigner, minted, bound.EventHash, bound.Sequence+1))
	if rec.Code != http.StatusCreated {
		t.Fatalf("attest: %d %s", rec.Code, rec.Body)
	}

	// ── the chain walks back from the action to the registration ────────────
	agentID := agentIDOf(t, e.db, minted.UAIID)
	if err := e.db.VerifyChain(ctx, agentID); err != nil {
		t.Fatalf("chain must verify end to end: %v", err)
	}
	events, err := e.db.ChainEvents(ctx, agentID, 50)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{store.KindRegister, store.KindBind, store.KindAction}
	if len(events) != len(want) {
		t.Fatalf("chain has %d events, want %d", len(events), len(want))
	}
	for i, kind := range want {
		if events[i].Kind != kind {
			t.Fatalf("event %d is %s, want %s", i, events[i].Kind, kind)
		}
	}
	if events[0].EventHash != minted.GenesisEventHash {
		t.Error("the chain does not start at the registration record")
	}

	// And the credentials issued at registration still verify.
	rec = e.do(t, http.MethodGet, "/v1/agents/"+minted.UAIID+"/credentials", nil)
	var set api.AgentCredentials
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Credentials) != 2 {
		t.Fatalf("got %d credentials, want 2", len(set.Credentials))
	}
}

func agentIDOf(t *testing.T, db *store.DB, uaiID string) string {
	t.Helper()
	a, err := db.AgentByUAIID(context.Background(), uaiID)
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func mustAttest(t *testing.T, signer uaicrypto.Signer, agent api.RegisteredAgent,
	prev string, seq int64) attest.Attestation {
	t.Helper()
	a := attest.Attestation{
		UAIVersion: attest.Version, EventID: ulid("E"),
		AgentDID: agent.DID, OwnerDID: "did:uai:owner:" + ulid("W"),
		Timestamp: time.Now().UTC(), Nonce: nonce(),
		Action:  attest.Action{Type: "route.optimize", Capability: "route.optimize"},
		Purpose: "delivery_optimization",
		Jurisdiction: attest.Jurisdiction{
			Origin: "AR", Targets: []string{}, CrossBorder: false, Basis: "owner_jurisdiction"},
		Policy: attest.Policy{Version: "GASC-2027.4",
			BundleHash: "sha256:" + strings.Repeat("c", 64),
			DecisionID: ulid("D"), Decision: "ALLOW"},
		Outcome: attest.OutcomeSuccess, PreviousEventHash: prev, Sequence: seq,
	}
	signed, err := attest.Sign(signer, a)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
