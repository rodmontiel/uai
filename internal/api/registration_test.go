package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/credential"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// regEnv is a registration fixture: an owner that already has a key, because
// ownership can only be PROVEN against a key the registry already holds.
type regEnv struct {
	db        *store.DB
	srv       http.Handler
	ownerID   string
	ownerDID  string
	owner     uaicrypto.Signer
	issuerDID string
	issuerPub any
}

func setupReg(t *testing.T) *regEnv {
	t.Helper()
	dsn := os.Getenv("UAI_TEST_DSN")
	if dsn == "" {
		t.Skip("UAI_TEST_DSN not set; skipping registration integration tests")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("UAI_TEST_DSN is set but the database is unusable: %v", err)
	}
	t.Cleanup(db.Close)

	ownerID := "own-" + ulid("W")
	ownerDID := "did:uai:owner:" + ulid("W")
	if err := db.CreateOwner(ctx, store.Owner{
		ID: ownerID, UAIID: "uai:owner:" + ulid("W"), DID: ownerDID,
		DisplayName: "ACME Ops", Jurisdiction: "AR"}); err != nil {
		t.Fatal(err)
	}
	signer, pub, err := uaicrypto.GenerateEd25519Signer(ownerDID + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateOwnerKey(ctx, ownerID, store.KeyRecord{
		ID: "okey-" + ulid("K"), KeyID: "key-1", Alg: "EdDSA",
		PublicJWK:  json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, b64url(pub))),
		Protection: "HSM", ValidFrom: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	const issuerDID = "did:web:credentials.uai.test"
	issuer, issuerPub, err := uaicrypto.GenerateEd25519Signer(issuerDID + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(db, api.WithScheme("http"), api.WithIssuer(issuerDID, issuer))
	return &regEnv{db: db, srv: srv.Routes(), ownerID: ownerID, ownerDID: ownerDID,
		owner: signer, issuerDID: issuerDID, issuerPub: issuerPub}
}

func (e *regEnv) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return e.doOn(t, e.srv, method, path, body)
}

// doOn issues a request against a specific handler, so a test can talk to a
// server whose clock differs from this one's.
func (e *regEnv) doOn(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf []byte
	if body != nil {
		var err error
		if buf, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "idem-"+nonce())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// open starts a registration and returns the challenge pair.
func (e *regEnv) open(t *testing.T) api.RegistrationChallenge {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/v1/agents", api.RegistrationRequest{
		LogicalName: "DeliveryOptimizer", Version: "1.4.2",
		AgentType: "autonomous_task_agent", OwnerDID: e.ownerDID,
		PrimaryJurisdiction: "AR",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("open registration: got %d, want 202: %s", rec.Code, rec.Body)
	}
	var ch api.RegistrationChallenge
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	return ch
}

// agentKeypair returns a fresh agent signer, its JWK and its thumbprint.
func agentKeypair(t *testing.T) (uaicrypto.Signer, json.RawMessage, string) {
	t.Helper()
	signer, pub, err := uaicrypto.GenerateEd25519Signer("did:key:pending#key-1")
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, b64url(pub)))
	jwk, err := uaicrypto.ParseJWK(raw)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := jwk.ThumbprintString()
	if err != nil {
		t.Fatal(err)
	}
	return signer, raw, tp
}

func (e *regEnv) proveOwner(t *testing.T, ch api.RegistrationChallenge, thumbprint string) *httptest.ResponseRecorder {
	t.Helper()
	sig, err := challenge.Sign(e.owner, challenge.Ownership{
		Challenge: ch.ChallengeOwner, RegistrationID: ch.RegistrationID,
		Role: challenge.RoleOwner, AgentKeyThumbprint: thumbprint, OwnerDID: e.ownerDID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e.do(t, http.MethodPost, "/v1/agents/"+ch.RegistrationID+"/prove", api.ProofSubmission{
		Role: challenge.RoleOwner, Challenge: ch.ChallengeOwner,
		AgentKeyThumbprint: thumbprint, Signature: sig,
	})
}

func (e *regEnv) proveAgent(t *testing.T, ch api.RegistrationChallenge, signer uaicrypto.Signer,
	jwk json.RawMessage, thumbprint string) *httptest.ResponseRecorder {
	t.Helper()
	sig, err := challenge.Sign(signer, challenge.Ownership{
		Challenge: ch.ChallengeAgent, RegistrationID: ch.RegistrationID,
		Role: challenge.RoleAgent, AgentKeyThumbprint: thumbprint, OwnerDID: e.ownerDID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e.do(t, http.MethodPost, "/v1/agents/"+ch.RegistrationID+"/prove", api.ProofSubmission{
		Role: challenge.RoleAgent, Challenge: ch.ChallengeAgent, PublicJWK: jwk, Signature: sig,
	})
}

// TestRegistrationMintsOnlyWithBothProofs is the core of §8.2: one signature is
// never enough, in either order.
func TestRegistrationMintsOnlyWithBothProofs(t *testing.T) {
	e := setupReg(t)
	for _, tc := range []struct{ name, first string }{
		{"owner proves first", "owner"},
		{"agent proves first", "agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := e.open(t)
			signer, jwk, tp := agentKeypair(t)

			var firstRec, secondRec *httptest.ResponseRecorder
			if tc.first == "owner" {
				firstRec = e.proveOwner(t, ch, tp)
				secondRec = e.proveAgent(t, ch, signer, jwk, tp)
			} else {
				firstRec = e.proveAgent(t, ch, signer, jwk, tp)
				secondRec = e.proveOwner(t, ch, tp)
			}

			// The first proof must NOT mint. An identity minted on one signature
			// would let either party create an agent the other never agreed to.
			if firstRec.Code != http.StatusAccepted {
				t.Fatalf("first proof: got %d, want 202: %s", firstRec.Code, firstRec.Body)
			}
			var pending api.PendingRegistration
			if err := json.Unmarshal(firstRec.Body.Bytes(), &pending); err != nil {
				t.Fatal(err)
			}
			if pending.Status != "AWAITING_PROOF" {
				t.Errorf("first proof status = %q, want AWAITING_PROOF", pending.Status)
			}

			if secondRec.Code != http.StatusCreated {
				t.Fatalf("second proof: got %d, want 201: %s", secondRec.Code, secondRec.Body)
			}
			var minted api.RegisteredAgent
			if err := json.Unmarshal(secondRec.Body.Bytes(), &minted); err != nil {
				t.Fatal(err)
			}
			// §8.4: registration yields REGISTERED. Anything higher would claim
			// a credential chain nobody validated.
			if minted.Status != "REGISTERED" {
				t.Errorf("minted status = %q, want REGISTERED", minted.Status)
			}
			if minted.AssuranceLevel != "UAI-AL0" {
				t.Errorf("assurance = %q, want UAI-AL0", minted.AssuranceLevel)
			}
			if !strings.HasPrefix(minted.UAIID, "uai:agent:") || minted.DID != "did:"+minted.UAIID {
				t.Errorf("identifiers are inconsistent: %s / %s", minted.UAIID, minted.DID)
			}
			if minted.GenesisEventHash == "" {
				t.Error("minted identity has no genesis event hash to anchor its chain")
			}

			// The identity must be reachable the moment it is minted.
			rec := e.do(t, http.MethodGet, "/v1/agents/"+minted.UAIID, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET minted agent: got %d: %s", rec.Code, rec.Body)
			}
		})
	}
}

// TestOwnerCannotSupplyItsOwnKey is the difference between ownership being
// proven and ownership being declared.
func TestOwnerCannotSupplyItsOwnKey(t *testing.T) {
	e := setupReg(t)
	ch := e.open(t)
	_, _, tp := agentKeypair(t)

	// An attacker mints a key, claims to be the owner, and sends the key it
	// wants checked. If this were accepted, "owner_did" would mean nothing.
	impostor, pub, err := uaicrypto.GenerateEd25519Signer(e.ownerDID + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := challenge.Sign(impostor, challenge.Ownership{
		Challenge: ch.ChallengeOwner, RegistrationID: ch.RegistrationID,
		Role: challenge.RoleOwner, AgentKeyThumbprint: tp, OwnerDID: e.ownerDID,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, http.MethodPost, "/v1/agents/"+ch.RegistrationID+"/prove", api.ProofSubmission{
		Role: challenge.RoleOwner, Challenge: ch.ChallengeOwner, AgentKeyThumbprint: tp,
		PublicJWK: json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, b64url(pub))),
		Signature: sig,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("owner-supplied key: got %d, want 400: %s", rec.Code, rec.Body)
	}

	// And without the key, the same impostor signature simply fails to verify
	// against the owner key the registry holds.
	rec = e.do(t, http.MethodPost, "/v1/agents/"+ch.RegistrationID+"/prove", api.ProofSubmission{
		Role: challenge.RoleOwner, Challenge: ch.ChallengeOwner,
		AgentKeyThumbprint: tp, Signature: sig,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("impostor owner signature: got %d, want 401: %s", rec.Code, rec.Body)
	}
}

// TestProofsMustNameTheSameAgentKey covers UAI_PROOF_MISMATCH (§8.5).
func TestProofsMustNameTheSameAgentKey(t *testing.T) {
	e := setupReg(t)
	ch := e.open(t)
	_, _, vouchedFor := agentKeypair(t)
	otherSigner, otherJWK, otherTP := agentKeypair(t)

	if rec := e.proveOwner(t, ch, vouchedFor); rec.Code != http.StatusAccepted {
		t.Fatalf("owner proof: got %d: %s", rec.Code, rec.Body)
	}
	// A different agent, correctly proving control of ITS key, must not be able
	// to complete a registration the owner vouched for a different key in.
	rec := e.proveAgent(t, ch, otherSigner, otherJWK, otherTP)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched agent key: got %d, want 400: %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_PROOF_MISMATCH" {
		t.Errorf("title = %q, want UAI_PROOF_MISMATCH", title)
	}
}

// TestChallengeIsPerRole stops one half's challenge answering for the other.
func TestChallengeIsPerRole(t *testing.T) {
	e := setupReg(t)
	ch := e.open(t)
	signer, jwk, tp := agentKeypair(t)

	swapped := ch
	swapped.ChallengeAgent = ch.ChallengeOwner
	rec := e.proveAgent(t, swapped, signer, jwk, tp)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("agent answering the owner challenge: got %d, want 401: %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_CHALLENGE_INVALID" {
		t.Errorf("title = %q, want UAI_CHALLENGE_INVALID", title)
	}
}

// TestProofIsFinal: the party that goes first cannot change what it vouched for
// after seeing the other half.
func TestProofIsFinal(t *testing.T) {
	e := setupReg(t)
	ch := e.open(t)
	_, _, tp := agentKeypair(t)

	if rec := e.proveOwner(t, ch, tp); rec.Code != http.StatusAccepted {
		t.Fatalf("first owner proof: got %d: %s", rec.Code, rec.Body)
	}
	rec := e.proveOwner(t, ch, tp)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second owner proof: got %d, want 409: %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_PROOF_FINAL" {
		t.Errorf("title = %q, want UAI_PROOF_FINAL", title)
	}
}

// TestProofCannotBeReplayedAcrossRegistrations: the statement names its own
// registration, so a valid proof is valid in exactly one place.
func TestProofCannotBeReplayedAcrossRegistrations(t *testing.T) {
	e := setupReg(t)
	first, second := e.open(t), e.open(t)
	_, _, tp := agentKeypair(t)

	sig, err := challenge.Sign(e.owner, challenge.Ownership{
		Challenge: first.ChallengeOwner, RegistrationID: first.RegistrationID,
		Role: challenge.RoleOwner, AgentKeyThumbprint: tp, OwnerDID: e.ownerDID,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same signature, aimed at the other registration. It fails on the challenge
	// first; even with the right challenge it would fail on the registration id
	// inside the signed bytes.
	rec := e.do(t, http.MethodPost, "/v1/agents/"+second.RegistrationID+"/prove", api.ProofSubmission{
		Role: challenge.RoleOwner, Challenge: first.ChallengeOwner,
		AgentKeyThumbprint: tp, Signature: sig,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed proof: got %d, want 401: %s", rec.Code, rec.Body)
	}

	sigWithOtherChallenge, err := challenge.Sign(e.owner, challenge.Ownership{
		Challenge: second.ChallengeOwner, RegistrationID: first.RegistrationID,
		Role: challenge.RoleOwner, AgentKeyThumbprint: tp, OwnerDID: e.ownerDID,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec = e.do(t, http.MethodPost, "/v1/agents/"+second.RegistrationID+"/prove", api.ProofSubmission{
		Role: challenge.RoleOwner, Challenge: second.ChallengeOwner,
		AgentKeyThumbprint: tp, Signature: sigWithOtherChallenge,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("proof bound to another registration: got %d, want 401: %s", rec.Code, rec.Body)
	}
}

// TestRegistrationRejectsIneligibleOwners covers UAI_OWNER_NOT_ELIGIBLE and
// UAI_OWNER_RESTRICTED (§8.5).
func TestRegistrationRejectsIneligibleOwners(t *testing.T) {
	e := setupReg(t)

	rec := e.do(t, http.MethodPost, "/v1/agents", api.RegistrationRequest{
		LogicalName: "Ghost", AgentType: "autonomous_task_agent",
		OwnerDID: "did:uai:owner:" + ulid("Z"), PrimaryJurisdiction: "AR",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown owner: got %d, want 403: %s", rec.Code, rec.Body)
	}
	// An unknown owner and an ineligible one answer the same way on purpose:
	// telling
	// them apart would make this endpoint an owner-enumeration oracle.
	if title := problemTitle(t, rec); title != "UAI_OWNER_NOT_ELIGIBLE" {
		t.Errorf("title = %q, want UAI_OWNER_NOT_ELIGIBLE", title)
	}

	ctx := context.Background()
	restrictedID, restrictedDID := "own-"+ulid("W"), "did:uai:owner:"+ulid("W")
	if err := e.db.CreateOwner(ctx, store.Owner{
		ID: restrictedID, UAIID: "uai:owner:" + ulid("W"), DID: restrictedDID,
		DisplayName: "Restricted Ops", Jurisdiction: "AR"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Pool().Exec(ctx,
		`UPDATE owners SET restrictions = ARRAY['NEW_REGISTRATIONS'], restricted_at = now() WHERE id = $1`,
		restrictedID); err != nil {
		t.Fatal(err)
	}
	rec = e.do(t, http.MethodPost, "/v1/agents", api.RegistrationRequest{
		LogicalName: "Blocked", AgentType: "autonomous_task_agent",
		OwnerDID: restrictedDID, PrimaryJurisdiction: "AR",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("restricted owner: got %d, want 403: %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_OWNER_RESTRICTED" {
		t.Errorf("title = %q, want UAI_OWNER_RESTRICTED", title)
	}
}

// TestExpiredChallengeIsRefused covers the 300 s window of §8.2.
func TestExpiredChallengeIsRefused(t *testing.T) {
	e := setupReg(t)
	ch := e.open(t)
	_, _, tp := agentKeypair(t)

	// The draft cannot be back-dated -- the schema forbids editing it, which is
	// itself the point -- so expiry is exercised by moving the server's clock
	// past the window instead.
	late := api.NewServer(e.db, api.WithScheme("http"),
		api.WithClock(func() time.Time { return time.Now().Add(2 * api.ChallengeTTL) })).Routes()
	sig, err := challenge.Sign(e.owner, challenge.Ownership{
		Challenge: ch.ChallengeOwner, RegistrationID: ch.RegistrationID,
		Role: challenge.RoleOwner, AgentKeyThumbprint: tp, OwnerDID: e.ownerDID,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := e.doOn(t, late, http.MethodPost, "/v1/agents/"+ch.RegistrationID+"/prove",
		api.ProofSubmission{
			Role: challenge.RoleOwner, Challenge: ch.ChallengeOwner,
			AgentKeyThumbprint: tp, Signature: sig,
		})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired challenge: got %d, want 401: %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_CHALLENGE_INVALID" {
		t.Errorf("title = %q, want UAI_CHALLENGE_INVALID", title)
	}
}

// TestProveRejectsAUAIID: no UAI-ID exists until both proofs verify, so passing
// one here is always a caller mistake and must say so rather than 404.
func TestProveRejectsAUAIID(t *testing.T) {
	e := setupReg(t)
	rec := e.do(t, http.MethodPost, "/v1/agents/uai:agent:"+ulid("A")+"/prove", api.ProofSubmission{
		Role: challenge.RoleOwner, Challenge: "x",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("UAI-ID at prove: got %d, want 400: %s", rec.Code, rec.Body)
	}
	if title := problemTitle(t, rec); title != "UAI_MALFORMED_IDENTIFIER" {
		t.Errorf("title = %q, want UAI_MALFORMED_IDENTIFIER", title)
	}
}

// TestRegistrationDraftIsImmutable: the terms both parties sign against cannot
// be rewritten underneath them.
func TestRegistrationDraftIsImmutable(t *testing.T) {
	e := setupReg(t)
	ch := e.open(t)
	ctx := context.Background()

	for _, tc := range []struct{ name, sql string }{
		{"expiry cannot be extended",
			`UPDATE registrations SET expires_at = now() + interval '1 day' WHERE id = $1`},
		{"a challenge cannot be swapped",
			`UPDATE registrations SET challenge_owner = 'attacker-chosen' WHERE id = $1`},
		{"the owner cannot be changed",
			`UPDATE registrations SET owner_did = 'did:uai:owner:01ZZZZZZZZZZZZZZZZZZZZZZZZ' WHERE id = $1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.db.Pool().Exec(ctx, tc.sql, ch.RegistrationID); err == nil {
				t.Fatal("the draft was edited; it must be refused")
			}
		})
	}
}

// TestMintedIdentityAnchorsItsChain: the genesis hash is not decoration. It is
// what the agent's first attestation must reference, so a verifier walking
// backwards from any action reaches registration through an unbroken path.
func TestMintedIdentityAnchorsItsChain(t *testing.T) {
	e := setupReg(t)
	ch := e.open(t)
	signer, jwk, tp := agentKeypair(t)
	if rec := e.proveOwner(t, ch, tp); rec.Code != http.StatusAccepted {
		t.Fatalf("owner proof: %s", rec.Body)
	}
	rec := e.proveAgent(t, ch, signer, jwk, tp)
	if rec.Code != http.StatusCreated {
		t.Fatalf("agent proof: %s", rec.Body)
	}
	var minted api.RegisteredAgent
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	agent, err := e.db.AgentByUAIID(ctx, minted.UAIID)
	if err != nil {
		t.Fatal(err)
	}
	head, err := e.db.ChainHead(ctx, agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if head.Hash != minted.GenesisEventHash {
		t.Errorf("chain head = %s, want the genesis hash %s", head.Hash, minted.GenesisEventHash)
	}
	if head.Sequence != 0 {
		t.Errorf("a freshly minted identity is at sequence %d, want 0", head.Sequence)
	}

	// The commitment must be openable. One whose salt was discarded could never
	// be tied back to the identity it supposedly commits to.
	var salt []byte
	if err := e.db.Pool().QueryRow(ctx,
		`SELECT identity_commitment_salt FROM agents WHERE id = $1`, agent.ID).Scan(&salt); err != nil {
		t.Fatal(err)
	}
	if len(salt) != uaicrypto.SaltLen {
		t.Fatalf("commitment salt is %d bytes, want %d", len(salt), uaicrypto.SaltLen)
	}

	// The agent's key must resolve, or nothing it ever signs can be verified.
	rows, err := e.db.AgentKeys(ctx, agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("minted identity has %d keys, want 1", len(rows))
	}
	stored, err := uaicrypto.ParseJWK(rows[0].PublicJWK)
	if err != nil {
		t.Fatal(err)
	}
	storedTP, err := stored.ThumbprintString()
	if err != nil {
		t.Fatal(err)
	}
	// The key that was vouched for is the key that was stored. Anything else
	// would mean the identity answers to a key nobody proved control of.
	if storedTP != tp {
		t.Errorf("stored key %s is not the key both parties proved: %s", storedTP, tp)
	}
}

// TestRegistrationIssuesBothCredentials covers §8.2: an identity and its
// credentials are created in one step.
func TestRegistrationIssuesBothCredentials(t *testing.T) {
	e := setupReg(t)
	ch := e.open(t)
	signer, jwk, tp := agentKeypair(t)
	if rec := e.proveOwner(t, ch, tp); rec.Code != http.StatusAccepted {
		t.Fatalf("owner proof: %s", rec.Body)
	}
	rec := e.proveAgent(t, ch, signer, jwk, tp)
	if rec.Code != http.StatusCreated {
		t.Fatalf("agent proof: %s", rec.Body)
	}
	var minted api.RegisteredAgent
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}

	rec = e.do(t, http.MethodGet, "/v1/agents/"+minted.UAIID+"/credentials", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET credentials: %d %s", rec.Code, rec.Body)
	}
	var set api.AgentCredentials
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Credentials) != 2 {
		t.Fatalf("got %d credentials, want 2", len(set.Credentials))
	}

	byType := map[string]credential.Credential{}
	for _, raw := range set.Credentials {
		var c credential.Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		// Every credential must verify against the issuer that signed it.
		if err := credential.Verify(e.issuerPub, c); err != nil {
			t.Errorf("%v does not verify: %v", c.Type, err)
		}
		byType[c.Type[1]] = c
	}
	for _, want := range []string{credential.TypeIdentity, credential.TypeOwnership} {
		if _, ok := byType[want]; !ok {
			t.Fatalf("no %s was issued", want)
		}
	}

	identity, err := credential.IdentityFrom(byType[credential.TypeIdentity])
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID != minted.DID {
		t.Errorf("identity credential names %s, want %s", identity.ID, minted.DID)
	}
	if identity.AgentKeyThumbprint != tp {
		t.Errorf("identity credential names key %s, want %s", identity.AgentKeyThumbprint, tp)
	}
	// §8.4 again, this time in the document a relying party actually reads.
	if identity.AssuranceLevel != "UAI-AL0" {
		t.Errorf("assurance %q, want UAI-AL0", identity.AssuranceLevel)
	}
}

// TestOwnershipCredentialStandsAlone is the §6.4.1 promise, end to end: a
// relying party validates ownership from the document and the owner's key,
// without asking UAI anything.
func TestOwnershipCredentialStandsAlone(t *testing.T) {
	e := setupReg(t)
	ch := e.open(t)
	signer, jwk, tp := agentKeypair(t)
	if rec := e.proveOwner(t, ch, tp); rec.Code != http.StatusAccepted {
		t.Fatalf("owner proof: %s", rec.Body)
	}
	rec := e.proveAgent(t, ch, signer, jwk, tp)
	if rec.Code != http.StatusCreated {
		t.Fatalf("agent proof: %s", rec.Body)
	}
	var minted api.RegisteredAgent
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	rec = e.do(t, http.MethodGet, "/v1/agents/"+minted.UAIID+"/credentials", nil)
	var set api.AgentCredentials
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}

	var ownership credential.Credential
	for _, raw := range set.Credentials {
		var c credential.Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		if c.Type[1] == credential.TypeOwnership {
			ownership = c
		}
	}
	subject, err := credential.OwnershipFrom(ownership)
	if err != nil {
		t.Fatal(err)
	}

	// The owner's public key, as a relying party would obtain it from the
	// owner. Nothing from UAI is consulted below this line.
	ownerPub := e.owner.Public()
	if err := credential.VerifyOwnership(subject, ownerPub); err != nil {
		t.Fatalf("the embedded two-sided proof must verify standalone: %v", err)
	}
	if subject.ID != minted.DID {
		t.Errorf("ownership credential names %s, want %s", subject.ID, minted.DID)
	}
	if subject.OwnerDID != e.ownerDID {
		t.Errorf("ownership credential names owner %s, want %s", subject.OwnerDID, e.ownerDID)
	}
	if ownership.ValidUntil != nil {
		t.Error("ownership must hold until unbound, not until a date nobody chose")
	}

	// And a relying party holding the WRONG owner key must not be convinced.
	_, other, err := uaicrypto.GenerateEd25519Signer(e.ownerDID + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.VerifyOwnership(subject, other); err == nil {
		t.Error("the ownership proof verified against a key the owner does not hold")
	}
}
