package api_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/internal/pdp"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/internal/translog"
	"github.com/rodmontiel/uai/pkg/attest"
	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/receipt"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

var seq atomic.Int64

func init() {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	seq.Store(int64(binary.BigEndian.Uint64(b[:]) % 1_000_000_000_000_000_000))
}

func ulid(prefix string) string {
	// The first character must be <= '7': a ULID's leading character encodes
	// only two bits, so anything higher overflows 128 bits and is rejected.
	return fmt.Sprintf("0%s%024d", strings.ToUpper(prefix), seq.Add(1))
}

func nonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

type env struct {
	db         *store.DB
	srv        http.Handler
	agent      store.Agent
	signer     uaicrypto.Signer
	ownerID    string
	pdpPub     any
	bundle     *pdp.Bundle
	tlog       *translog.Log
	logPub     any
	witnessPub any
}

func setup(t *testing.T) *env {
	t.Helper()
	dsn := os.Getenv("UAI_TEST_DSN")
	if dsn == "" {
		t.Skip("UAI_TEST_DSN not set; skipping API integration tests")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("UAI_TEST_DSN is set but the database is unusable: %v", err)
	}
	t.Cleanup(db.Close)

	orgID, ownerID, agentID := "org-"+ulid("O"), "own-"+ulid("W"), "ag-"+ulid("A")
	if err := db.CreateOrganization(ctx, store.Organization{
		ID: orgID, DID: "did:web:acme-" + strings.ToLower(orgID) + ".example",
		LegalName: "ACME Robotics", Jurisdiction: "AR"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateOwner(ctx, store.Owner{
		ID: ownerID, UAIID: "uai:owner:" + ulid("W"), DID: "did:uai:owner:" + ulid("W"),
		OrganizationID: orgID, DisplayName: "ACME Ops", Jurisdiction: "AR"}); err != nil {
		t.Fatal(err)
	}

	agentULID := ulid("A")
	agent := store.Agent{
		ID: agentID, UAIID: "uai:agent:" + agentULID, DID: "did:uai:agent:" + agentULID,
		OwnerID: ownerID, OrganizationID: orgID, LogicalName: "DeliveryOptimizer",
		AgentType: "autonomous_task_agent", PrimaryJurisdiction: "AR", AssuranceLevel: "UAI-AL2",
		IdentityCommitment: "sha256:" + strings.Repeat("a", 64), PolicyVersion: "GASC-2027.4",
		GenesisEventHash: "sha256:" + strings.Repeat("b", 64), Status: "ACTIVE",
	}
	signer, pub, err := uaicrypto.GenerateEd25519Signer(agent.DID + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	jwk := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, b64url(pub))
	if err := db.CreateAgent(ctx, agent, store.AgentKey{
		ID: "key-" + ulid("K"), KeyID: "key-1", Alg: "EdDSA",
		PublicJWK: json.RawMessage(jwk), Protection: "TPM2",
		ValidFrom: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// §6.10: ACTIVE means a runtime is bound. A fixture that claimed ACTIVE with
	// nothing bound described a state the protocol does not have, and the policy
	// engine noticed before we did.
	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO runtime_identities (id, agent_id, spiffe_id, cert_hash, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		"rt-"+ulid("R"), agent.ID,
		"spiffe://uai.test/agents/"+agent.UAIID+"/i/"+nonce()[:8],
		"sha256:"+strings.Repeat("d", 64), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	issuer, issuerPub, err := uaicrypto.GenerateEd25519Signer("did:web:pdp.uai.test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := pdp.LoadAuthorityFile("../../policy/authority.json")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := pdp.Load(ctx, os.DirFS("../../policy/gasc-2027.4"), auth,
		time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("the committed bundle must load: %v", err)
	}
	logSigner, logPub, err := uaicrypto.GenerateEd25519Signer("did:web:log.uai.test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	wSigner, wPub, err := uaicrypto.GenerateEd25519Signer("did:web:witness-0.uai.test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	witness := translog.NewWitness("witness-0", wSigner)
	tlog, err := translog.Open(ctx, db, "uai.test/log/"+ulid("L"), logSigner,
		translog.WithWitnesses(1, witness))
	if err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(db, api.WithScheme("http"),
		api.WithIssuer("did:web:pdp.uai.test", issuer), api.WithBundle(bundle),
		api.WithTransparency(tlog))
	return &env{db: db, srv: srv.Routes(), agent: agent, signer: signer, ownerID: ownerID,
		pdpPub: issuerPub, bundle: bundle, tlog: tlog, logPub: logPub, witnessPub: wPub}
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (e *env) attestation(t *testing.T, prev string, seqNo int64) attest.Attestation {
	t.Helper()
	a := attest.Attestation{
		UAIVersion: attest.Version, EventID: ulid("E"),
		AgentDID: e.agent.DID, OwnerDID: "did:uai:owner:" + ulid("W"),
		Timestamp: time.Now().UTC(), Nonce: nonce(),
		Action:  attest.Action{Type: "route.optimize", Capability: "route.optimize"},
		Purpose: "delivery_optimization",
		Jurisdiction: attest.Jurisdiction{
			Origin: "AR", Targets: []string{}, CrossBorder: false, Basis: "owner_jurisdiction"},
		Policy: attest.Policy{Version: "GASC-2027.4",
			BundleHash: "sha256:" + strings.Repeat("c", 64),
			DecisionID: ulid("D"), Decision: "ALLOW"},
		Outcome: attest.OutcomeSuccess, PreviousEventHash: prev, Sequence: seqNo,
	}
	signed, err := attest.Sign(e.signer, a)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// post signs and sends an attestation. idemKey may be reused to test retries.
func (e *env) post(t *testing.T, a attest.Attestation, idemKey string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://api.uai.test/v1/actions/attest", strings.NewReader(string(body)))
	req.Header.Set("Idempotency-Key", idemKey)
	if err := pop.SignRequest(e.signer, req, body, uaicrypto.DomainAttestation, e.agent.UAIID, nonce()); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	return rec
}

// postSigned issues a PoP-signed JSON request to this env's own server.
func (e *env) postSigned(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return e.postSignedTo(t, e.srv, path, body)
}

// postSignedDomain signs under a specific PoP domain.
func (e *env) postSignedDomain(t *testing.T, path string, body any, domain uaicrypto.Domain) *httptest.ResponseRecorder {
	t.Helper()
	return e.postSignedDomainTo(t, e.srv, path, body, domain)
}

func (e *env) postSignedDomainTo(t *testing.T, srv http.Handler, path string, body any,
	domain uaicrypto.Domain) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://api.uai.test"+path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "idem-"+nonce())
	if err := pop.SignRequest(e.signer, req, raw, domain, e.agent.UAIID, nonce()); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// postUnsigned sends without proof of possession.
func (e *env) postUnsigned(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://api.uai.test"+path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	return rec
}

// postSignedTo signs with THIS env's agent key but sends to another server, so
// a test can check that holding a valid key is not permission to act for
// somebody else.
func (e *env) postSignedTo(t *testing.T, srv http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://api.uai.test"+path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "idem-"+nonce())
	if err := pop.SignRequest(e.signer, req, raw, uaicrypto.DomainChallenge, e.agent.UAIID, nonce()); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func problemTitle(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p api.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("response is not a problem document: %s", rec.Body.String())
	}
	return p.Title
}

func TestAttestAdvancesTheChain(t *testing.T) {
	e := setup(t)
	prev := e.agent.GenesisEventHash
	// Registration occupies sequence 1 (§9.4), so the first action is 2. The
	// client does not guess this: it reads the head and adds one.
	for i := int64(2); i <= 4; i++ {
		rec := e.post(t, e.attestation(t, prev, i), "idem-"+ulid("I"))
		if rec.Code != http.StatusCreated {
			t.Fatalf("attest %d: status %d, body %s", i, rec.Code, rec.Body.String())
		}
		var out struct {
			EventHash string `json:"event_hash"`
			Sequence  int64  `json:"sequence"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Sequence != i {
			t.Fatalf("sequence = %d, want %d", out.Sequence, i)
		}
		prev = out.EventHash
	}
	if err := e.db.VerifyChain(context.Background(), e.agent.ID); err != nil {
		t.Fatalf("chain should verify: %v", err)
	}
}

func TestUnsignedRequestRejected(t *testing.T) {
	e := setup(t)
	a := e.attestation(t, e.agent.GenesisEventHash, 2)
	body, _ := json.Marshal(a)
	req := httptest.NewRequest(http.MethodPost, "http://api.uai.test/v1/actions/attest", strings.NewReader(string(body)))
	req.Header.Set("Idempotency-Key", "idem-"+ulid("I"))
	// A well-formed, correctly signed ATTESTATION is still not a signed REQUEST.
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || problemTitle(t, rec) != "UAI_POP_REQUIRED" {
		t.Fatalf("status %d, title %s", rec.Code, problemTitle(t, rec))
	}
}

func TestAttestingForAnotherAgentRejected(t *testing.T) {
	e := setup(t)
	a := e.attestation(t, e.agent.GenesisEventHash, 2)
	// Re-sign the attestation body under a different declared identity. The
	// request signature is still ours, so this is precisely the case where
	// trusting the body would make attribution a string comparison.
	a.AgentDID = "did:uai:agent:" + ulid("Z")
	resigned, err := attest.Sign(e.signer, a)
	if err != nil {
		t.Fatal(err)
	}
	rec := e.post(t, resigned, "idem-"+ulid("I"))
	if rec.Code != http.StatusForbidden || problemTitle(t, rec) != "UAI_IDENTITY_MISMATCH" {
		t.Fatalf("status %d, title %s, body %s", rec.Code, problemTitle(t, rec), rec.Body.String())
	}
}

func TestByteIdenticalResendIsAReplay(t *testing.T) {
	// A retry must re-sign. Resending the exact same bytes reuses the RFC 9421
	// nonce, and a nonce is single-use by construction.
	e := setup(t)
	a := e.attestation(t, e.agent.GenesisEventHash, 2)
	body, _ := json.Marshal(a)
	key := "idem-" + ulid("I")
	reqNonce := nonce()

	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://api.uai.test/v1/actions/attest", strings.NewReader(string(body)))
		req.Header.Set("Idempotency-Key", key)
		if err := pop.SignRequest(e.signer, req, body, uaicrypto.DomainAttestation, e.agent.UAIID, reqNonce); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		e.srv.ServeHTTP(rec, req)
		return rec
	}
	if rec := send(); rec.Code != http.StatusCreated {
		t.Fatalf("first send: %d %s", rec.Code, rec.Body.String())
	}
	rec := send()
	if rec.Code != http.StatusUnauthorized || problemTitle(t, rec) != "UAI_REPLAY_DETECTED" {
		t.Fatalf("a byte-identical resend should be a replay: %d %s", rec.Code, rec.Body.String())
	}
}

func TestResignedRetryReplaysTheOriginalResponse(t *testing.T) {
	// The documented retry pattern: same body, same Idempotency-Key, FRESH
	// signature and nonce. The effect happens once and the caller sees the
	// original response.
	e := setup(t)
	a := e.attestation(t, e.agent.GenesisEventHash, 2)
	key := "idem-" + ulid("I")

	first := e.post(t, a, key)
	if first.Code != http.StatusCreated {
		t.Fatalf("first: %d %s", first.Code, first.Body.String())
	}
	second := e.post(t, a, key)
	if second.Code != http.StatusCreated {
		t.Fatalf("retry: %d %s", second.Code, second.Body.String())
	}
	if second.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("the retry was not marked as a replay")
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("the retry returned a different response:\n%s\n%s", first.Body.String(), second.Body.String())
	}
	// And exactly one event exists.
	head, err := e.db.ChainHead(context.Background(), e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 2, not 1: registration is sequence 1 and the single action is 2. A second
	// event would put the head at 3.
	if head.Sequence != 2 {
		t.Fatalf("the retry created a second event: sequence %d", head.Sequence)
	}
}

func TestStaleChainHeadReturnsTheCurrentHead(t *testing.T) {
	e := setup(t)
	prev := e.agent.GenesisEventHash
	if rec := e.post(t, e.attestation(t, prev, 2), "idem-"+ulid("I")); rec.Code != http.StatusCreated {
		t.Fatalf("setup attest: %d %s", rec.Code, rec.Body.String())
	}
	rec := e.post(t, e.attestation(t, prev, 2), "idem-"+ulid("I"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var p api.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Title != "UAI_CHAIN_CONFLICT" || p.ChainHead == nil {
		t.Fatalf("a conflict must carry the current head: %s", rec.Body.String())
	}
	if p.ChainHead.Sequence != 2 {
		t.Fatalf("head sequence = %d, want 2", p.ChainHead.Sequence)
	}
}

func TestRevokedIdentityCannotAttest(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if rec := e.post(t, e.attestation(t, e.agent.GenesisEventHash, 2), "idem-"+ulid("I")); rec.Code != http.StatusCreated {
		t.Fatalf("setup attest: %d %s", rec.Code, rec.Body.String())
	}
	head, err := e.db.ChainHead(ctx, e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetAgentStatus(ctx, e.agent.ID, "REVOKED", time.Now()); err != nil {
		t.Fatal(err)
	}
	rec := e.post(t, e.attestation(t, head.Hash, 3), "idem-"+ulid("I"))
	if rec.Code != http.StatusForbidden || problemTitle(t, rec) != "UAI_IDENTITY_REVOKED" {
		t.Fatalf("status %d, title %s", rec.Code, problemTitle(t, rec))
	}
}

func TestVerifyEndpointIsAlwaysAnswerable(t *testing.T) {
	e := setup(t)
	cases := map[string]struct{ path, status string }{
		"known agent":        {"/v1/verify/" + e.agent.UAIID, "UAI_VERIFIED"},
		"unknown identifier": {"/v1/verify/uai:agent:0000000000000000000000000Z", "UAI_UNVERIFIED"},
		"malformed":          {"/v1/verify/not-an-identifier", "UAI_UNVERIFIED"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://api.uai.test"+c.path, nil)
			rec := httptest.NewRecorder()
			e.srv.ServeHTTP(rec, req)
			// Always 200: reporting "not found" would invite the reading that
			// silence means something.
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
			var out struct {
				Status   string `json:"status"`
				Verified bool   `json:"verified"`
				Note     string `json:"note"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.Status != c.status {
				t.Fatalf("status = %s, want %s", out.Status, c.status)
			}
			if c.status == "UAI_UNVERIFIED" && !strings.Contains(out.Note, "not an assertion") {
				t.Fatalf("an unverified answer must say it is not an accusation: %q", out.Note)
			}
		})
	}
}

func TestRevokedIdentityStillVerifiesAsRevoked(t *testing.T) {
	// INV-006: a revoked identity keeps its history and stays resolvable. It
	// answers REVOKED, not "not found".
	e := setup(t)
	if err := e.db.SetAgentStatus(context.Background(), e.agent.ID, "REVOKED", time.Now()); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://api.uai.test/v1/verify/"+e.agent.UAIID, nil)
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	var out struct {
		Status   string `json:"status"`
		Revoked  bool   `json:"revoked"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "UAI_REVOKED" || !out.Revoked || out.Verified {
		t.Fatalf("unexpected verification result: %s", rec.Body.String())
	}
}

func TestIdempotencyKeyRequired(t *testing.T) {
	e := setup(t)
	a := e.attestation(t, e.agent.GenesisEventHash, 2)
	body, _ := json.Marshal(a)
	req := httptest.NewRequest(http.MethodPost, "http://api.uai.test/v1/actions/attest", strings.NewReader(string(body)))
	if err := pop.SignRequest(e.signer, req, body, uaicrypto.DomainAttestation, e.agent.UAIID, nonce()); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || problemTitle(t, rec) != "UAI_IDEMPOTENCY_KEY_REQUIRED" {
		t.Fatalf("status %d, title %s", rec.Code, problemTitle(t, rec))
	}
}

// TestAttestationGetsATransparencyReceipt: the response carries evidence a
// third party can check without asking us anything (§18.1).
func TestAttestationGetsATransparencyReceipt(t *testing.T) {
	e := setup(t)
	head, err := e.db.ChainHead(context.Background(), e.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	a := e.attestation(t, head.Hash, head.Sequence+1)
	rec := e.post(t, a, "idem-"+ulid("I"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("attest: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Transparency string          `json:"transparency"`
		Receipt      receipt.Receipt `json:"receipt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Transparency != "LOGGED" {
		t.Fatalf("transparency = %q, want LOGGED", out.Transparency)
	}

	// The statement a verifier holds is the signed attestation, canonicalized.
	// A verifier that re-serialized it any other way would compute a different
	// leaf; RFC 8785 is what makes "the same statement" mean the same bytes on
	// every machine that ever handles it.
	statement, err := uaicrypto.Canonicalize(a)
	if err != nil {
		t.Fatal(err)
	}
	anchors := receipt.TrustAnchors{
		LogKeys:      map[string]any{"did:web:log.uai.test#key-1": e.logPub},
		WitnessKeys:  map[string]any{"witness-0": e.witnessPub},
		MinWitnesses: 1,
	}
	status, err := receipt.Verify(out.Receipt, statement, anchors)
	if err != nil {
		t.Fatalf("the receipt must verify offline: %v", err)
	}
	// No anchor yet: the ledger writer has not run. VERIFIED_UNANCHORED is the
	// strongest truthful answer in that window, and claiming VERIFIED would be
	// asserting durability nobody has provided.
	if status != receipt.StatusVerifiedUnanchored {
		t.Errorf("status = %s, want VERIFIED_UNANCHORED", status)
	}

	// And it is persisted, so /v1/actions/{id} can hand it back later.
	var stored int
	if err := e.db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM transparency_receipts WHERE subject_id = $1`, a.EventID).
		Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Errorf("%d receipts stored for %s, want 1", stored, a.EventID)
	}
}

// getJSON performs an unauthenticated GET and decodes the body.
func (e *env) getJSON(t *testing.T, path string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://api.uai.test"+path, nil)
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: %v\n%s", path, err, rec.Body)
		}
	}
	return rec.Code
}

// postJSON performs an unsigned POST and returns the response, so a test can
// assert on a refusal rather than only on a success.
func (e *env) postJSON(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://api.uai.test"+path,
		strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "test-"+nonce())
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	return rec.Result()
}
