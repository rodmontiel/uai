package api_test

// Negative tests for the security invariants of §20.3 that had none at this
// layer. Each one asserts that a FORBIDDEN operation fails; a test here that
// stops failing means a control is gone.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/governance"
	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

func b64urlDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// ── INV-001 · an identity is never "verified" without cryptographic proof ────
//
// /v1/verify is the whole product for a relying party: one unauthenticated GET
// whose answer they are asked to act on. "verified": true has to mean a key
// proved itself, not that a row exists.
//
// The path to true runs through exactly one state -- ACTIVE (§6.10) -- and
// ACTIVE is reached only by binding a runtime, which is behind proof of
// possession. These tests hold that path shut from both ends: an identity that
// has not bound is not verified, and binding without the right signature does
// not happen.

// registered creates an agent in REGISTERED: registration done, nothing proved.
func (e *env) registered(t *testing.T) store.Agent {
	agent, _ := e.registeredWithKey(t)
	return agent
}

// registeredWithKey also returns the agent's signer, for tests that have to act
// as the agent rather than merely look at it.
func (e *env) registeredWithKey(t *testing.T) (store.Agent, uaicrypto.Signer) {
	t.Helper()
	id := ulid("A")
	agent := store.Agent{
		ID: "ag-" + id, UAIID: "uai:agent:" + id, DID: "did:uai:agent:" + id,
		OwnerID: e.ownerID, OrganizationID: e.agent.OrganizationID,
		LogicalName: "UnprovenAgent", AgentType: "autonomous_task_agent",
		PrimaryJurisdiction: "AR", AssuranceLevel: "UAI-AL0",
		IdentityCommitment: "sha256:" + repeat64('a'), PolicyVersion: "GASC-2027.4",
		GenesisEventHash: "sha256:" + repeat64('b'), Status: "REGISTERED",
	}
	signer, pub, err := uaicrypto.GenerateEd25519Signer(agent.DID + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	jwk := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, b64url(pub))
	if err := e.db.CreateAgent(context.Background(), agent, store.AgentKey{
		ID: "key-" + ulid("K"), KeyID: "key-1", Alg: "EdDSA",
		PublicJWK: json.RawMessage(jwk), Protection: "SOFTWARE",
		ValidFrom: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return agent, signer
}

func (e *env) verifyVerdict(t *testing.T, uaiID string) map[string]any {
	t.Helper()
	out := map[string]any{}
	if code := e.getJSON(t, "/v1/verify/"+uaiID, &out); code != http.StatusOK {
		t.Fatalf("/v1/verify returned %d; it answers 200 for everything, including what it has never seen", code)
	}
	return out
}

func TestINV001_RegistrationAloneIsNotVerification(t *testing.T) {
	e := setup(t)
	agent := e.registered(t)

	out := e.verifyVerdict(t, agent.UAIID)
	if out["verified"] != false {
		t.Errorf("INV-001: an agent that has proved nothing reported verified=%v.\n"+
			"Registration is a claim. Only the binding that follows it is proof.", out["verified"])
	}
	if out["status"] != "UAI_REGISTERED" {
		t.Errorf("INV-001: status = %v, want UAI_REGISTERED", out["status"])
	}
}

func TestINV001_AnUnknownIdentifierIsNotVerified(t *testing.T) {
	e := setup(t)
	// Well-formed and never registered: the case where an absence of evidence
	// is most likely to be read as evidence.
	out := e.verifyVerdict(t, "uai:agent:"+ulid("Z"))
	if out["verified"] != false {
		t.Errorf("INV-001: an unknown identifier reported verified=%v", out["verified"])
	}
	if note, _ := out["note"].(string); !strings.Contains(note, "not an assertion") {
		t.Errorf("INV-001: an unverifiable identity must not read as an accusation.\nnote = %q", note)
	}
}

func TestINV001_BindingWithoutProofOfPossessionIsRefused(t *testing.T) {
	e := setup(t)
	agent := e.registered(t)

	body := `{"svid_spiffe_id":"spiffe://uai.test/attacker","svid_cert_hash":"sha256:` + repeat64('d') + `"}`
	req := httptest.NewRequest(http.MethodPost,
		"http://api.uai.test/v1/agents/"+agent.UAIID+"/bind", strings.NewReader(body))
	req.Header.Set("Idempotency-Key", nonce())
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("INV-001: an unsigned bind returned %d, want 401", rec.Code)
	}
	if out := e.verifyVerdict(t, agent.UAIID); out["verified"] != false {
		t.Errorf("INV-001: the agent became verified=%v after an unsigned bind", out["verified"])
	}
}

func TestINV001_BindingSignedByAnotherIdentityIsRefused(t *testing.T) {
	e := setup(t)
	agent := e.registered(t)

	// The env's own agent holds a real, registered, currently valid key. It is
	// the strongest attacker this layer faces: not a forged signature, a
	// genuine one made by somebody else.
	body := []byte(`{"svid_spiffe_id":"spiffe://uai.test/attacker","svid_cert_hash":"sha256:` +
		repeat64('d') + `"}`)
	req := httptest.NewRequest(http.MethodPost,
		"http://api.uai.test/v1/agents/"+agent.UAIID+"/bind", strings.NewReader(string(body)))
	req.Header.Set("Idempotency-Key", nonce())
	if err := pop.SignRequest(e.signer, req, body, uaicrypto.DomainChallenge,
		e.agent.UAIID, nonce()); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("INV-001: a bind signed by a DIFFERENT registered identity returned %d, want 403.\n"+
			"body: %s", rec.Code, rec.Body.String())
	}
	if out := e.verifyVerdict(t, agent.UAIID); out["verified"] != false {
		t.Errorf("INV-001: the agent became verified=%v on somebody else's signature", out["verified"])
	}
}

// ── INV-003 · no administrator can edit or delete evidence ───────────────────
//
// The database refuses it (test/invariants/invariants.sql). §20.3's first
// enforcement point is earlier and simpler: "No API path exists." That is a
// property of the source, so it is checked against the source -- a route or a
// query added in a hurry is exactly how this stops being true, and it would
// never show up in a behavioural test because nobody writes the test for a
// route they just added.

var (
	routeRE = regexp.MustCompile(`mux\.Handle\(\s*"([A-Z]+) ([^"]+)"`)
	// Deliberately loose: any write verb near either evidence table.
	evidenceWriteRE = regexp.MustCompile(`(?is)(UPDATE|DELETE\s+FROM|TRUNCATE)\s+(evidence_items|evidence_custody)`)
)

func goSourcesUnder(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[path] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no sources scanned; the check would pass by finding nothing")
	}
	return out
}

func TestINV003_NoAPIPathCanWriteEvidence(t *testing.T) {
	routes, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, m := range routeRE.FindAllStringSubmatch(string(routes), -1) {
		method, path := m[1], m[2]
		found++
		if !strings.Contains(path, "evidence") {
			continue
		}
		if method != http.MethodGet {
			t.Errorf("INV-003: %s %s is a write path to evidence.\n"+
				"Evidence is collected once and never edited: §20.3 says no API path exists.",
				method, path)
		}
	}
	if found == 0 {
		t.Fatal("no routes matched; the route pattern changed and this check stopped checking")
	}
	t.Logf("INV-003: %d routes audited, none writes evidence", found)
}

func TestINV003_NoServiceCodeUpdatesOrDeletesEvidence(t *testing.T) {
	for path, src := range goSourcesUnder(t, "..", "../../services", "../../pkg", "../../tools") {
		if m := evidenceWriteRE.FindString(src); m != "" {
			t.Errorf("INV-003: %s contains %q.\n"+
				"Crypto-shredding is the only write, and it belongs to the database\n"+
				"(evidence_items_shred_only), where the trigger can check that the\n"+
				"commitment survived. A statement here could not be.", path, strings.Join(strings.Fields(m), " "))
		}
	}
}

// ── INV-004 · no administrator can modify votes ──────────────────────────────
//
// The database refuses UPDATE and DELETE on votes, so the remaining move is to
// INSERT: file a row carrying an assertion the delegate really produced, beside
// a value they never cast.
//
// Nothing in the assertion itself objects. The delegate signed a digest, the
// digest is stored, and the two still agree. What breaks the attack is the
// tally rebuilding that digest from the statement it claims to represent --
// including the value -- and finding it different.
func TestINV004_AVoteValueCannotBeFiledBesideSomebodyElsesAssertion(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c := e.council(t, "AR", "DE", "JP")

	// A genuine NO from delegate 0, cast through the API.
	if resp := e.vote(t, c, 0, governance.VoteNo, true); resp.StatusCode != http.StatusCreated {
		t.Fatalf("an honest vote was refused: %d", resp.StatusCode)
	}

	// Delegate 1 signs NO -- really signs it, with their own authenticator.
	voteNonce := nonce()
	statement := governance.Statement{
		CaseID: c.caseID, Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: e.agent.DID, EvidenceDigest: c.evidence,
		DelegateDID: c.delegates[1], Value: governance.VoteNo, Nonce: voteNonce,
	}
	digest, err := statement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	assertion := c.auths[1].assert(digest, true)
	decode := func(k string) []byte {
		b, err := b64urlDecode(assertion[k].(string))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	// Filed as YES. Everything else about the row is true.
	var delegateID string
	if err := e.db.Pool().QueryRow(ctx,
		`SELECT id FROM human_delegates WHERE did = $1`, c.delegates[1]).Scan(&delegateID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Pool().Exec(ctx, `
		INSERT INTO votes (id, proposal_id, delegate_id, country_code, value, evidence_digest,
		                   vote_digest, authenticator_data, client_data_json, assertion_signature,
		                   user_verified, nonce)
		VALUES ($1,$2,$3,'DE','YES'::vote_value,$4,$5,$6,$7,$8,true,$9)`,
		"v-"+ulid("V"), c.proposalID, delegateID, c.evidence,
		uaicrypto.FormatDigest(digest), decode("authenticator_data"),
		decode("client_data_json"), decode("signature"), voteNonce); err != nil {
		t.Fatalf("the database accepted no such row, so this test proves nothing: %v", err)
	}

	// The tally must refuse to produce a number from a record it cannot stand behind.
	out := map[string]any{}
	code := e.getJSON(t, "/v1/governance/proposals/"+c.proposalID, &out)
	if code == http.StatusOK {
		tally, _ := out["tally"].(map[string]any)
		t.Fatalf("INV-004: the tally counted a value nobody voted for: %v\n"+
			"The assertion is genuine and the value beside it is not. A tally that\n"+
			"reads the value column has not recomputed anything.", tally)
	}
	t.Logf("INV-004: refused with %d", code)
}

// TestINV004_TheSameVoteFiledHonestlyStillCounts guards the test above from
// passing for the wrong reason: the refusal has to come from the mismatch, not
// from direct insertion being rejected outright.
func TestINV004_TheSameVoteFiledHonestlyStillCounts(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c := e.council(t, "AR", "DE", "JP")

	voteNonce := nonce()
	statement := governance.Statement{
		CaseID: c.caseID, Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: e.agent.DID, EvidenceDigest: c.evidence,
		DelegateDID: c.delegates[1], Value: governance.VoteNo, Nonce: voteNonce,
	}
	digest, err := statement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	assertion := c.auths[1].assert(digest, true)
	decode := func(k string) []byte {
		b, err := b64urlDecode(assertion[k].(string))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var delegateID string
	if err := e.db.Pool().QueryRow(ctx,
		`SELECT id FROM human_delegates WHERE did = $1`, c.delegates[1]).Scan(&delegateID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Pool().Exec(ctx, `
		INSERT INTO votes (id, proposal_id, delegate_id, country_code, value, evidence_digest,
		                   vote_digest, authenticator_data, client_data_json, assertion_signature,
		                   user_verified, nonce)
		VALUES ($1,$2,$3,'DE','NO'::vote_value,$4,$5,$6,$7,$8,true,$9)`,
		"v-"+ulid("V"), c.proposalID, delegateID, c.evidence,
		uaicrypto.FormatDigest(digest), decode("authenticator_data"),
		decode("client_data_json"), decode("signature"), voteNonce); err != nil {
		t.Fatal(err)
	}

	out := map[string]any{}
	if code := e.getJSON(t, "/v1/governance/proposals/"+c.proposalID, &out); code != http.StatusOK {
		t.Fatalf("an honestly filed vote was refused: %d", code)
	}
	tally, _ := out["tally"].(map[string]any)
	if n, _ := tally["no"].(float64); n != 1 {
		t.Errorf("tally.no = %v, want 1 -- %v", tally["no"], tally)
	}
}
