package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/governance"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// authenticator is a software stand-in for a delegate's hardware token.
//
// It cannot demonstrate INV-005 — that rests on a human gesture no test can
// perform. What it demonstrates is the half that lives here: that the gateway
// recomputes the vote digest, checks the assertion against the credential the
// delegate registered, and refuses one whose user-verified flag is clear.
type authenticator struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	rpID  string
	count uint32
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{priv: priv, pub: pub, rpID: api.DefaultGovernanceRPID}
}

func (a *authenticator) jwk() json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`,
		base64.RawURLEncoding.EncodeToString(a.pub)))
}

func (a *authenticator) assert(challenge []byte, userVerified bool) map[string]any {
	rp := sha256.Sum256([]byte(a.rpID))
	var flags byte = 0x01
	if userVerified {
		flags |= 0x04
	}
	a.count++
	authData := append(append([]byte{}, rp[:]...), flags,
		byte(a.count>>24), byte(a.count>>16), byte(a.count>>8), byte(a.count))
	clientData := []byte(`{"type":"webauthn.get","challenge":"` +
		base64.RawURLEncoding.EncodeToString(challenge) +
		`","origin":"` + api.DefaultGovernanceOrigin + `","crossOrigin":false}`)
	sum := sha256.Sum256(clientData)
	signature := ed25519.Sign(a.priv, append(append([]byte{}, authData...), sum[:]...))
	return map[string]any{
		"authenticator_data": base64.RawURLEncoding.EncodeToString(authData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(clientData),
		"signature":          base64.RawURLEncoding.EncodeToString(signature),
		"user_verified":      userVerified,
	}
}

// nextCase allocates a case identifier after the highest one on file.
func nextCase(t *testing.T, e *env) string {
	t.Helper()
	var highest int
	if err := e.db.Pool().QueryRow(context.Background(),
		`SELECT coalesce(max(substring(id from 9)::int), 0) FROM harm_cases
		  WHERE id ~ '^UAI-INC-[0-9]{6}$'`).Scan(&highest); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("UAI-INC-%06d", highest+1)
}

// council appoints delegates and opens a proposal against this env's agent.
type council struct {
	proposalID string
	caseID     string
	evidence   string
	delegates  []string
	auths      []*authenticator
}

func (e *env) council(t *testing.T, countries ...string) council {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	c := council{
		// Continued from what the database already holds, not from 1. A counter
		// that restarted each process would collide with the previous run's
		// cases, and a test that only passes against a fresh database is a test
		// that will fail for a reason nobody is looking for.
		caseID:   nextCase(t, e),
		evidence: "sha256:" + repeat64('e'),
	}
	if err := e.db.OpenCase(ctx, store.NewCase{
		ID: c.caseID, AgentID: e.agent.ID, OwnerID: e.ownerID,
		Summary:        "reached infrastructure outside its declared scope",
		HarmCategories: []string{"UNAUTHORIZED_ACCESS"}, EvidenceDigest: c.evidence,
		OpenedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	for _, country := range countries {
		auth := newAuthenticator(t)
		// ulid() is the suite's unique-identifier helper: a fresh value per
		// call, so two councils never share a delegate. Sharing one would also
		// be one human voting on two proposals about one agent, which is not
		// the thing under test here.
		id := ulid("D")
		did := "did:uai:delegate:" + id
		if _, err := e.db.Pool().Exec(ctx, `
			INSERT INTO country_members (code, did, display_name, credential_hash)
			VALUES ($1, $2, $3, $4) ON CONFLICT (code) DO NOTHING`,
			country, "did:uai:country:"+ulid("N"),
			"Member state "+country, "sha256:"+repeat64('a')); err != nil {
			t.Fatal(err)
		}
		if err := e.db.CreateDelegate(ctx, store.Delegate{
			ID: "del-" + id, UAIID: "uai:delegate:" + id, DID: did,
			Country: country, DisplayName: "Delegate " + country,
			CredentialID: []byte("cred-" + id),
			PublicJWK:    auth.jwk(), CredentialHash: "sha256:" + repeat64('b'),
		}); err != nil {
			t.Fatal(err)
		}
		c.delegates = append(c.delegates, did)
		c.auths = append(c.auths, auth)
	}
	c.proposalID = ulid("P")
	if err := e.db.OpenProposal(ctx, store.NewProposal{
		ID: c.proposalID, CaseID: c.caseID, Kind: governance.KindPermanentRevocation,
		AgentID: e.agent.ID, EvidenceDigest: c.evidence, PolicyVersion: e.bundle.Version(),
		BundleHash: e.bundle.Hash(), Threshold: fmt.Sprintf("%d-of-%d",
			len(countries)-1, len(countries)),
		OpenedAt: now, ClosesAt: now.Add(72 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

// vote casts one delegate's vote through the API.
func (e *env) vote(t *testing.T, c council, i int, value string, userVerified bool) *http.Response {
	t.Helper()
	proposal := map[string]any{}
	rec := e.getJSON(t, "/v1/governance/proposals/"+c.proposalID, &proposal)
	if rec != http.StatusOK {
		t.Fatalf("proposal: %d", rec)
	}
	voteNonce := nonce()
	statement := governance.Statement{
		CaseID: c.caseID, Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: e.agent.DID, EvidenceDigest: c.evidence,
		DelegateDID: c.delegates[i], Value: value, Nonce: voteNonce,
	}
	digest, err := statement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"delegate_did": c.delegates[i], "vote": value, "nonce": voteNonce,
		"assertion": c.auths[i].assert(digest, userVerified),
	}
	return e.postJSON(t, "/v1/governance/proposals/"+c.proposalID+"/vote", body)
}

// TestTheVoteStaysOpenUntilEveryoneHasAnswered.
//
// The demo found this: the proposal authorized on the vote that first met the
// threshold, and the delegate who wanted to vote NO was refused. The record
// then showed 4-0 where five delegates voted 4-1, and the dissent had been
// erased by arithmetic.
func TestTheVoteStaysOpenUntilEveryoneHasAnswered(t *testing.T) {
	e := setup(t)
	c := e.council(t, "AR", "DE", "JP", "CA", "IN")

	for i, value := range []string{"YES", "YES", "YES", "YES"} {
		resp := e.vote(t, c, i, value, true)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("vote %d: %d", i, resp.StatusCode)
		}
	}
	// The threshold is met and the last delegate has still not answered.
	var proposal map[string]any
	e.getJSON(t, "/v1/governance/proposals/"+c.proposalID, &proposal)
	if proposal["authorized"] == true {
		t.Fatal("the proposal authorized before the last delegate could vote")
	}

	// And the dissent lands.
	if resp := e.vote(t, c, 4, "NO", true); resp.StatusCode != http.StatusCreated {
		t.Fatalf("the dissenting vote was refused: %d", resp.StatusCode)
	}
	e.getJSON(t, "/v1/governance/proposals/"+c.proposalID, &proposal)
	if proposal["authorized"] != true {
		t.Fatalf("a complete 4-1 vote did not authorize: %v", proposal["reason"])
	}
	tally, _ := proposal["tally"].(map[string]any)
	if tally["no"].(float64) != 1 {
		t.Fatalf("the record shows %v NO votes, the council cast 1", tally["no"])
	}
}

// TestAnAssertionWithoutUserVerificationIsNotAVote is INV-005 at the API.
func TestAnAssertionWithoutUserVerificationIsNotAVote(t *testing.T) {
	e := setup(t)
	c := e.council(t, "AR", "DE", "JP")

	resp := e.vote(t, c, 0, "YES", false)
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("an assertion without user verification was counted as a vote")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", resp.StatusCode)
	}
	var problem api.Problem
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if problem.Title != "UAI_VOTE_NOT_USER_VERIFIED" {
		t.Fatalf("title = %q, want UAI_VOTE_NOT_USER_VERIFIED", problem.Title)
	}
}

// TestAVoteCannotBeLiftedOntoAnotherProposal. The challenge is the vote digest,
// so an assertion is bound to the exact case, agent, evidence and answer.
func TestAVoteCannotBeLiftedOntoAnotherProposal(t *testing.T) {
	e := setup(t)
	first := e.council(t, "AR", "DE", "JP")
	second := e.council(t, "AR", "DE", "JP")

	// An assertion produced for the first proposal, presented against the second.
	statement := governance.Statement{
		CaseID: first.caseID, Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: e.agent.DID, EvidenceDigest: first.evidence,
		DelegateDID: first.delegates[0], Value: "YES", Nonce: nonce(),
	}
	digest, err := statement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	resp := e.postJSON(t, "/v1/governance/proposals/"+second.proposalID+"/vote", map[string]any{
		"delegate_did": second.delegates[0], "vote": "YES", "nonce": statement.Nonce,
		"assertion": first.auths[0].assert(digest, true),
	})
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("an assertion for one proposal was accepted on another")
	}
}

// TestTheGovernanceProofRebuildsFromTheVotes: §16.3 preconditions 5 and 6, run
// by a party that is not the server.
func TestTheGovernanceProofRebuildsFromTheVotes(t *testing.T) {
	e := setup(t)
	c := e.council(t, "AR", "DE", "JP", "CA", "IN")
	for i, value := range []string{"YES", "YES", "YES", "YES", "NO"} {
		if resp := e.vote(t, c, i, value, true); resp.StatusCode != http.StatusCreated {
			t.Fatalf("vote %d: %d", i, resp.StatusCode)
		}
	}
	var proposal map[string]any
	e.getJSON(t, "/v1/governance/proposals/"+c.proposalID, &proposal)
	if proposal["authorized"] != true {
		t.Fatalf("not authorized: %v", proposal["reason"])
	}

	var decisionID string
	if err := e.db.Pool().QueryRow(context.Background(),
		`SELECT id FROM revocation_decisions WHERE proposal_id = $1`, c.proposalID).
		Scan(&decisionID); err != nil {
		t.Fatal(err)
	}
	var decision governance.Decision
	e.getJSON(t, "/v1/revocations/"+decisionID, &decision)

	// The check an independent verifier runs.
	if err := governance.Recompute(decision); err != nil {
		t.Fatalf("the decision does not follow from its own votes: %v", err)
	}
	if decision.Tally.Yes != 4 || decision.Tally.No != 1 || len(decision.Votes) != 5 {
		t.Fatalf("tally %d/%d over %d votes", decision.Tally.Yes, decision.Tally.No,
			len(decision.Votes))
	}
}

// TestAnAdministratorCannotChooseAnything is §16.3.
//
// The only input is a decision id. Everything else was fixed by the governance
// proof, and the server recomputes it before acting rather than reading back
// the row that claims it was already checked.
func TestAnAdministratorCannotChooseAnything(t *testing.T) {
	e := setup(t)
	c := e.council(t, "AR", "DE", "JP", "CA", "IN")
	for i, value := range []string{"YES", "YES", "YES", "YES", "NO"} {
		if resp := e.vote(t, c, i, value, true); resp.StatusCode != http.StatusCreated {
			t.Fatalf("vote %d: %d", i, resp.StatusCode)
		}
	}
	var decisionID string
	if err := e.db.Pool().QueryRow(context.Background(),
		`SELECT id FROM revocation_decisions WHERE proposal_id = $1`, c.proposalID).
		Scan(&decisionID); err != nil {
		t.Fatal(err)
	}

	// The body is ignored: whatever an administrator writes there, the decision
	// id in the path is the whole input.
	rec := e.postSignedDomain(t, "/v1/revocations/"+decisionID+"/execute",
		map[string]any{"decision_id": decisionID, "subject": "someone-else",
			"reason": "because I said so"}, uaicrypto.DomainRevocation)
	if rec.Code != http.StatusOK {
		t.Fatalf("execute: %d %s", rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["subject"] != e.agent.UAIID {
		t.Fatalf("the administrator revoked %v, the decision named %s", out["subject"], e.agent.UAIID)
	}
	// And the response says what revocation is, where it is least convenient.
	note, _ := out["note"].(string)
	if note == "" || !contains(note, "cannot stop software from running") {
		t.Errorf("the response does not say what revocation cannot do: %q", note)
	}

	// Executing twice is refused: a second on-chain event for one decision
	// would leave a reader of the chain guessing which one counted.
	again := e.postSignedDomain(t, "/v1/revocations/"+decisionID+"/execute",
		map[string]any{"decision_id": decisionID}, uaicrypto.DomainRevocation)
	if again.Code != http.StatusConflict {
		t.Fatalf("a second execution returned %d, want 409", again.Code)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
