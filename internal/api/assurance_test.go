package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestAssuranceIsDerivedNotStored is the gate on the defect this file exists
// for: agents.assurance_level was written once at registration and never again,
// and four surfaces reported it as if it were current.
//
// The column is gone (migration 0011) and store.Agent no longer carries the
// field, so a stale read is a compile error rather than a wrong number. What
// remains testable at runtime is the part a schema cannot express: that every
// surface answers with the SAME level, and that the level moves when the
// evidence moves.
func TestAssuranceIsDerivedNotStored(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	// 1. The two surfaces that report a level must agree. Before this change
	//    they did not: /verify derived, /v1/agents read the column, and the
	//    fixture wrote "UAI-AL2" into it while the evidence said AL0.
	var card, verify struct {
		AssuranceLevel string `json:"assurance_level"`
		LimitedBy      string `json:"assurance_limited_by"`
	}
	if code := e.getJSON(t, "/v1/agents/"+e.agent.UAIID, &card); code != http.StatusOK {
		t.Fatalf("identity card: %d", code)
	}
	if code := e.getJSON(t, "/v1/verify/"+e.agent.UAIID, &verify); code != http.StatusOK {
		t.Fatalf("verify: %d", code)
	}
	if card.AssuranceLevel != verify.AssuranceLevel {
		t.Fatalf("surfaces disagree: card says %q, verify says %q",
			card.AssuranceLevel, verify.AssuranceLevel)
	}

	// 2. With no runtime bound, the runtime dimension is what holds the level
	//    down -- a fact about evidence, not a stored string.
	if verify.LimitedBy != "runtime attestation" {
		t.Fatalf("unbound agent should be limited by runtime attestation, got %q", verify.LimitedBy)
	}

	// 3. Move the evidence: an attested runtime, live now. Nothing writes an
	//    assurance level anywhere -- if the reported level still followed a
	//    stored value, this would change nothing.
	//
	//    bound_at must be LATER than the fixture's self-declared runtime: the
	//    evidence query reads the most recent live binding, so an attested one
	//    backdated behind a self-declared one is correctly ignored.
	now := time.Now().UTC()
	if _, err := e.db.Pool().Exec(ctx, `
		INSERT INTO runtime_identities (id, agent_id, spiffe_id, cert_hash, attestor,
		                                bound_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		"rt-"+ulid("R"), e.agent.ID, "spiffe://uai.test/agents/"+ulid("S")+"/i/dev",
		"sha256:"+repeat64('c'), "spiffe://uai.test",
		now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if code := e.getJSON(t, "/v1/verify/"+e.agent.UAIID, &verify); code != http.StatusOK {
		t.Fatalf("verify after binding: %d", code)
	}
	// The overall level does NOT rise: it is the minimum of three dimensions and
	// owner verification is pinned at SELF_ASSERTED (§20.5). What moves is which
	// dimension is now the ceiling, and that is the observable proof the number
	// was recomputed rather than recalled.
	if verify.LimitedBy != "owner verification" {
		t.Fatalf("an attested runtime should move the ceiling to the owner, got %q", verify.LimitedBy)
	}
	if code := e.getJSON(t, "/v1/agents/"+e.agent.UAIID, &card); code != http.StatusOK {
		t.Fatalf("identity card after binding: %d", code)
	}
	if card.AssuranceLevel != verify.AssuranceLevel {
		t.Fatalf("surfaces disagree after the evidence moved: card %q, verify %q",
			card.AssuranceLevel, verify.AssuranceLevel)
	}
}

// TestAgentsTableHasNoAssuranceColumn keeps the column from coming back.
//
// Dropping it is what makes the stale read unrepresentable; a migration that
// re-adds it "for convenience" would restore the defect in full, and the Go
// compiler cannot see a database.
func TestAgentsTableHasNoAssuranceColumn(t *testing.T) {
	e := setup(t)
	var n int
	if err := e.db.Pool().QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.columns
		 WHERE table_name = 'agents' AND column_name = 'assurance_level'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("agents.assurance_level is back. An assurance level is derived from evidence " +
			"on every read; a column holding one is a cache with no invalidation path, and " +
			"for its whole life it held the registration-time default.")
	}
}

// TestIdentityCardCarriesTheChainAnchor covers a field OpenAPI declares on this
// response and the implementation did not send.
//
// It is not cosmetic. The card is what a relying party reads about an identity,
// and genesis_event_hash is the only thing on it that closes the walk backwards:
// the first attestation names it as previous_event_hash, so without it a
// verifier holding an action can reach its predecessors and then stop, with no
// way to tell whether it arrived at registration or at a truncation.
func TestIdentityCardCarriesTheChainAnchor(t *testing.T) {
	e := setup(t)
	var card struct {
		Genesis            string `json:"genesis_event_hash"`
		IdentityCommitment string `json:"identity_commitment"`
	}
	if code := e.getJSON(t, "/v1/agents/"+e.agent.UAIID, &card); code != http.StatusOK {
		t.Fatalf("identity card: %d", code)
	}
	if card.Genesis == "" {
		t.Fatal("the identity card does not carry genesis_event_hash, which OpenAPI " +
			"declares on this response and a verifier needs to reach registration")
	}
	if card.Genesis != e.agent.GenesisEventHash {
		t.Fatalf("genesis_event_hash = %q, want %q", card.Genesis, e.agent.GenesisEventHash)
	}
	// Distinct values with the same shape. Reporting one where the other belongs
	// would look right in a screenshot and break every chain walk.
	if card.Genesis == card.IdentityCommitment {
		t.Fatal("genesis_event_hash and identity_commitment are the same value: " +
			"one anchors the event chain, the other commits to the identity record")
	}
}
