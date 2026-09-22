package store_test

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/store"
)

// These are integration tests: they need a real PostgreSQL with the migrations
// applied. Set UAI_TEST_DSN to run them.
//
// They skip when the variable is unset, and FAIL when it is set but unusable.
// A test that silently passes because it could not run is worse than no test —
// which this repository has already been bitten by once.
func open(t *testing.T) *store.DB {
	t.Helper()
	dsn := os.Getenv("UAI_TEST_DSN")
	if dsn == "" {
		t.Skip("UAI_TEST_DSN not set; skipping store integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("UAI_TEST_DSN is set but the database is unusable: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

var seq atomic.Int64

// The counter starts at a random offset because the database outlives the test
// process: a fresh `go test` run would otherwise reuse the identifiers the
// previous run already inserted, and the collision looks like a bug in the code
// under test rather than in the fixture.
func init() {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	seq.Store(int64(binary.BigEndian.Uint64(b[:]) % 1_000_000_000_000_000_000))
}

// ulid builds a syntactically valid 26-character identifier for tests.
//
// Two details, both learned the hard way:
//   - The counter is zero-padded on the LEFT. Padding on the right collides:
//     "W1" and "W10" both become W followed by 1 and then zeros to width 26.
//   - The counter is atomic. The concurrency test calls this from goroutines,
//     and a racy counter produces duplicate identifiers, which surfaces as a
//     primary-key violation that looks like a bug in the code under test.
func ulid(prefix string) string {
	// The first character must be <= '7': a ULID's leading character encodes
	// only two bits, so anything higher overflows 128 bits and is rejected.
	return fmt.Sprintf("0%s%024d", strings.ToUpper(prefix), seq.Add(1))
}

func digest(b byte) string { return "sha256:" + strings.Repeat(string(rune('a'+b%6)), 64) }

type fixture struct {
	db      *store.DB
	agent   store.Agent
	ownerID string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	db := open(t)
	ctx := context.Background()

	orgID := "org-" + ulid("O")
	ownerID := "own-" + ulid("W")
	agentID := "ag-" + ulid("A")

	if err := db.CreateOrganization(ctx, store.Organization{
		ID: orgID, DID: "did:web:acme-" + strings.ToLower(orgID) + ".example",
		LegalName: "ACME Robotics", Jurisdiction: "AR",
	}); err != nil {
		t.Fatalf("create organization: %v", err)
	}
	if err := db.CreateOwner(ctx, store.Owner{
		ID: ownerID, UAIID: "uai:owner:" + ulid("W"), DID: "did:uai:owner:" + ulid("W"),
		OrganizationID: orgID, DisplayName: "ACME Ops", Jurisdiction: "AR",
	}); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	agent := store.Agent{
		ID: agentID, UAIID: "uai:agent:" + ulid("A"), DID: "did:uai:agent:" + ulid("A"),
		OwnerID: ownerID, OrganizationID: orgID, LogicalName: "DeliveryOptimizer",
		AgentType: "autonomous_task_agent", PrimaryJurisdiction: "AR",
		AssuranceLevel: "UAI-AL2", IdentityCommitment: digest(0),
		PolicyVersion: "GASC-2027.4", GenesisEventHash: digest(1),
	}
	key := store.AgentKey{
		ID: "key-" + ulid("K"), KeyID: "key-1", Alg: "EdDSA",
		PublicJWK:  json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"abc"}`),
		Protection: "TPM2", ValidFrom: time.Now().Add(-time.Hour),
	}
	if err := db.CreateAgent(ctx, agent, key); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	return &fixture{db: db, agent: agent, ownerID: ownerID}
}

func (f *fixture) append(t *testing.T, prev string, n byte) (string, error) {
	t.Helper()
	id := ulid("E")
	eventHash := "sha256:" + fmt.Sprintf("%064x", n)
	err := f.db.AppendAction(context.Background(),
		store.ActionEvent{
			ID: id, AgentID: f.agent.ID, OwnerID: f.ownerID,
			ActionType: "route.optimize", Capability: "route.optimize", Purpose: "delivery",
			JurisdictionOrigin: "AR", JurisdictionBasis: "owner_jurisdiction",
			Outcome: "SUCCESS", PreviousEventHash: prev, EventHash: eventHash,
			AssertedAt: time.Now(),
		},
		store.Attestation{
			EventID: id, AgentID: f.agent.ID, Payload: json.RawMessage(`{}`),
			Alg: "EdDSA", Signature: "zSig" + id, SignerKID: f.agent.DID + "#key-1",
			Nonce: "nonce-" + id,
		})
	return eventHash, err
}

func TestChainStartsAtGenesis(t *testing.T) {
	f := setup(t)
	head, err := f.db.ChainHead(context.Background(), f.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The chain is anchored to the identity itself, not to nothing: the first
	// action must reference the registration event.
	if head.Hash != f.agent.GenesisEventHash || head.Sequence != 0 {
		t.Fatalf("head = %+v, want genesis %s at sequence 0", head, f.agent.GenesisEventHash)
	}
}

func TestAppendAdvancesTheChain(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	prev := f.agent.GenesisEventHash
	for i := byte(1); i <= 3; i++ {
		h, err := f.append(t, prev, i)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		head, err := f.db.ChainHead(ctx, f.agent.ID)
		if err != nil {
			t.Fatal(err)
		}
		if head.Hash != h || head.Sequence != int64(i) {
			t.Fatalf("after append %d head = %+v, want %s at %d", i, head, h, i)
		}
		prev = h
	}
	if err := f.db.VerifyChain(ctx, f.agent.ID); err != nil {
		t.Fatalf("chain should verify: %v", err)
	}
}

func TestStaleHeadIsAConflictNotAFork(t *testing.T) {
	f := setup(t)
	prev := f.agent.GenesisEventHash
	h1, err := f.append(t, prev, 1)
	if err != nil {
		t.Fatal(err)
	}
	_ = h1

	// Submitting against the old head is an ordinary race, not evidence of
	// anything: the caller refetches and retries.
	_, err = f.append(t, prev, 2)
	if !errors.Is(err, store.ErrChainConflict) {
		t.Fatalf("expected ErrChainConflict, got %v", err)
	}
	var conflict *store.ChainConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected the current head to be reported, got %v", err)
	}
	if conflict.Actual.Hash != h1 || conflict.Actual.Sequence != 1 {
		t.Fatalf("conflict reports head %+v, want %s at 1", conflict.Actual, h1)
	}
}

func TestConcurrentAppendsProduceAForkNotACorruptChain(t *testing.T) {
	f := setup(t)
	prev := f.agent.GenesisEventHash

	// Two writers read the same head and both try to extend it. One wins; the
	// other must be refused by the database, because a committed fork would be
	// indistinguishable from a cloned agent after the fact.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.append(t, prev, byte(10+i))
		}(i)
	}
	wg.Wait()

	okCount := 0
	for _, err := range errs {
		switch {
		case err == nil:
			okCount++
		case errors.Is(err, store.ErrChainConflict):
			// The loser is caught by the head check, the chain index or the
			// sequence index depending on interleaving. All three mean the same
			// thing -- the head moved -- and all three must surface as a
			// retryable conflict. Reporting a lost race as a fork would raise an
			// incident against an innocent agent every time two replicas
			// attested at once.
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if okCount != 1 {
		t.Fatalf("%d of 2 concurrent appends succeeded, want exactly 1", okCount)
	}
	if err := f.db.VerifyChain(context.Background(), f.agent.ID); err != nil {
		t.Fatalf("chain must stay intact after a race: %v", err)
	}
}

func TestReplayedNonceRejected(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	prev := f.agent.GenesisEventHash
	id := ulid("E")
	ev := store.ActionEvent{
		ID: id, AgentID: f.agent.ID, OwnerID: f.ownerID, ActionType: "route.optimize",
		Purpose: "delivery", JurisdictionOrigin: "AR", JurisdictionBasis: "owner_jurisdiction",
		Outcome: "SUCCESS", PreviousEventHash: prev, EventHash: digest(2), AssertedAt: time.Now(),
	}
	att := store.Attestation{
		EventID: id, AgentID: f.agent.ID, Payload: json.RawMessage(`{}`), Alg: "EdDSA",
		Signature: "zSig", SignerKID: f.agent.DID + "#key-1", Nonce: "reused-nonce",
	}
	if err := f.db.AppendAction(ctx, ev, att); err != nil {
		t.Fatal(err)
	}
	ev2, att2 := ev, att
	ev2.ID, att2.EventID = ulid("E"), ev2.ID
	ev2.PreviousEventHash, ev2.EventHash = digest(2), digest(3)
	if err := f.db.AppendAction(ctx, ev2, att2); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected a nonce conflict, got %v", err)
	}
}

func TestAttestedActionsAreAppendOnly(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.append(t, f.agent.GenesisEventHash, 1); err != nil {
		t.Fatal(err)
	}
	// INV-002: the record of what an agent did is not editable, and the store
	// maps the database guard to a distinguishable error.
	_, err := f.db.Pool().Exec(ctx,
		`UPDATE action_events SET outcome = 'FAILURE' WHERE agent_id = $1`, f.agent.ID)
	if err == nil {
		t.Fatal("an attested action was modified")
	}
	if !strings.Contains(err.Error(), "UAI_APPEND_ONLY") {
		t.Fatalf("expected the append-only guard to fire, got %v", err)
	}
}

func TestRevocationKeepsHistory(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.append(t, f.agent.GenesisEventHash, 1); err != nil {
		t.Fatal(err)
	}
	if err := f.db.SetAgentStatus(ctx, f.agent.ID, "REVOKED", time.Now()); err != nil {
		t.Fatal(err)
	}
	a, err := f.db.AgentByUAIID(ctx, f.agent.UAIID)
	if err != nil {
		t.Fatalf("a revoked identity must still resolve: %v", err)
	}
	if a.Status != "REVOKED" || a.RevokedAt == nil {
		t.Fatalf("status = %s, revoked_at = %v", a.Status, a.RevokedAt)
	}
	// INV-006: revocation is a status change. Deleting the agent would destroy
	// exactly the evidence the revocation was based on.
	events, err := f.db.Chain(ctx, f.agent.ID, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("history lost on revocation: %d events, err %v", len(events), err)
	}
	_, err = f.db.Pool().Exec(ctx, `DELETE FROM agents WHERE id = $1`, f.agent.ID)
	if err == nil {
		t.Fatal("a revoked agent was deleted")
	}
}

func TestAgentRoundTrip(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	got, err := f.db.AgentByUAIID(ctx, f.agent.UAIID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DID != f.agent.DID || got.AssuranceLevel != "UAI-AL2" || got.Status != "REGISTERED" {
		t.Fatalf("agent did not round trip: %+v", got)
	}
	keys, err := f.db.AgentKeys(ctx, f.agent.ID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys = %d, err %v", len(keys), err)
	}
	if keys[0].Protection != "TPM2" || keys[0].Alg != "EdDSA" {
		t.Fatalf("key did not round trip: %+v", keys[0])
	}
}

func TestUnknownAgentIsNotFound(t *testing.T) {
	db := open(t)
	if _, err := db.AgentByUAIID(context.Background(), "uai:agent:0000000000000000000000000Z"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
