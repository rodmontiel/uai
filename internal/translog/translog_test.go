package translog_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/internal/translog"
	"github.com/rodmontiel/uai/pkg/merkle"
	"github.com/rodmontiel/uai/pkg/receipt"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

const origin = "uai.test/log/1"

type env struct {
	db  *store.DB
	log *translog.Log
	ws  []*translog.Witness
}

func setup(t *testing.T, minWitnesses int, witnessCount int) *env {
	t.Helper()
	dsn := os.Getenv("UAI_TEST_DSN")
	if dsn == "" {
		t.Skip("UAI_TEST_DSN not set; skipping transparency log tests")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("UAI_TEST_DSN is set but the database is unusable: %v", err)
	}
	t.Cleanup(db.Close)

	// A fresh origin per test: the log is append-only, so tests cannot share one.
	o := fmt.Sprintf("%s/%d", origin, time.Now().UnixNano())
	signer, _, err := uaicrypto.GenerateEd25519Signer("did:web:log.uai.test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	var ws []*translog.Witness
	for i := 0; i < witnessCount; i++ {
		ws1, _, err := uaicrypto.GenerateEd25519Signer(fmt.Sprintf("did:web:w%d.uai.test#key-1", i))
		if err != nil {
			t.Fatal(err)
		}
		ws = append(ws, translog.NewWitness(fmt.Sprintf("witness-%d", i), ws1))
	}
	l, err := translog.Open(ctx, db, o, signer, translog.WithWitnesses(minWitnesses, ws...))
	if err != nil {
		t.Fatal(err)
	}
	return &env{db: db, log: l, ws: ws}
}

func statement(n int) []byte {
	return []byte(fmt.Sprintf(`{"event_id":"E%04d","claim":"something happened"}`, n))
}

// TestReceiptsVerifyWithoutTheLog is the design goal of §18.1: evidence that
// survives the disappearance of its issuer.
func TestReceiptsVerifyWithoutTheLog(t *testing.T) {
	e := setup(t, 2, 2)
	ctx := context.Background()
	anchors := e.log.TrustAnchors()

	var receipts []receipt.Receipt
	for i := 0; i < 5; i++ {
		r, err := e.log.Append(ctx, statement(i), translog.KindAttestation, fmt.Sprintf("E%04d", i), time.Now())
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		receipts = append(receipts, r)
	}

	for i, r := range receipts {
		// A verifier holding the statement, the receipt and the trust anchors
		// needs nothing else. No call reaches the log below this line.
		status, err := receipt.Verify(r, statement(i), anchors)
		if err != nil {
			t.Fatalf("receipt %d: %v", i, err)
		}
		if status != receipt.StatusVerifiedUnanchored && status != receipt.StatusVerified {
			t.Errorf("receipt %d status = %s", i, status)
		}
		if uint64(i) != r.LogIndex {
			t.Errorf("receipt %d is for index %d", i, r.LogIndex)
		}
	}

	t.Run("a receipt does not verify against a different statement", func(t *testing.T) {
		if _, err := receipt.Verify(receipts[0], statement(99), anchors); err == nil {
			t.Error("a receipt verified a statement it was not issued for")
		}
	})

	t.Run("a tampered inclusion proof is caught", func(t *testing.T) {
		bad := receipts[3]
		bad.InclusionProof = append([]string{}, bad.InclusionProof...)
		bad.InclusionProof[0] = "sha256:" + strings.Repeat("0", 64)
		if _, err := receipt.Verify(bad, statement(3), anchors); err == nil {
			t.Error("a tampered proof verified")
		}
	})
}

// TestUnderWitnessedIsVisible: §18.4 requires a checkpoint below the witness
// threshold to be marked, so verifiers see reduced assurance rather than a
// silent downgrade.
func TestUnderWitnessedIsVisible(t *testing.T) {
	// Policy wants three co-signatures; only one witness exists.
	e := setup(t, 3, 1)
	r, err := e.log.Append(context.Background(), statement(0), translog.KindAttestation, "E0000", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Verify returns the status AND an error, deliberately. A caller writing
	// the idiomatic `if err != nil { reject }` gets the safe behaviour by
	// default; a caller that wants the nuance reads the status. Returning only
	// the status would let reduced assurance pass silently, and returning only
	// the error would collapse it into an ordinary verification failure.
	status, err := receipt.Verify(r, statement(0), e.log.TrustAnchors())
	if !errors.Is(err, receipt.ErrNotEnoughWitnesses) {
		t.Fatalf("got %v, want ErrNotEnoughWitnesses", err)
	}
	if status != receipt.StatusUnderwitnessed {
		t.Errorf("status = %s, want UNDERWITNESSED: one co-signature does not meet a threshold of three", status)
	}
}

// TestWitnessRefusesASplitView is the mechanism §17.4 rests on.
//
// A log operator showing two verifiers two histories must get witness
// signatures for two inconsistent checkpoints. This is the refusal.
func TestWitnessRefusesASplitView(t *testing.T) {
	signer, _, err := uaicrypto.GenerateEd25519Signer("did:web:w.uai.test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	w := translog.NewWitness("witness-de", signer)

	// The honest history the witness first co-signs.
	honest := merkle.New()
	for i := 0; i < 4; i++ {
		honest.Append(statement(i))
	}
	cp1 := checkpointOf(honest, 4)
	proof, err := honest.ConsistencyProof(1, 4)
	if err != nil {
		t.Fatal(err)
	}
	_ = proof
	if _, err := w.CoSign(cp1, nil); err != nil {
		t.Fatalf("the first checkpoint must be co-signed: %v", err)
	}

	// A DIFFERENT history of the same length: entry 2 replaced. This is the
	// operator rewriting what it already showed somebody.
	forked := merkle.New()
	for i := 0; i < 4; i++ {
		if i == 2 {
			forked.Append(statement(999))
			continue
		}
		forked.Append(statement(i))
	}
	if _, err := w.CoSign(checkpointOf(forked, 4), nil); !errors.Is(err, translog.ErrInconsistent) {
		t.Fatalf("a witness co-signed two roots at one size: %v", err)
	}

	// And a longer history that does not extend the one it signed.
	for i := 4; i < 8; i++ {
		forked.Append(statement(i))
	}
	bogus, err := forked.ConsistencyProof(4, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.CoSign(checkpointOf(forked, 8), bogus); !errors.Is(err, translog.ErrInconsistent) {
		t.Fatalf("a witness co-signed a history that does not extend its own view: %v", err)
	}

	// The honest continuation is accepted, so the refusal is specific and not
	// a witness that simply stopped working.
	for i := 4; i < 8; i++ {
		honest.Append(statement(i))
	}
	good, err := honest.ConsistencyProof(4, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.CoSign(checkpointOf(honest, 8), good); err != nil {
		t.Fatalf("an honest extension must be co-signed: %v", err)
	}
}

func checkpointOf(tree *merkle.Tree, size uint64) receipt.Checkpoint {
	root, err := tree.RootAtSize(size)
	if err != nil {
		panic(err)
	}
	return receipt.Checkpoint{Origin: origin, Size: size, Root: root, Timestamp: time.Now().UTC()}
}

// TestTheLogRebuildsFromItsLeaves: a restart must produce the same tree, or
// every proof issued after it would be for a different history.
func TestTheLogRebuildsFromItsLeaves(t *testing.T) {
	e := setup(t, 1, 1)
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		if _, err := e.log.Append(ctx, statement(i), translog.KindAttestation,
			fmt.Sprintf("E%04d", i), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	before, err := e.db.LatestCheckpoint(ctx, e.log.Origin())
	if err != nil {
		t.Fatal(err)
	}

	signer, _, err := uaicrypto.GenerateEd25519Signer("did:web:log.uai.test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := translog.Open(ctx, e.db, e.log.Origin(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Size() != 6 {
		t.Fatalf("reopened log has %d entries, want 6", reopened.Size())
	}
	// The property that matters. A tree rebuilt from the wrong leaves would
	// still issue internally consistent proofs; only comparing the rebuilt root
	// against the root that was already signed catches it.
	if got := uaicrypto.FormatDigest(reopened.Root()); got != before.Root {
		t.Fatalf("the rebuilt tree roots to %s, the published checkpoint says %s", got, before.Root)
	}

	r, err := reopened.Append(ctx, statement(6), translog.KindAttestation, "E0006", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.LogIndex != 6 {
		t.Errorf("the reopened log appended at index %d, want 6", r.LogIndex)
	}
}

// TestTheSameStatementIsNotLoggedTwice: one statement at two indices would make
// an inclusion proof ambiguous about which entry it proved.
func TestTheSameStatementIsNotLoggedTwice(t *testing.T) {
	e := setup(t, 1, 1)
	ctx := context.Background()
	if _, err := e.log.Append(ctx, statement(0), translog.KindAttestation, "E0000", time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err := e.log.Append(ctx, statement(0), translog.KindAttestation, "E0000", time.Now())
	if !errors.Is(err, store.ErrAlreadyLogged) {
		t.Fatalf("got %v, want ErrAlreadyLogged", err)
	}
}
