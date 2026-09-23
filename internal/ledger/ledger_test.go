package ledger_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/chain"
	"github.com/rodmontiel/uai/internal/ledger"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/internal/translog"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// TestKeccakMatchesKnownVectors: the EVM uses the pre-standard Keccak, not
// SHA3-256, and the two differ for every input. Getting this wrong produces
// function selectors that address nothing, which fails as an unexplained
// no-op rather than as an error.
func TestKeccakMatchesKnownVectors(t *testing.T) {
	cases := map[string]string{
		"":                          "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"abc":                       "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
		"transfer(address,uint256)": "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b",
	}
	for in, want := range cases {
		if got := hex.EncodeToString(chain.Keccak256([]byte(in))); got != want {
			t.Errorf("Keccak256(%q) = %s, want %s", in, got, want)
		}
	}
	// The selector everyone knows, as a cross-check that the truncation is right.
	if got := hex.EncodeToString(chain.Selector("transfer(address,uint256)")); got != "a9059cbb" {
		t.Errorf("selector = %s, want a9059cbb", got)
	}
}

// TestEncodingRefusesWhatTheContractsRefuse: the same rule INV-007 enforces on
// the contracts, enforced here on the way in.
func TestEncodingRefusesWhatTheContractsRefuse(t *testing.T) {
	if _, err := chain.WordFromBytes32([]byte("short")); !errors.Is(err, chain.ErrUnsupportedArgument) {
		t.Errorf("got %v, want ErrUnsupportedArgument", err)
	}
	if _, err := chain.WordFromAddress("0xdeadbeef"); !errors.Is(err, chain.ErrUnsupportedArgument) {
		t.Errorf("got %v, want ErrUnsupportedArgument", err)
	}
	// A uint is right-aligned, as the ABI requires.
	w := chain.WordFromUint(258)
	if hex.EncodeToString(w[:]) != strings.Repeat("0", 61)+"102" {
		t.Errorf("uint encoding = %s", hex.EncodeToString(w[:]))
	}
}

// TestNoopAdapterFabricatesNothing is the property that keeps a development
// build from claiming durability nobody provided.
func TestNoopAdapterFabricatesNothing(t *testing.T) {
	anchor, err := ledger.NoopAdapter{}.Publish(context.Background(), 7, []byte("root"))
	if !errors.Is(err, ledger.ErrNoPublicAnchor) {
		t.Fatalf("got %v, want ErrNoPublicAnchor", err)
	}
	if anchor.Tx != "" || anchor.Block != 0 || anchor.ChainID != 0 {
		t.Errorf("the noop adapter invented an anchor: %+v", anchor)
	}
}

// ── the live path ───────────────────────────────────────────────────────────

type evm struct {
	client   *chain.Client
	contract string
}

// startAnvil brings up a local EVM, or skips.
func startAnvil(t *testing.T) *evm {
	t.Helper()
	anvil, err := exec.LookPath("anvil")
	if err != nil {
		home, _ := os.UserHomeDir()
		anvil = home + "/.local/foundry/bin/anvil"
		if _, statErr := os.Stat(anvil); statErr != nil {
			t.Skip("anvil not found; skipping the live ledger test")
		}
	}
	bytecodePath := "../../contracts/out/UAITransparencyAnchor.sol/UAITransparencyAnchor.json"
	raw, err := os.ReadFile(bytecodePath)
	if err != nil {
		t.Skip("contracts are not compiled; run `make contracts` to exercise the live ledger path")
	}
	var art struct {
		Bytecode struct {
			Object string `json:"object"`
		} `json:"bytecode"`
	}
	if err := json.Unmarshal(raw, &art); err != nil {
		t.Fatal(err)
	}
	code, err := hex.DecodeString(strings.TrimPrefix(art.Bytecode.Object, "0x"))
	if err != nil {
		t.Fatal(err)
	}

	port := 18545 + int(time.Now().UnixNano()%2000)
	cmd := exec.Command(anvil, "--port", fmt.Sprint(port), "--silent", "--chain-id", "13370")
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start anvil: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	ctx := context.Background()
	client := chain.New(fmt.Sprintf("http://127.0.0.1:%d", port), "", 13370)
	var accounts []string
	for i := 0; i < 60; i++ {
		accounts, err = client.Accounts(ctx)
		if err == nil && len(accounts) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(accounts) == 0 {
		t.Skipf("anvil did not come up: %v", err)
	}
	client = chain.New(fmt.Sprintf("http://127.0.0.1:%d", port), accounts[0], 13370)

	admin, err := chain.WordFromAddress(accounts[0])
	if err != nil {
		t.Fatal(err)
	}
	// minWitnesses = 1, matching the log this test drives.
	addr, err := client.Deploy(ctx, code, admin, chain.WordFromUint(1))
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	// The deployer is admin; grant it the writer role the anchor call requires.
	role := chain.Keccak256([]byte("UAI_WRITER"))
	roleWord, err := chain.WordFromBytes32(role)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(ctx, addr,
		chain.Encode("grantRole(bytes32,address)", roleWord, admin)); err != nil {
		t.Fatalf("grantRole: %v", err)
	}
	return &evm{client: client, contract: addr}
}

// TestCheckpointsReachTheLedger drives the whole pipeline: statements into the
// log, checkpoints out, anchors on a real EVM.
func TestCheckpointsReachTheLedger(t *testing.T) {
	dsn := os.Getenv("UAI_TEST_DSN")
	if dsn == "" {
		t.Skip("UAI_TEST_DSN not set")
	}
	e := startAnvil(t)
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	origin := fmt.Sprintf("uai.test/ledger/%d", time.Now().UnixNano())
	logSigner, _, err := uaicrypto.GenerateEd25519Signer("did:web:log.uai.test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	wSigner, _, err := uaicrypto.GenerateEd25519Signer("did:web:w0.uai.test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	tlog, err := translog.Open(ctx, db, origin, logSigner,
		translog.WithWitnesses(1, translog.NewWitness("witness-0", wSigner)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := tlog.Append(ctx, []byte(fmt.Sprintf(`{"n":%d}`, i)),
			translog.KindAttestation, fmt.Sprintf("E%d", i), time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	w := ledger.New(db, e.client, ledger.Options{Origin: origin, Contract: e.contract})
	anchored, err := w.Drain(ctx)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if anchored != 3 {
		t.Fatalf("anchored %d checkpoints, want 3", anchored)
	}

	// The ledger now holds the latest size, and the contract refuses to go
	// backwards — so a second drain finds nothing and changes nothing.
	again, err := w.Drain(ctx)
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if again != 0 {
		t.Errorf("a second drain anchored %d checkpoints; the queue should be empty", again)
	}

	// Read the anchored size back from the chain. This is the part that makes
	// the pipeline real rather than a database write with extra steps.
	out, err := e.client.CallView(ctx, e.contract, chain.Encode("latestSize()"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Fatalf("latestSize returned %d bytes", len(out))
	}
	if got := out[31]; got != 3 {
		t.Errorf("the ledger reports size %d, want 3", got)
	}

	// And the database records where each anchor landed.
	var count int
	if err := db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM ledger_commitments WHERE subject_id LIKE $1`, origin+"#%").
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("%d ledger commitments recorded, want 3", count)
	}
}

// TestTheLedgerRefusesAStaleCheckpoint: a log that shrank would be a log that
// dropped entries, and the contract is the thing that makes that impossible to
// do quietly.
func TestTheLedgerRefusesAStaleCheckpoint(t *testing.T) {
	e := startAnvil(t)
	ctx := context.Background()
	root, err := chain.WordFromBytes32(chain.Keccak256([]byte("root-10")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Send(ctx, e.contract,
		chain.Encode("anchor(bytes32,uint64,uint32)", root, chain.WordFromUint(10), chain.WordFromUint(1))); err != nil {
		t.Fatalf("first anchor: %v", err)
	}
	older, err := chain.WordFromBytes32(chain.Keccak256([]byte("root-9")))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.client.Send(ctx, e.contract,
		chain.Encode("anchor(bytes32,uint64,uint32)", older, chain.WordFromUint(9), chain.WordFromUint(1)))
	if !errors.Is(err, chain.ErrReverted) {
		t.Fatalf("got %v, want ErrReverted: the ledger must refuse a shrinking log", err)
	}
}
