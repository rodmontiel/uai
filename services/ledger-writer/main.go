// Command uai-ledger-writer anchors witnessed transparency checkpoints on the
// consortium ledger.
//
// It is a separate process from the gateway on purpose. Anchoring is a
// durability layer, not an admission gate (§12.4): the gateway must keep
// accepting attestations while this is down, and the cleanest way to guarantee
// that is for the two to be unable to block each other.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rodmontiel/uai/internal/chain"
	"github.com/rodmontiel/uai/internal/ledger"
	"github.com/rodmontiel/uai/internal/store"
)

func main() {
	var (
		dsn      = flag.String("dsn", os.Getenv("PG_DSN"), "PostgreSQL connection string")
		rpc      = flag.String("rpc", envOr("UAI_CHAIN_RPC", "http://localhost:8545"), "consortium ledger JSON-RPC endpoint")
		from     = flag.String("from", os.Getenv("UAI_CHAIN_FROM"), "account the node signs with")
		contract = flag.String("anchor-contract", os.Getenv("UAI_ANCHOR_CONTRACT"), "UAITransparencyAnchor address")
		chainID  = flag.Uint64("chain-id", 13370, "consortium chain id")
		origin   = flag.String("log-origin", envOr("UAI_LOG_ORIGIN", "uai.world/log/1"), "transparency log origin")
		interval = flag.Duration("interval", 10*time.Second, "how often to drain the queue")
		adapter  = flag.String("public-anchor", envOr("UAI_PUBLIC_ANCHOR_ADAPTER", "noop-dev"), "public anchor adapter")
		once     = flag.Bool("once", false, "drain once and exit")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	switch {
	case *dsn == "":
		slog.Error("no database configured", "hint", "set PG_DSN or pass -dsn")
		os.Exit(1)
	case *contract == "":
		slog.Error("no anchor contract configured", "hint", "set UAI_ANCHOR_CONTRACT to the deployed UAITransparencyAnchor")
		os.Exit(1)
	case *from == "":
		// The node holds the key, not this process — but it still has to be
		// told which account to use, and guessing would write from whichever
		// account happened to be first.
		slog.Error("no sending account configured", "hint", "set UAI_CHAIN_FROM")
		os.Exit(1)
	}

	pub, err := adapterByName(*adapter)
	if err != nil {
		slog.Error("unknown public anchor adapter", "adapter", *adapter, "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, *dsn)
	if err != nil {
		slog.Error("database unavailable", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	client := chain.New(*rpc, *from, *chainID)
	writer := ledger.New(db, client, ledger.Options{
		Origin: *origin, Contract: *contract, Adapter: pub, Logger: logger,
	})

	slog.Info("ledger writer starting", "rpc", *rpc, "contract", *contract,
		"origin", *origin, "public_anchor", pub.Name(), "interval", interval.String())

	drain := func() {
		n, err := writer.Drain(ctx)
		if err != nil {
			// A revert is the ledger doing its job and is already logged with
			// the checkpoint that caused it. Anything else is an operational
			// problem worth surfacing.
			if !errors.Is(err, chain.ErrReverted) {
				slog.Error("drain failed", "err", err)
			}
			return
		}
		if n > 0 {
			slog.Info("checkpoints anchored", "count", n)
		}
	}

	drain()
	if *once {
		return
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("ledger writer stopping")
			return
		case <-ticker.C:
			drain()
		}
	}
}

func adapterByName(name string) (ledger.PublicAnchorAdapter, error) {
	switch name {
	case "noop-dev", "":
		return ledger.NoopAdapter{}, nil
	default:
		// Named but not built. Refusing is the point: silently falling back to
		// noop would mean a deployment that believes it publishes a public
		// anchor and does not.
		return nil, errors.New("only noop-dev ships today; ethereum-l1, base, arbitrum and " +
			"bitcoin-ots arrive with the deployment phase (docs/protocol/11-ledger-transparency.md §17.4)")
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
