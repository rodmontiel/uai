// Command uai-gateway serves the UAI public API.
//
// It is the Policy Enforcement Point of docs/protocol/08-guardrail.md: every
// state-changing call passes proof-of-possession verification here before any
// handler sees it, so no downstream service ever has to decide whether to
// believe an identifier in a body.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/internal/store"
)

func main() {
	var (
		addr   = flag.String("addr", envOr("UAI_ADDR", ":8080"), "listen address")
		dsn    = flag.String("dsn", os.Getenv("PG_DSN"), "PostgreSQL connection string")
		scheme = flag.String("scheme", envOr("UAI_SCHEME", "https"), "external URL scheme used to rebuild the signed target URI")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *dsn == "" {
		slog.Error("no database configured", "hint", "set PG_DSN or pass -dsn")
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

	// The scheme is explicit rather than inferred. A server-side request has a
	// relative URL, and reconstructing the wrong absolute target makes every
	// signature verify against a resource the caller never addressed.
	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.NewServer(db, api.WithScheme(*scheme)).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go purgeExpired(ctx, db)

	go func() {
		slog.Info("gateway listening", "addr", *addr, "scheme", *scheme)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown", "err", err)
	}
}

// purgeExpired drops expired idempotency claims and replay nonces.
//
// It runs in-process for the MVP. Note the consequence: the replay cache only
// protects for as long as entries are retained, so the purge interval must stay
// comfortably longer than the accepted clock skew, or a captured request would
// become replayable simply by waiting.
func purgeExpired(ctx context.Context, db *store.DB) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := db.PurgeExpired(ctx)
			if err != nil {
				slog.Warn("purge expired", "err", err)
				continue
			}
			if n > 0 {
				slog.Info("purged expired entries", "rows", n)
			}
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
