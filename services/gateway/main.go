// Command uai-gateway serves the UAI public API.
//
// It is the Policy Enforcement Point of docs/protocol/08-guardrail.md: every
// state-changing call passes proof-of-possession verification here before any
// handler sees it, so no downstream service ever has to decide whether to
// believe an identifier in a body.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/internal/keyfile"
	"github.com/rodmontiel/uai/internal/pdp"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/internal/translog"
	"github.com/rodmontiel/uai/pkg/spiffe"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

func main() {
	var (
		addr       = flag.String("addr", envOr("UAI_ADDR", ":8080"), "listen address")
		dsn        = flag.String("dsn", os.Getenv("PG_DSN"), "PostgreSQL connection string")
		scheme     = flag.String("scheme", envOr("UAI_SCHEME", "https"), "external URL scheme used to rebuild the signed target URI")
		issuerDID  = flag.String("issuer-did", envOr("UAI_ISSUER_DID", "did:web:credentials.uai.world"), "DID of the credential issuer")
		issuerKey  = flag.String("issuer-key", envOr("UAI_ISSUER_KEY", ".keys/issuer.jwk"), "path to the issuer signing key")
		bundleDir  = flag.String("policy-bundle", envOr("UAI_POLICY_BUNDLE", "policy/gasc-2027.4"), "GASC bundle directory")
		authority  = flag.String("policy-authority", envOr("UAI_POLICY_AUTHORITY", "policy/authority.json"), "public approval set for policy bundles")
		logOrigin  = flag.String("log-origin", envOr("UAI_LOG_ORIGIN", "uai.world/log/1"), "transparency log origin")
		witnessN   = flag.Int("log-witnesses", 2, "number of local witnesses (MVP; production uses independent operators)")
		minWitness = flag.Int("log-min-witnesses", 2, "co-signatures a checkpoint needs to count as fully witnessed")

		// Runtime attestation (§9.1, phase 12). Both or neither: a bundle
		// without a trust domain cannot tell a foreign SVID from a forged one,
		// and a trust domain without a bundle verifies nothing.
		spireBundle = flag.String("spire-bundle", os.Getenv("UAI_SPIRE_BUNDLE"),
			"PEM trust bundle for the SPIRE trust domain; when set, binding requires an attested SVID")
		spireDomain = flag.String("spire-trust-domain", os.Getenv("UAI_SPIRE_TRUST_DOMAIN"),
			"SPIFFE trust domain this registry accepts SVIDs from")
		tlsCert = flag.String("tls-cert", os.Getenv("UAI_TLS_CERT"), "PEM certificate to serve TLS with")
		tlsKey  = flag.String("tls-key", os.Getenv("UAI_TLS_KEY"), "PEM private key for -tls-cert")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *dsn == "" {
		slog.Error("no database configured", "hint", "set PG_DSN or pass -dsn")
		os.Exit(1)
	}

	// The issuer key is required, not optional. Starting without one would mean
	// discovering at the first registration that no credential can be issued --
	// and the alternative, generating a key at boot, is worse: it hands out
	// credentials that stop verifying at the next restart.
	signer, err := keyfile.Load(*issuerKey, *issuerDID+"#key-1")
	if err != nil {
		slog.Error("no credential issuer key", "err", err,
			"hint", "create one with: go run ./tools/uai-keygen -did "+*issuerDID)
		os.Exit(1)
	}

	// The policy bundle is required, and it is verified before it is compiled.
	// A gateway that started without policy would have to answer every request
	// with a fail-closed refusal anyway; failing at startup says why once
	// instead of once per request.
	auth, err := pdp.LoadAuthorityFile(*authority)
	if err != nil {
		slog.Error("no policy authority set", "err", err)
		os.Exit(1)
	}
	bundle, err := pdp.Load(context.Background(), os.DirFS(*bundleDir), auth, time.Now())
	if err != nil {
		slog.Error("policy bundle rejected", "err", err, "dir", *bundleDir,
			"hint", "a bundle edited without the governance keys no longer matches its manifest")
		os.Exit(1)
	}
	slog.Info("policy loaded", "version", bundle.Version(), "hash", bundle.Hash())

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
	// The transparency log. Its signing key is the issuer key for now: the MVP
	// runs one process, and a separate log key would be a second secret with no
	// second operator behind it. §23.1 splits uai-transparency-service out, and
	// that is when the key should become its own.
	witnesses := make([]*translog.Witness, 0, *witnessN)
	for i := 0; i < *witnessN; i++ {
		// Local, simulated witnesses (§18.3). They provide the MECHANISM, not
		// the independence: split-view detection rests on witnesses being run
		// by parties who would not collude with the log, and processes on one
		// host are not that.
		ws, _, wErr := uaicrypto.GenerateEd25519Signer(fmt.Sprintf("did:web:witness-%d.local#key-1", i))
		if wErr != nil {
			slog.Error("witness key", "err", wErr)
			os.Exit(1)
		}
		witnesses = append(witnesses, translog.NewWitness(fmt.Sprintf("witness-%d", i), ws))
	}
	tlog, err := translog.Open(ctx, db, *logOrigin, signer,
		translog.WithWitnesses(*minWitness, witnesses...))
	if err != nil {
		slog.Error("transparency log unavailable", "err", err)
		os.Exit(1)
	}
	slog.Info("transparency log open", "origin", tlog.Origin(), "size", tlog.Size(),
		"witnesses", len(witnesses), "min_witnesses", *minWitness)

	opts := []api.Option{
		api.WithScheme(*scheme),
		api.WithIssuer(*issuerDID, signer),
		api.WithBundle(bundle),
		api.WithTransparency(tlog),
	}
	trust, err := loadTrustBundle(*spireDomain, *spireBundle)
	if err != nil {
		slog.Error("runtime attestation misconfigured", "err", err)
		os.Exit(1)
	}
	if trust != nil {
		// Attestation without TLS is a configuration in which binding can never
		// succeed: the SVID arrives as a client certificate, and a plaintext
		// listener has no place to put one. Every bind would fail closed with a
		// correct-sounding error, and the operator would go looking at the
		// agent. Refusing to start names the contradiction instead.
		if *tlsCert == "" {
			slog.Error("runtime attestation requires TLS",
				"why", "an X509-SVID is presented as a client certificate, which plaintext cannot carry",
				"fix", "pass -tls-cert and -tls-key, or drop -spire-bundle")
			os.Exit(1)
		}
		opts = append(opts, api.WithSPIFFE(trust))
		slog.Info("runtime attestation enabled", "trust_domain", trust.TrustDomain,
			"ca_certificates", trust.Size())
	} else {
		// Said out loud, every start. A registry recording runtimes the agents
		// described themselves is a normal configuration and a weak one, and
		// the difference is invisible unless somebody says it.
		slog.Warn("runtime attestation disabled",
			"effect", "bindings record self-declared runtimes and stay at the AL0 runtime dimension",
			"hint", "set -spire-bundle and -spire-trust-domain")
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.NewServer(db, opts...).Routes(),
		TLSConfig:         clientCertConfig(trust),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go purgeExpired(ctx, db)

	go func() {
		serving := "http"
		if *tlsCert != "" {
			serving = "https"
		}
		slog.Info("gateway listening", "addr", *addr, "scheme", *scheme, "serving", serving)
		var err error
		if *tlsCert != "" {
			err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// loadTrustBundle reads the SPIRE trust bundle, or returns nil when runtime
// attestation is not configured.
//
// Half a configuration is an error rather than a default. A bundle with no
// trust domain would accept an SVID from any domain that CA happens to sign
// for, and a trust domain with no bundle would verify nothing while looking
// like it was verifying something -- which is the worse of the two.
func loadTrustBundle(trustDomain, path string) (*spiffe.Bundle, error) {
	switch {
	case trustDomain == "" && path == "":
		return nil, nil
	case trustDomain == "":
		return nil, fmt.Errorf("-spire-bundle was given without -spire-trust-domain")
	case path == "":
		return nil, fmt.Errorf("-spire-trust-domain was given without -spire-bundle")
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the trust bundle: %w", err)
	}
	return spiffe.ParseBundle(trustDomain, pemBytes)
}

// clientCertConfig asks for a client certificate without requiring one.
//
// Requesting rather than requiring, because /verify, /trust-anchors and the DID
// documents are unauthenticated by design -- a verification endpoint that
// demanded a certificate would be a verification endpoint nobody could use. The
// binding handler is what requires the SVID, and it refuses when none arrived.
//
// VerifyPeerCertificate is deliberately absent: crypto/tls would reject a
// handshake whose client certificate does not chain to the bundle, and the
// caller would see a TLS alert instead of a problem document saying which of
// the four things went wrong. The chain is verified in pkg/spiffe, where the
// refusal can be explained.
func clientCertConfig(trust *spiffe.Bundle) *tls.Config {
	if trust == nil {
		return nil
	}
	return &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
}
