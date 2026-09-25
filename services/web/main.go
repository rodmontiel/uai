// Command uai-web serves the frontend and proxies the API.
//
// Serving both from one origin is a security decision, not a convenience one.
// It lets the page run under a Content-Security-Policy with no `unsafe-inline`
// and `connect-src 'self'`, which means injected script has nowhere to run and
// nowhere to send anything. A separate API origin would need CORS, and CORS is
// a list of exceptions to exactly those rules.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// contentSecurityPolicy is deliberately strict and deliberately short.
//
// No inline script and no eval: the verify page's job is to tell a visitor
// whether to trust an agent, and anything that could inject code into it could
// change that answer. Everything it runs is a module file from this origin, so
// a reader can compare what is served against what is in the repository.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; style-src 'self'; connect-src 'self'; " +
	"img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; " +
	"frame-ancestors 'none'"

func main() {
	var (
		addr   = flag.String("addr", envOr("UAI_WEB_ADDR", ":8081"), "listen address")
		root   = flag.String("root", envOr("UAI_WEB_ROOT", "web"), "directory to serve")
		apiURL = flag.String("api", envOr("UAI_API_URL", "http://127.0.0.1:8080"), "gateway to proxy /v1 to")
		apiCA  = flag.String("api-ca", os.Getenv("UAI_API_CA"), "PEM CA bundle to verify the gateway's certificate with")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	target, err := url.Parse(*apiURL)
	if err != nil {
		slog.Error("bad api url", "err", err)
		os.Exit(1)
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		slog.Error("bad root", "err", err)
		os.Exit(1)
	}
	if _, err := os.Stat(filepath.Join(abs, "index.html")); err != nil {
		slog.Error("no frontend at that root", "root", abs, "err", err)
		os.Exit(1)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	// When the gateway serves TLS with an SVID, its certificate chains to the
	// SPIRE bundle and to nothing a public trust store knows. Handing the proxy
	// that bundle is what lets it verify the gateway rather than skip the check
	// -- and skipping it here would mean the one hop a browser cannot see is
	// the one hop nobody authenticates.
	if *apiCA != "" {
		pem, err := os.ReadFile(*apiCA)
		if err != nil {
			slog.Error("cannot read the API CA bundle", "path", *apiCA, "err", err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			slog.Error("the API CA bundle contains no certificates", "path", *apiCA)
			os.Exit(1)
		}
		proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, MinVersion: tls.VersionTLS12,
		}}
		slog.Info("verifying the gateway against a private CA", "ca", *apiCA)
	}
	files := http.FileServer(http.Dir(abs))

	mux := http.NewServeMux()
	mux.Handle("/v1/", proxy)
	mux.Handle("/", files)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           headers(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		slog.Info("web listening", "addr", *addr, "root", abs, "api", target.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	slog.Info("web stopped")
}

// headers applies the security headers every response carries.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// A verification page should not be embeddable: a framed copy could be
		// overlaid to show a different verdict than the one it computed.
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			// Verification answers change: a cached "verified" for an identity
			// revoked five minutes ago is exactly the wrong thing to show.
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
