package pop_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

const (
	agentID = "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"
	kid     = "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1"
	nonce   = "8f1c2b9d4e6a7c3f0b1d2e3a4c5b6d7e"
)

func newSigner(t *testing.T) (uaicrypto.Signer, ed25519.PublicKey) {
	t.Helper()
	s, pub, err := uaicrypto.GenerateEd25519Signer(kid)
	if err != nil {
		t.Fatal(err)
	}
	return s, pub
}

func signedRequest(t *testing.T, s uaicrypto.Signer, body []byte, domain uaicrypto.Domain) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://api.uai.world/v1/actions/attest", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := pop.SignRequest(s, req, body, domain, agentID, nonce); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

func resolver(pub crypto.PublicKey) pop.KeyResolver {
	return func(string, time.Time) (crypto.PublicKey, error) { return pub, nil }
}

// --- signature base ---------------------------------------------------------

func TestSignatureBaseFormat(t *testing.T) {
	// RFC 9421 section 2.5: one quoted component name per line, then
	// "@signature-params" with no trailing newline.
	req := httptest.NewRequest(http.MethodPost, "https://api.uai.world/v1/actions/attest", nil)
	req.Header.Set("Content-Digest", "sha-256=:abc:")
	req.Header.Set("UAI-Agent-Id", agentID)
	req.Header.Set("UAI-Nonce", nonce)

	p := pop.Params{
		Components: pop.DefaultComponents,
		Created:    1790000524,
		KeyID:      kid,
		Alg:        "ed25519",
		Tag:        string(uaicrypto.DomainAttestation),
	}
	base, err := pop.SignatureBase(pop.FromRequest(req, "https"), p)
	if err != nil {
		t.Fatal(err)
	}
	want := `"@method": POST` + "\n" +
		`"@target-uri": https://api.uai.world/v1/actions/attest` + "\n" +
		`"content-digest": sha-256=:abc:` + "\n" +
		`"uai-agent-id": ` + agentID + "\n" +
		`"uai-nonce": ` + nonce + "\n" +
		`"@signature-params": ("@method" "@target-uri" "content-digest" "uai-agent-id" "uai-nonce")` +
		`;created=1790000524;keyid="` + kid + `";alg="ed25519";tag="UAI-v1:attestation"`
	if string(base) != want {
		t.Fatalf("signature base differs\n got:\n%s\nwant:\n%s", base, want)
	}
	if strings.HasSuffix(string(base), "\n") {
		t.Fatal("signature base must not end with a newline")
	}
}

func TestSignatureBaseRejectsMissingComponent(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://api.uai.world/v1/actions/attest", nil)
	p := pop.Params{Components: []string{"@method", "content-digest"}, Created: 1}
	if _, err := pop.SignatureBase(pop.FromRequest(req, "https"), p); !errors.Is(err, pop.ErrMissingComponent) {
		t.Fatalf("expected ErrMissingComponent, got %v", err)
	}
}

func TestSignatureInputRoundTrip(t *testing.T) {
	p := pop.Params{
		Components: pop.DefaultComponents, Created: 1790000524, Expires: 1790000824,
		KeyID: kid, Alg: "ed25519", Tag: string(uaicrypto.DomainVote),
	}
	label, back, err := pop.ParseSignatureInput("uai=" + p.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	if label != "uai" {
		t.Fatalf("label = %q", label)
	}
	if back.Created != p.Created || back.Expires != p.Expires || back.KeyID != p.KeyID ||
		back.Alg != p.Alg || back.Tag != p.Tag || len(back.Components) != len(p.Components) {
		t.Fatalf("params did not survive the round trip: %+v", back)
	}
}

// --- content digest ---------------------------------------------------------

func TestContentDigest(t *testing.T) {
	body := []byte(`{"a":1}`)
	d := pop.ContentDigest(body)
	if !strings.HasPrefix(d, "sha-256=:") || !strings.HasSuffix(d, ":") {
		t.Fatalf("digest form = %q", d)
	}
	if err := pop.VerifyContentDigest(d, body); err != nil {
		t.Fatalf("digest should verify: %v", err)
	}
	if err := pop.VerifyContentDigest(d, []byte(`{"a":2}`)); !errors.Is(err, pop.ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch, got %v", err)
	}
}

// --- end to end -------------------------------------------------------------

func TestSignAndVerify(t *testing.T) {
	s, pub := newSigner(t)
	body := []byte(`{"event_id":"01JY8RA3C7K2V9M0QW4T6Z8XPD"}`)
	req := signedRequest(t, s, body, uaicrypto.DomainAttestation)

	p, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.KeyID != kid || p.Tag != string(uaicrypto.DomainAttestation) {
		t.Fatalf("unexpected params: %+v", p)
	}
}

func TestUnsignedRequestRejected(t *testing.T) {
	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "https://api.uai.world/v1/actions/attest", nil)
	// INV-002: an identifier in a header or body is not proof of anything.
	req.Header.Set(pop.HeaderAgentID, agentID)
	if _, err := pop.VerifyRequest(req, body, pop.VerifyOptions{Resolve: resolver(nil)}); !errors.Is(err, pop.ErrNoSignature) {
		t.Fatalf("expected ErrNoSignature, got %v", err)
	}
}

func TestTamperedBodyRejected(t *testing.T) {
	s, pub := newSigner(t)
	body := []byte(`{"amount":100}`)
	req := signedRequest(t, s, body, uaicrypto.DomainAttestation)

	tampered := []byte(`{"amount":1000000}`)
	_, err := pop.VerifyRequest(req, tampered, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub),
	})
	if !errors.Is(err, pop.ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch, got %v", err)
	}
}

func TestTamperedTargetRejected(t *testing.T) {
	s, pub := newSigner(t)
	body := []byte(`{}`)
	req := signedRequest(t, s, body, uaicrypto.DomainAttestation)

	// Same signature, different resource: a captured call to one endpoint must
	// not authorize another.
	req.URL.Path = "/v1/revocations/01JY8RF60000000000000000ZZ/execute"
	if _, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub),
	}); err == nil {
		t.Fatal("a signature verified against a different target URI")
	}
}

func TestTamperedAgentIdRejected(t *testing.T) {
	s, pub := newSigner(t)
	body := []byte(`{}`)
	req := signedRequest(t, s, body, uaicrypto.DomainAttestation)

	req.Header.Set(pop.HeaderAgentID, "uai:agent:01JY8R9ZB00000000000000000")
	if _, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub),
	}); err == nil {
		t.Fatal("the claimed identity was altered without invalidating the signature")
	}
}

func TestCrossDomainRejected(t *testing.T) {
	s, pub := newSigner(t)
	body := []byte(`{}`)
	// Signed as a vote, presented to an attestation endpoint.
	req := signedRequest(t, s, body, uaicrypto.DomainVote)
	_, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub),
	})
	if !errors.Is(err, pop.ErrTagMismatch) {
		t.Fatalf("expected ErrTagMismatch, got %v", err)
	}
}

func TestRelabelledTagStillFails(t *testing.T) {
	s, pub := newSigner(t)
	body := []byte(`{}`)
	req := signedRequest(t, s, body, uaicrypto.DomainVote)

	// Rewriting the tag in the header does not help: the tag is inside the
	// signed base, so the signature no longer matches.
	input := req.Header.Get(pop.HeaderSignatureInput)
	req.Header.Set(pop.HeaderSignatureInput,
		strings.Replace(input, `tag="UAI-v1:vote"`, `tag="UAI-v1:attestation"`, 1))

	if _, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub),
	}); !errors.Is(err, uaicrypto.ErrBadSignature) {
		t.Fatalf("expected the signature to fail, got %v", err)
	}
}

func TestPartialCoverageRejected(t *testing.T) {
	s, pub := newSigner(t)
	body := []byte(`{"amount":100}`)
	req, err := http.NewRequest(http.MethodPost, "https://api.uai.world/v1/actions/attest", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(pop.HeaderAgentID, agentID)
	req.Header.Set(pop.HeaderNonce, nonce)
	req.Header.Set(pop.HeaderContentDigest, pop.ContentDigest(body))

	// A caller signs only the method, leaving the body and identity uncovered.
	p := pop.Params{
		Components: []string{"@method"}, Created: time.Now().Unix(),
		KeyID: kid, Alg: "ed25519", Tag: string(uaicrypto.DomainAttestation),
	}
	base, err := pop.SignatureBase(pop.FromRequest(req, "https"), p)
	if err != nil {
		t.Fatal(err)
	}
	_, sig, err := uaicrypto.SignHTTPSignatureBase(s, base)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(pop.HeaderSignatureInput, "uai="+p.Serialize())
	req.Header.Set(pop.HeaderSignature, "uai=:"+b64(sig)+":")

	if _, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub),
	}); !errors.Is(err, pop.ErrComponentNotCovered) {
		t.Fatalf("expected ErrComponentNotCovered, got %v", err)
	}
}

func TestClockSkewRejected(t *testing.T) {
	s, pub := newSigner(t)
	body := []byte(`{}`)
	req := signedRequest(t, s, body, uaicrypto.DomainAttestation)

	future := func() time.Time { return time.Now().Add(10 * time.Minute) }
	if _, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub), Now: future,
	}); !errors.Is(err, pop.ErrStale) {
		t.Fatalf("expected ErrStale, got %v", err)
	}
}

func TestReplayRejected(t *testing.T) {
	s, pub := newSigner(t)
	body := []byte(`{}`)
	req := signedRequest(t, s, body, uaicrypto.DomainAttestation)
	cache := pop.NewMemoryNonceCache()
	opts := pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub), Nonces: cache,
	}
	if _, err := pop.VerifyRequest(req, body, opts); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	if _, err := pop.VerifyRequest(req, body, opts); !errors.Is(err, pop.ErrReplay) {
		t.Fatalf("expected ErrReplay on the second use, got %v", err)
	}
}

func TestInvalidRequestDoesNotConsumeANonce(t *testing.T) {
	// Replay is checked last on purpose. Otherwise an attacker could burn a
	// legitimate caller's nonces by replaying them with a broken signature.
	s, pub := newSigner(t)
	body := []byte(`{}`)
	cache := pop.NewMemoryNonceCache()
	opts := pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub), Nonces: cache,
	}

	bad := signedRequest(t, s, body, uaicrypto.DomainAttestation)
	bad.Header.Set(pop.HeaderSignature, "uai=:"+b64([]byte("not a signature"))+":")
	if _, err := pop.VerifyRequest(bad, body, opts); err == nil {
		t.Fatal("a broken signature verified")
	}

	good := signedRequest(t, s, body, uaicrypto.DomainAttestation)
	if _, err := pop.VerifyRequest(good, body, opts); err != nil {
		t.Fatalf("the nonce was consumed by a rejected request: %v", err)
	}
}

func TestResolverReceivesCreationTime(t *testing.T) {
	// A historical signature must be verified against the key valid when it was
	// made. Resolving "the current key" silently invalidates history on every
	// rotation, which is the most common verification bug in systems like this.
	s, pub := newSigner(t)
	body := []byte(`{}`)
	req := signedRequest(t, s, body, uaicrypto.DomainAttestation)

	var seen time.Time
	_, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation,
		Resolve: func(_ string, at time.Time) (crypto.PublicKey, error) {
			seen = at
			return pub, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen.IsZero() {
		t.Fatal("the resolver was not given a point in time")
	}
	if d := time.Since(seen); d > time.Minute || d < -time.Minute {
		t.Fatalf("resolver received %s, which is not the signature creation time", seen)
	}
}

func TestRotatedKeyDoesNotInvalidateHistory(t *testing.T) {
	s, oldPub := newSigner(t)
	body := []byte(`{}`)
	req := signedRequest(t, s, body, uaicrypto.DomainAttestation)

	_, newPub, err := uaicrypto.GenerateEd25519Signer(kid)
	if err != nil {
		t.Fatal(err)
	}
	rotatedAt := time.Now().Add(time.Hour)

	resolve := func(_ string, at time.Time) (crypto.PublicKey, error) {
		if at.Before(rotatedAt) {
			return oldPub, nil
		}
		return newPub, nil
	}
	if _, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolve,
	}); err != nil {
		t.Fatalf("a signature made before rotation must stay verifiable: %v", err)
	}
}

func TestECDSASigner(t *testing.T) {
	s, pub, err := uaicrypto.GenerateECDSASigner(uaicrypto.AlgES256, kid)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{}`)
	req := signedRequest(t, s, body, uaicrypto.DomainAttestation)
	if _, err := pop.VerifyRequest(req, body, pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: resolver(pub),
	}); err != nil {
		t.Fatalf("ES256 proof of possession failed: %v", err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
