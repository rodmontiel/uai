package api_test

// Phase 12: the registry verifies where an agent runs instead of believing it.
//
// Before this, a bind carried svid_spiffe_id, svid_cert_hash and image_digest
// signed by the AGENT's own key, and the row was stored with
// attestor = "self-declared". §9.1 step 6 says the registry must "verify SVID
// chain + verify SVID subject matches uai_id"; nothing did.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/spiffe"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

const testTrustDomain = "uai.test"

// signingCA stands in for the SPIRE server's CA.
type signingCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newSigningCA(t *testing.T) *signingCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "spire test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &signingCA{cert: cert, key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// svidFor issues an X509-SVID for a SPIFFE path.
func (c *signingCA) svidFor(t *testing.T, path string, ttl time.Duration) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse("spiffe://" + testTrustDomain + path)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), URIs: []*url.URL{uri},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(ttl),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func ulidOf(uaiID string) string {
	if i := strings.LastIndex(uaiID, ":"); i >= 0 {
		return uaiID[i+1:]
	}
	return uaiID
}

// attestingServer is this env's server with runtime attestation switched on.
func (e *env) attestingServer(t *testing.T, ca *signingCA) http.Handler {
	t.Helper()
	bundle, err := spiffe.ParseBundle(testTrustDomain, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	return api.NewServer(e.db, api.WithScheme("http"), api.WithSPIFFE(bundle)).Routes()
}

// bind runs the two-call exchange of §9.1.1 against a handler, optionally
// presenting a client certificate chain.
func (e *env) bind(t *testing.T, srv http.Handler, uaiID string, signer uaicrypto.Signer,
	body map[string]any, chain []*x509.Certificate) (int, map[string]any) {
	t.Helper()

	send := func(payload map[string]any) (int, map[string]any) {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		url := "http://api.uai.test/v1/agents/" + uaiID + "/bind"
		req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(string(raw)))
		req.Header.Set("Idempotency-Key", nonce())
		if err := pop.SignRequest(signer, req, raw, uaicrypto.DomainChallenge, uaiID, nonce()); err != nil {
			t.Fatal(err)
		}
		if chain != nil {
			// The handler reads r.TLS.PeerCertificates; setting it directly
			// tests the check without standing up a TLS listener, which would
			// test crypto/tls rather than this.
			req.TLS = &tls.ConnectionState{PeerCertificates: chain, HandshakeComplete: true}
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, challengeBody := send(map[string]any{})
	if code != http.StatusAccepted {
		return code, challengeBody
	}
	// §9.1: the signature covers the challenge AND the SVID identifiers, so
	// that neither is forgeable by somebody holding only the other. A real
	// client knows both -- it just fetched the SVID -- so the test fills them
	// from the certificate unless it is deliberately testing a disagreement.
	if chain != nil && body["svid_spiffe_id"] == nil {
		leaf := chain[0]
		body["svid_spiffe_id"] = leaf.URIs[0].String()
		sum := sha256.Sum256(leaf.Raw)
		body["svid_cert_hash"] = "sha256:" + hex.EncodeToString(sum[:])
	}
	value, _ := challengeBody["challenge"].(string)
	audience, _ := challengeBody["audience"].(string)

	stmt := challenge.Binding{
		Challenge: value, Operation: challenge.OpBind, UAIID: uaiID, Audience: audience,
		SpiffeID: str(body["svid_spiffe_id"]), SVIDCertHash: str(body["svid_cert_hash"]),
		ImageDigest: str(body["image_digest"]),
	}
	sig, err := challenge.SignBinding(signer, stmt)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"challenge": value, "signature": sig}
	for k, v := range body {
		payload[k] = v
	}
	return send(payload)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// ── the attack §9.1 step 6 exists to stop ───────────────────────────────────

// TestAGenuineSVIDCannotBindAnotherAgent.
//
// The certificate is real, current, and issued by the SPIRE CA this registry
// trusts. It simply belongs to a different agent. Without the subject check,
// any workload holding any valid SVID in the trust domain could bind itself to
// any identity in the registry -- and the binding would verify forever after.
func TestAGenuineSVIDCannotBindAnotherAgent(t *testing.T) {
	e := setup(t)
	ca := newSigningCA(t)
	srv := e.attestingServer(t, ca)

	victim, _ := e.registeredWithKey(t)
	attacker, attackerKey := e.registeredWithKey(t)

	// The attacker's own, entirely legitimate SVID.
	svid := ca.svidFor(t, "/agents/"+ulidOf(attacker.UAIID)+"/i/7f6a92", time.Hour)

	code, out := e.bind(t, srv, victim.UAIID, attackerKey, map[string]any{
		"svid_spiffe_id": "spiffe://" + testTrustDomain + "/agents/" + ulidOf(victim.UAIID) + "/i/1",
		"svid_cert_hash": "sha256:" + strings.Repeat("d", 64),
	}, []*x509.Certificate{svid})

	// PoP refuses first -- the attacker is not the victim -- and that is the
	// outer door. What matters is that it is not the only one.
	if code < 400 {
		t.Fatalf("an agent bound another identity: %d %v", code, out)
	}

	// So run the same attack as the victim itself, holding the attacker's SVID.
	// This is the case PoP cannot see: the right agent, the wrong runtime.
	victimAgent, victimKey := e.registeredWithKey(t)
	svid = ca.svidFor(t, "/agents/"+ulidOf(attacker.UAIID)+"/i/7f6a92", time.Hour)
	code, out = e.bind(t, srv, victimAgent.UAIID, victimKey, map[string]any{},
		[]*x509.Certificate{svid})
	if code != http.StatusForbidden {
		t.Fatalf("a bind with another agent's SVID returned %d, want 403: %v", code, out)
	}
	if title, _ := out["title"].(string); title != "UAI_RUNTIME_IDENTITY_MISMATCH" {
		t.Errorf("code = %q, want UAI_RUNTIME_IDENTITY_MISMATCH", title)
	}
}

func TestBindingWithoutAnSVIDIsRefusedWhenTheRegistryAttests(t *testing.T) {
	e := setup(t)
	ca := newSigningCA(t)
	srv := e.attestingServer(t, ca)
	agent, key := e.registeredWithKey(t)

	code, out := e.bind(t, srv, agent.UAIID, key, map[string]any{
		"svid_spiffe_id": "spiffe://" + testTrustDomain + "/agents/" + ulidOf(agent.UAIID) + "/i/1",
		"svid_cert_hash": "sha256:" + strings.Repeat("d", 64),
	}, nil)

	if code != http.StatusUnauthorized {
		t.Fatalf("a bind with no client certificate returned %d, want 401: %v", code, out)
	}
	if title, _ := out["title"].(string); title != "UAI_RUNTIME_ATTESTATION_REQUIRED" {
		t.Errorf("code = %q, want UAI_RUNTIME_ATTESTATION_REQUIRED", title)
	}
	if v := e.verifyVerdict(t, agent.UAIID); v["verified"] != false {
		t.Error("the agent became verified on a refused bind")
	}
}

func TestAnSVIDFromAnUntrustedCAIsRefused(t *testing.T) {
	e := setup(t)
	ca, rogue := newSigningCA(t), newSigningCA(t)
	srv := e.attestingServer(t, ca)
	agent, key := e.registeredWithKey(t)

	// Right trust domain, right path, right agent. Nobody we trust signed it.
	svid := rogue.svidFor(t, "/agents/"+ulidOf(agent.UAIID)+"/i/1", time.Hour)
	code, out := e.bind(t, srv, agent.UAIID, key, map[string]any{}, []*x509.Certificate{svid})
	if code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %v", code, out)
	}
	if title, _ := out["title"].(string); title != "UAI_RUNTIME_NOT_ATTESTED" {
		t.Errorf("code = %q, want UAI_RUNTIME_NOT_ATTESTED", title)
	}
}

// TestTheStatementMustAgreeWithTheCertificate: the statement is what gets
// stored and re-verified years later, so it has to say what is true.
func TestTheStatementMustAgreeWithTheCertificate(t *testing.T) {
	e := setup(t)
	ca := newSigningCA(t)
	srv := e.attestingServer(t, ca)
	agent, key := e.registeredWithKey(t)

	svid := ca.svidFor(t, "/agents/"+ulidOf(agent.UAIID)+"/i/real", time.Hour)
	code, out := e.bind(t, srv, agent.UAIID, key, map[string]any{
		"svid_spiffe_id": "spiffe://" + testTrustDomain + "/agents/" + ulidOf(agent.UAIID) + "/i/invented",
		"svid_cert_hash": "sha256:" + strings.Repeat("d", 64),
	}, []*x509.Certificate{svid})

	if code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %v", code, out)
	}
	if title, _ := out["title"].(string); title != "UAI_RUNTIME_MISMATCH" {
		t.Errorf("code = %q, want UAI_RUNTIME_MISMATCH", title)
	}
}

// ── the honest case, and what it is worth ───────────────────────────────────

// TestAnAttestedBindingRecordsTheAttestorAndTheRealExpiry.
func TestAnAttestedBindingRecordsTheAttestorAndTheRealExpiry(t *testing.T) {
	e := setup(t)
	ca := newSigningCA(t)
	srv := e.attestingServer(t, ca)
	agent, key := e.registeredWithKey(t)

	// Five minutes, not the hour SVIDTTL used to assume.
	svid := ca.svidFor(t, "/agents/"+ulidOf(agent.UAIID)+"/i/7f6a92", 5*time.Minute)
	code, out := e.bind(t, srv, agent.UAIID, key, map[string]any{}, []*x509.Certificate{svid})
	if code != http.StatusOK {
		t.Fatalf("a genuine SVID was refused: %d %v", code, out)
	}
	if out["status"] != "ACTIVE" {
		t.Fatalf("status = %v", out["status"])
	}

	var attestor, spiffeID string
	var expires time.Time
	if err := e.db.Pool().QueryRow(t.Context(), `
		SELECT attestor, spiffe_id, expires_at FROM runtime_identities
		 WHERE agent_id = $1 ORDER BY bound_at DESC LIMIT 1`, agent.ID).
		Scan(&attestor, &spiffeID, &expires); err != nil {
		t.Fatal(err)
	}
	if attestor != "spiffe://"+testTrustDomain {
		t.Errorf("attestor = %q, want the trust domain that vouched for it", attestor)
	}
	if !strings.HasSuffix(spiffeID, "/i/7f6a92") {
		t.Errorf("spiffe_id = %q — it must come from the certificate", spiffeID)
	}
	// The certificate's own NotAfter. A row claiming an hour would report the
	// runtime as current long after the attestor stopped vouching for it.
	if d := time.Until(expires); d > 10*time.Minute {
		t.Errorf("expires in %s; the SVID expires in 5 minutes", d.Round(time.Second))
	}
}

// TestAttestationAloneDoesNotRaiseTheAssuranceLevel is §6.8 held to its word.
//
// The runtime is attested and the owner is still self-asserted, so the identity
// is UAI-AL0 -- and /verify says which dimension holds it there, because a bare
// AL0 is indistinguishable from a misconfiguration.
func TestAttestationAloneDoesNotRaiseTheAssuranceLevel(t *testing.T) {
	e := setup(t)
	ca := newSigningCA(t)
	srv := e.attestingServer(t, ca)
	agent, key := e.registeredWithKey(t)

	svid := ca.svidFor(t, "/agents/"+ulidOf(agent.UAIID)+"/i/1", time.Hour)
	if code, out := e.bind(t, srv, agent.UAIID, key, map[string]any{}, []*x509.Certificate{svid}); code != http.StatusOK {
		t.Fatalf("bind: %d %v", code, out)
	}

	v := e.verifyVerdict(t, agent.UAIID)
	if v["assurance_level"] != "UAI-AL0" {
		t.Errorf("assurance = %v, want UAI-AL0: an attested runtime does not verify an owner", v["assurance_level"])
	}
	if v["assurance_limited_by"] != "owner verification" {
		t.Errorf("limited_by = %v, want %q", v["assurance_limited_by"], "owner verification")
	}
	if d, _ := v["assurance_detail"].(string); !strings.Contains(d, "self-asserted") {
		t.Errorf("detail = %q; it has to say what would have to change", d)
	}
}

// TestWithoutABundleTheRuntimeIsRecordedAsSelfDeclared keeps `make dev` working
// and keeps it honest: the binding happens, and it is worth nothing toward the
// runtime dimension.
func TestWithoutABundleTheRuntimeIsRecordedAsSelfDeclared(t *testing.T) {
	e := setup(t)
	agent, key := e.registeredWithKey(t)

	code, out := e.bind(t, e.srv, agent.UAIID, key, map[string]any{
		"svid_spiffe_id": "spiffe://" + testTrustDomain + "/agents/" + ulidOf(agent.UAIID) + "/i/1",
		"svid_cert_hash": "sha256:" + strings.Repeat("d", 64),
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("bind: %d %v", code, out)
	}
	var attestor string
	if err := e.db.Pool().QueryRow(t.Context(), `
		SELECT attestor FROM runtime_identities WHERE agent_id = $1
		 ORDER BY bound_at DESC LIMIT 1`, agent.ID).Scan(&attestor); err != nil {
		t.Fatal(err)
	}
	if attestor != "self-declared" {
		t.Errorf("attestor = %q, want self-declared", attestor)
	}
	if v := e.verifyVerdict(t, agent.UAIID); v["assurance_level"] != "UAI-AL0" {
		t.Errorf("assurance = %v", v["assurance_level"])
	}
}
