package spiffe_test

// Certificates are generated here rather than committed as vectors. An X509
// vector carries a NotAfter, so a committed one is a test that starts failing
// on a date nobody chose, and the usual repair is to widen the window until the
// expiry check no longer checks anything.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/spiffe"
)

const (
	trustDomain = "uai.test"
	agentULID   = "01JY8R9ZAF392N7QX2T81JH6KM"
	agentUAIID  = "uai:agent:" + agentULID
)

var base = time.Date(2027, 6, 1, 12, 0, 0, 0, time.UTC)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newCA(t *testing.T, name string) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             base.Add(-24 * time.Hour),
		NotAfter:              base.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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
	return &ca{cert: cert, key: key, der: der}
}

func (c *ca) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// leafOpts lets a test build the one certificate that is wrong in one way.
type leafOpts struct {
	uris      []string
	isCA      bool
	keyUsage  x509.KeyUsage
	notBefore time.Time
	notAfter  time.Time
}

func (c *ca) leaf(t *testing.T, o leafOpts) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uris []*url.URL
	for _, u := range o.uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, parsed)
	}
	if o.notBefore.IsZero() {
		o.notBefore = base.Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = base.Add(time.Hour)
	}
	if o.keyUsage == 0 {
		o.keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: ""},
		URIs:         uris, NotBefore: o.notBefore, NotAfter: o.notAfter,
		IsCA: o.isCA, KeyUsage: o.keyUsage, BasicConstraintsValid: true,
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

func agentID(ulid string) string {
	return "spiffe://" + trustDomain + "/agents/" + ulid + "/i/7f6a92"
}

// ── the honest case ─────────────────────────────────────────────────────────

func TestAGenuineSVIDAttestsItsAgent(t *testing.T) {
	root := newCA(t, "uai.test root")
	bundle, err := spiffe.ParseBundle(trustDomain, root.pem())
	if err != nil {
		t.Fatal(err)
	}
	leaf := root.leaf(t, leafOpts{uris: []string{agentID(agentULID)}})

	svid, err := spiffe.Verify([]*x509.Certificate{leaf}, bundle, base)
	if err != nil {
		t.Fatalf("a genuine SVID was refused: %v", err)
	}
	if got := svid.ID.String(); got != agentID(agentULID) {
		t.Errorf("ID = %s", got)
	}
	if err := svid.Attests(agentUAIID); err != nil {
		t.Errorf("the SVID did not attest its own agent: %v", err)
	}
	if len(svid.CertHash) != len("sha256:")+64 {
		t.Errorf("cert hash = %q", svid.CertHash)
	}
	if !svid.ExpiresAt.Equal(leaf.NotAfter) {
		t.Errorf("ExpiresAt = %s, want %s", svid.ExpiresAt, leaf.NotAfter)
	}
}

// ── the attacks ─────────────────────────────────────────────────────────────

// TestAnSVIDCannotAttestAnotherAgent is §9.1 step 6.
//
// The certificate is genuine, current, and issued by the right CA. It simply
// belongs to a different agent. Without this check a workload holding ANY valid
// SVID in the trust domain could bind itself to ANY identity in the registry.
func TestAnSVIDCannotAttestAnotherAgent(t *testing.T) {
	root := newCA(t, "uai.test root")
	bundle, _ := spiffe.ParseBundle(trustDomain, root.pem())
	other := "01JY8R9ZB00000000000000000"
	leaf := root.leaf(t, leafOpts{uris: []string{agentID(other)}})

	svid, err := spiffe.Verify([]*x509.Certificate{leaf}, bundle, base)
	if err != nil {
		t.Fatalf("the certificate itself is valid: %v", err)
	}
	err = svid.Attests(agentUAIID)
	if !errors.Is(err, spiffe.ErrWrongSubject) {
		t.Fatalf("an SVID for %s attested %s: %v", other, agentULID, err)
	}
}

func TestAnSVIDFromAnotherTrustDomainIsRefused(t *testing.T) {
	ours := newCA(t, "uai.test root")
	theirs := newCA(t, "evil.test root")
	bundle, _ := spiffe.ParseBundle(trustDomain, ours.pem())

	// Correctly formed, correctly signed -- by somebody else's CA, for
	// somebody else's trust domain, naming our agent.
	leaf := theirs.leaf(t, leafOpts{
		uris: []string{"spiffe://evil.test/agents/" + agentULID + "/i/1"}})

	_, err := spiffe.Verify([]*x509.Certificate{leaf}, bundle, base)
	if !errors.Is(err, spiffe.ErrWrongTrustDomain) {
		t.Fatalf("got %v, want ErrWrongTrustDomain", err)
	}
}

func TestASelfSignedSVIDIsRefused(t *testing.T) {
	root := newCA(t, "uai.test root")
	rogue := newCA(t, "rogue")
	bundle, _ := spiffe.ParseBundle(trustDomain, root.pem())

	// Right trust domain, right path, right shape. Nobody we trust signed it.
	leaf := rogue.leaf(t, leafOpts{uris: []string{agentID(agentULID)}})
	_, err := spiffe.Verify([]*x509.Certificate{leaf}, bundle, base)
	if !errors.Is(err, spiffe.ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}

func TestAnExpiredSVIDIsRefusedAtTheTimeItIsChecked(t *testing.T) {
	root := newCA(t, "uai.test root")
	bundle, _ := spiffe.ParseBundle(trustDomain, root.pem())
	leaf := root.leaf(t, leafOpts{
		uris:      []string{agentID(agentULID)},
		notBefore: base.Add(-2 * time.Hour), notAfter: base.Add(-time.Hour)})

	if _, err := spiffe.Verify([]*x509.Certificate{leaf}, bundle, base); !errors.Is(err, spiffe.ErrUntrusted) {
		t.Fatalf("an expired SVID verified: %v", err)
	}
	// And the same chain verifies for the moment it WAS valid. Re-checking a
	// binding recorded last year must ask "was this valid then".
	if _, err := spiffe.Verify([]*x509.Certificate{leaf}, bundle, base.Add(-90*time.Minute)); err != nil {
		t.Fatalf("a once-valid SVID did not verify at a time inside its window: %v", err)
	}
}

// TestALeafThatCouldIssueSVIDsIsRefused: a CA certificate with a SPIFFE ID can
// sign SVIDs for every workload in the trust domain. Accepting one as a leaf
// would hand its holder the whole namespace.
func TestALeafThatCouldIssueSVIDsIsRefused(t *testing.T) {
	root := newCA(t, "uai.test root")
	bundle, _ := spiffe.ParseBundle(trustDomain, root.pem())

	for name, o := range map[string]leafOpts{
		"a CA certificate": {uris: []string{agentID(agentULID)}, isCA: true,
			keyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature},
		"may sign certificates": {uris: []string{agentID(agentULID)},
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign},
		"may sign CRLs": {uris: []string{agentID(agentULID)},
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign},
	} {
		t.Run(name, func(t *testing.T) {
			leaf := root.leaf(t, o)
			if _, err := spiffe.Verify([]*x509.Certificate{leaf}, bundle, base); !errors.Is(err, spiffe.ErrInvalidSVID) {
				t.Fatalf("got %v, want ErrInvalidSVID", err)
			}
		})
	}
}

// TestALeafWithTwoIdentitiesIsRefused: two URI SANs means a verifier reading
// the first and a verifier reading the second disagree about who acted.
func TestALeafWithTwoIdentitiesIsRefused(t *testing.T) {
	root := newCA(t, "uai.test root")
	bundle, _ := spiffe.ParseBundle(trustDomain, root.pem())
	other := "01JY8R9ZB00000000000000000"

	for name, uris := range map[string][]string{
		"two SPIFFE IDs":               {agentID(agentULID), agentID(other)},
		"no URI SAN":                   {},
		"a SPIFFE ID and an https URI": {agentID(agentULID), "https://uai.test/agents/" + agentULID},
	} {
		t.Run(name, func(t *testing.T) {
			leaf := root.leaf(t, leafOpts{uris: uris})
			if _, err := spiffe.Verify([]*x509.Certificate{leaf}, bundle, base); !errors.Is(err, spiffe.ErrInvalidSVID) {
				t.Fatalf("got %v, want ErrInvalidSVID", err)
			}
		})
	}
}

// ── the identifier itself ───────────────────────────────────────────────────

func TestIDParsing(t *testing.T) {
	for _, bad := range []string{
		"", "uai.test/agents/x", "https://uai.test/agents/x",
		"spiffe://", "spiffe:///agents/x", "spiffe://uai.test:8443/agents/x",
		"spiffe://UAI.test/agents/x", "spiffe://u:p@uai.test/agents/x",
		"spiffe://uai.test/agents/x?q=1", "spiffe://uai.test/agents/x#f",
		"spiffe://uai.test/agents//x", "spiffe://uai.test/agents/x/",
		"spiffe://uai.test/agents/../admin",
	} {
		if _, err := spiffe.ParseID(bad); err == nil {
			t.Errorf("%q was accepted as a SPIFFE ID", bad)
		}
	}
	for _, good := range []string{
		"spiffe://uai.test", "spiffe://uai.test/agents/" + agentULID,
		agentID(agentULID), "spiffe://uai.world/ns/default/sa/gateway",
	} {
		if _, err := spiffe.ParseID(good); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}

func TestOnlyAnAgentPathNamesAnIdentity(t *testing.T) {
	for _, path := range []string{
		"spiffe://uai.test",
		"spiffe://uai.test/ns/default/sa/gateway",
		"spiffe://uai.test/agents/not-a-ulid",
		"spiffe://uai.test/agents/" + agentULID + "extra",
		"spiffe://uai.test/workload/" + agentULID,
	} {
		id, err := spiffe.ParseID(path)
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		if _, err := id.AgentULID(); err == nil {
			t.Errorf("%q was read as naming a UAI agent", path)
		}
	}
	// The gateway's own SVID is a workload SVID and names no agent. It must
	// not be usable to bind one.
	id, _ := spiffe.ParseID("spiffe://uai.test/ns/uai/sa/gateway")
	svid := &spiffe.SVID{ID: id}
	if err := svid.Attests(agentUAIID); err == nil {
		t.Error("the gateway's own SVID attested an agent identity")
	}
}

func TestAnEmptyBundleIsAnErrorNotAnEmptyPool(t *testing.T) {
	if _, err := spiffe.ParseBundle(trustDomain, []byte("")); err == nil {
		t.Fatal("an empty bundle was accepted; every chain would then be refused as forged")
	}
	if _, err := spiffe.ParseBundle("", []byte("x")); err == nil {
		t.Fatal("a bundle with no trust domain was accepted")
	}
}
