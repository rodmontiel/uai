// Package spiffe verifies X509-SVIDs against a trust bundle.
//
// This is the half of §9.1 that was missing. A binding statement carries
// `svid_spiffe_id`, `svid_cert_hash` and `image_digest`, signed by the agent's
// own key -- which makes it the agent attesting its own runtime. §9.1 step 6
// says the registry must "verify SVID chain + verify SVID subject matches
// uai_id", and until this package existed nothing did: the fields were checked
// for presence and stored.
//
// Nothing here talks to SPIRE. It takes a chain and a bundle and answers
// whether the chain is a valid X509-SVID for that trust domain, which is what a
// relying party re-reading a stored binding years from now has to be able to do
// with the certificate alone. No dependencies, no I/O, no clock of its own.
//
// Reference: SPIFFE X509-SVID specification.
package spiffe

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Scheme is the only URI scheme a SPIFFE ID may use.
const Scheme = "spiffe"

var (
	// ErrInvalidID is returned for anything that is not a SPIFFE ID.
	ErrInvalidID = errors.New("spiffe: not a SPIFFE ID")
	// ErrInvalidSVID is returned when a certificate breaks an X509-SVID rule.
	ErrInvalidSVID = errors.New("spiffe: not a valid X509-SVID")
	// ErrUntrusted is returned when a chain does not verify against the bundle.
	ErrUntrusted = errors.New("spiffe: chain does not verify against the trust bundle")
	// ErrWrongSubject is returned when a genuine SVID from the right trust
	// domain is used to attest an identity it does not name. This is the
	// refusal §9.1 step 6 exists to produce.
	ErrWrongSubject = errors.New("spiffe: the SVID does not attest this identity")
	// ErrWrongTrustDomain is returned when a valid SVID belongs elsewhere.
	//
	// Separate from ErrUntrusted because it is a different accusation: the
	// certificate is genuine and was issued by somebody we are not federated
	// with. Collapsing the two would report a federation gap as a forgery.
	ErrWrongTrustDomain = errors.New("spiffe: SVID belongs to another trust domain")
)

// ID is a parsed SPIFFE ID: spiffe://<trust domain><path>.
type ID struct {
	TrustDomain string
	Path        string // "" or a path beginning with "/"
}

// ParseID parses and validates a SPIFFE ID.
func ParseID(s string) (ID, error) {
	u, err := url.Parse(s)
	if err != nil {
		return ID{}, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	switch {
	case u.Scheme != Scheme:
		return ID{}, fmt.Errorf("%w: scheme is %q, want %q", ErrInvalidID, u.Scheme, Scheme)
	case u.Host == "":
		return ID{}, fmt.Errorf("%w: no trust domain in %q", ErrInvalidID, s)
	case u.User != nil:
		return ID{}, fmt.Errorf("%w: userinfo is not allowed", ErrInvalidID)
	// A query or fragment would make two IDs that name the same workload
	// compare unequal, and comparison is the only thing IDs are used for.
	case u.RawQuery != "" || u.Fragment != "":
		return ID{}, fmt.Errorf("%w: query and fragment are not allowed", ErrInvalidID)
	case u.Port() != "":
		return ID{}, fmt.Errorf("%w: a trust domain has no port", ErrInvalidID)
	case strings.ToLower(u.Host) != u.Host:
		return ID{}, fmt.Errorf("%w: trust domain %q is not lowercase", ErrInvalidID, u.Host)
	}
	if strings.Contains(u.Path, "//") || strings.HasSuffix(u.Path, "/") {
		return ID{}, fmt.Errorf("%w: %q has an empty path segment", ErrInvalidID, s)
	}
	for _, seg := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if seg == "." || seg == ".." {
			return ID{}, fmt.Errorf("%w: %q contains a relative segment", ErrInvalidID, s)
		}
	}
	return ID{TrustDomain: u.Host, Path: u.Path}, nil
}

// String renders the ID.
func (id ID) String() string { return Scheme + "://" + id.TrustDomain + id.Path }

// MemberOf reports whether the ID belongs to a trust domain.
func (id ID) MemberOf(trustDomain string) bool { return id.TrustDomain == trustDomain }

// Bundle is the set of CA certificates for one trust domain.
type Bundle struct {
	TrustDomain string
	roots       *x509.CertPool
	count       int
}

// ParseBundle reads a PEM trust bundle for a trust domain.
func ParseBundle(trustDomain string, pemBytes []byte) (*Bundle, error) {
	if trustDomain == "" {
		return nil, fmt.Errorf("%w: a bundle without a trust domain authenticates nothing", ErrInvalidID)
	}
	certs, err := ParseChainPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		// An empty pool verifies nothing, but a caller who did not notice would
		// read every refusal as a forgery rather than as a missing bundle.
		return nil, fmt.Errorf("%w: the bundle for %s contains no certificates",
			ErrInvalidSVID, trustDomain)
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return &Bundle{TrustDomain: trustDomain, roots: pool, count: len(certs)}, nil
}

// Size is the number of CA certificates in the bundle.
func (b *Bundle) Size() int { return b.count }

// ParseChainPEM decodes a PEM block sequence into certificates, leaf first.
func ParseChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			// Skipped rather than refused: a bundle file that also carries a
			// key or a comment block is common, and a private key landing in
			// one is a problem for whoever wrote it, not a parse error here.
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSVID, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// SVID is a chain that verified.
type SVID struct {
	ID        ID
	Leaf      *x509.Certificate
	CertHash  string    // "sha256:…" over the leaf's DER, the form §9.1 stores
	ExpiresAt time.Time // the leaf's NotAfter
}

// Verify checks a chain against a bundle and returns the SVID it proves.
//
// `now` is passed in rather than read, so that re-verifying a binding recorded
// last year asks "was this valid then", which is the only question worth asking
// about it. A verifier using its own clock would report every expired-but-once-
// valid SVID as a forgery.
func Verify(chain []*x509.Certificate, b *Bundle, now time.Time) (*SVID, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: no trust bundle", ErrUntrusted)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: empty chain", ErrInvalidSVID)
	}
	leaf := chain[0]
	id, err := LeafID(leaf)
	if err != nil {
		return nil, err
	}
	if !id.MemberOf(b.TrustDomain) {
		return nil, fmt.Errorf("%w: %s is in %q, the bundle is for %q",
			ErrWrongTrustDomain, id, id.TrustDomain, b.TrustDomain)
	}

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	// ExtKeyUsage is deliberately ANY. An X509-SVID is used for both sides of
	// an mTLS connection and for nothing else, and SPIRE does not always set
	// the extension; requiring ClientAuth here would refuse valid SVIDs for a
	// property this package is not the right place to assert.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: b.roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUntrusted, err)
	}

	sum := sha256.Sum256(leaf.Raw)
	return &SVID{
		ID: id, Leaf: leaf,
		CertHash:  "sha256:" + hex.EncodeToString(sum[:]),
		ExpiresAt: leaf.NotAfter,
	}, nil
}

// LeafID extracts and validates the SPIFFE ID of a leaf certificate.
//
// The X509-SVID rules enforced here are the ones that decide whether a
// certificate can be MISTAKEN for something it is not: a leaf that is also a CA
// could sign SVIDs for any workload in the trust domain, and a leaf carrying
// two URI SANs has two identities, which means a verifier reading the first and
// a verifier reading the second disagree about who acted.
func LeafID(leaf *x509.Certificate) (ID, error) {
	if leaf == nil {
		return ID{}, fmt.Errorf("%w: no leaf certificate", ErrInvalidSVID)
	}
	if len(leaf.URIs) != 1 {
		return ID{}, fmt.Errorf("%w: a leaf carries exactly one URI SAN, this one has %d",
			ErrInvalidSVID, len(leaf.URIs))
	}
	if leaf.IsCA {
		return ID{}, fmt.Errorf("%w: the leaf is a CA certificate, so it could issue SVIDs "+
			"for any workload in its trust domain", ErrInvalidSVID)
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 || leaf.KeyUsage&x509.KeyUsageCRLSign != 0 {
		return ID{}, fmt.Errorf("%w: the leaf may sign certificates or CRLs", ErrInvalidSVID)
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return ID{}, fmt.Errorf("%w: the leaf cannot make digital signatures", ErrInvalidSVID)
	}
	return ParseID(leaf.URIs[0].String())
}
