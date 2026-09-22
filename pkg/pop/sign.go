package pop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Header names used by the UAI API.
const (
	HeaderSignatureInput = "Signature-Input"
	HeaderSignature      = "Signature"
	HeaderContentDigest  = "Content-Digest"
	HeaderAgentID        = "UAI-Agent-Id"
	HeaderNonce          = "UAI-Nonce"

	// Label is the RFC 9421 signature label UAI uses.
	Label = "uai"
)

var (
	// ErrNoSignature is returned when the request carries no signature.
	ErrNoSignature = errors.New("pop: request is not signed")
	// ErrTagMismatch is returned when the signature's tag is not the expected UAI domain.
	ErrTagMismatch = errors.New("pop: signature tag does not match the expected domain")
	// ErrStale is returned when created/expires fall outside the accepted window.
	ErrStale = errors.New("pop: signature timestamp outside the accepted window")
	// ErrReplay is returned when a nonce has already been seen.
	ErrReplay = errors.New("pop: nonce already used")
	// ErrDigestMismatch is returned when Content-Digest does not match the body.
	ErrDigestMismatch = errors.New("pop: content digest does not match the body")
	// ErrComponentNotCovered is returned when a required component was not signed.
	ErrComponentNotCovered = errors.New("pop: required component is not covered by the signature")
)

// ContentDigest returns an RFC 9530 Content-Digest field value for a body.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// VerifyContentDigest checks a Content-Digest field value against a body.
func VerifyContentDigest(value string, body []byte) error {
	want := ContentDigest(body)
	// A message may carry several algorithms; sha-256 is the one UAI requires.
	for _, part := range strings.Split(value, ",") {
		if strings.TrimSpace(part) == strings.TrimSpace(want) {
			return nil
		}
	}
	return fmt.Errorf("%w: got %q, want %q", ErrDigestMismatch, value, want)
}

// SignRequest signs an outgoing request in place, setting Content-Digest,
// Signature-Input and Signature.
//
// The body is required because the digest is a covered component: signing
// without covering the body would leave it swappable, which is the whole point
// of proof of possession on a state-changing call.
func SignRequest(s uaicrypto.Signer, r *http.Request, body []byte, domain uaicrypto.Domain, agentID, nonce string) error {
	if !domain.Valid() {
		return fmt.Errorf("%w: %q", uaicrypto.ErrUnknownDomain, domain)
	}
	if agentID == "" || nonce == "" {
		return errors.New("pop: agent id and nonce are required")
	}
	r.Header.Set(HeaderContentDigest, ContentDigest(body))
	r.Header.Set(HeaderAgentID, agentID)
	r.Header.Set(HeaderNonce, nonce)

	httpAlg, err := uaicrypto.HTTPSignatureAlg(s.Algorithm())
	if err != nil {
		return err
	}
	p := Params{
		Components: DefaultComponents,
		Created:    time.Now().Unix(),
		KeyID:      s.KID(),
		Alg:        httpAlg,
		Tag:        string(domain),
	}
	scheme := "https"
	if r.URL != nil && r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	}
	base, err := SignatureBase(FromRequest(r, scheme), p)
	if err != nil {
		return err
	}
	_, sig, err := uaicrypto.SignHTTPSignatureBase(s, base)
	if err != nil {
		return err
	}
	r.Header.Set(HeaderSignatureInput, Label+"="+p.Serialize())
	r.Header.Set(HeaderSignature, Label+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

// KeyResolver returns the public key for a verification method as it was valid
// at a given time.
//
// The time argument is the point of this signature: a historical signature must
// be verified against the key material valid when it was made, not against the
// current key set. Resolving "the current key" is the most common verification
// bug in systems like this, and it silently invalidates history on every
// rotation.
type KeyResolver func(kid string, at time.Time) (crypto.PublicKey, error)

// NonceCache records nonces that have been seen, so a captured request cannot
// be replayed.
type NonceCache interface {
	// Seen records the nonce and reports whether it had already been used.
	Seen(kid, nonce string, expiry time.Time) bool
}

// VerifyOptions configure verification.
type VerifyOptions struct {
	// Domain is the context the caller is verifying in. The signature's tag
	// must match it.
	Domain uaicrypto.Domain
	// Resolve returns the public key valid at the signature's creation time.
	Resolve KeyResolver
	// MaxSkew is the accepted clock divergence. Zero means 300s.
	MaxSkew time.Duration
	// Nonces, when set, enforces single use.
	Nonces NonceCache
	// RequiredComponents must all be covered. Zero value means DefaultComponents.
	RequiredComponents []string
	// Now overrides the clock in tests.
	Now func() time.Time
	// Scheme is used to rebuild the absolute target URI of a server-side request.
	Scheme string
}

// VerifyRequest checks the proof of possession on an incoming request.
//
// The order of checks is deliberate: cheap structural checks first, then the
// digest, then the signature, then replay. Verifying a signature before
// checking that the covered components are the required ones would let a caller
// sign a subset of the message and still pass.
func VerifyRequest(r *http.Request, body []byte, opts VerifyOptions) (Params, error) {
	var zero Params
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	skew := opts.MaxSkew
	if skew == 0 {
		skew = 300 * time.Second
	}
	required := opts.RequiredComponents
	if required == nil {
		required = DefaultComponents
	}
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "https"
	}

	inputHeader := r.Header.Get(HeaderSignatureInput)
	sigHeader := r.Header.Get(HeaderSignature)
	if inputHeader == "" || sigHeader == "" {
		return zero, ErrNoSignature
	}
	label, p, err := ParseSignatureInput(inputHeader)
	if err != nil {
		return zero, err
	}

	// The tag carries the domain. Checking it is what makes RFC 9421 signatures
	// domain-separated without a UAI-specific prefix.
	if opts.Domain != "" && p.Tag != string(opts.Domain) {
		return zero, fmt.Errorf("%w: tag %q, expected %q", ErrTagMismatch, p.Tag, opts.Domain)
	}

	covered := map[string]bool{}
	for _, c := range p.Components {
		covered[strings.ToLower(c)] = true
	}
	for _, c := range required {
		if !covered[strings.ToLower(c)] {
			return zero, fmt.Errorf("%w: %s", ErrComponentNotCovered, c)
		}
	}

	t := now()
	if p.Created != 0 {
		created := time.Unix(p.Created, 0)
		if created.After(t.Add(skew)) || created.Before(t.Add(-skew)) {
			return zero, fmt.Errorf("%w: created %s, now %s, max skew %s",
				ErrStale, created.UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339), skew)
		}
	}
	if p.Expires != 0 && t.After(time.Unix(p.Expires, 0)) {
		return zero, fmt.Errorf("%w: expired", ErrStale)
	}

	if digest := r.Header.Get(HeaderContentDigest); digest != "" {
		if err := VerifyContentDigest(digest, body); err != nil {
			return zero, err
		}
	} else if covered["content-digest"] {
		return zero, fmt.Errorf("%w: content-digest is covered but absent", ErrMissingComponent)
	}

	sig, err := parseSignatureHeader(sigHeader, label)
	if err != nil {
		return zero, err
	}
	base, err := SignatureBase(FromRequest(r, scheme), p)
	if err != nil {
		return zero, err
	}
	if opts.Resolve == nil {
		return zero, errors.New("pop: no key resolver configured")
	}
	pub, err := opts.Resolve(p.KeyID, time.Unix(p.Created, 0))
	if err != nil {
		return zero, fmt.Errorf("pop: resolve %q: %w", p.KeyID, err)
	}
	if err := uaicrypto.VerifyHTTPSignatureBase(pub, p.Alg, base, sig); err != nil {
		return zero, err
	}

	// Replay is checked LAST, so that an invalid request never consumes a
	// nonce: otherwise an attacker could burn a legitimate caller's nonces by
	// replaying them with a broken signature.
	if opts.Nonces != nil {
		nonce := r.Header.Get(HeaderNonce)
		if nonce == "" {
			return zero, fmt.Errorf("%w: %s", ErrMissingComponent, HeaderNonce)
		}
		if opts.Nonces.Seen(p.KeyID, nonce, t.Add(2*skew)) {
			return zero, fmt.Errorf("%w: %s", ErrReplay, nonce)
		}
	}
	return p, nil
}

func parseSignatureHeader(value, label string) ([]byte, error) {
	for _, part := range strings.Split(value, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(k) != label {
			continue
		}
		v = strings.TrimSpace(v)
		if !strings.HasPrefix(v, ":") || !strings.HasSuffix(v, ":") || len(v) < 2 {
			return nil, fmt.Errorf("%w: signature is not a byte sequence", ErrMalformedParams)
		}
		return base64.StdEncoding.DecodeString(v[1 : len(v)-1])
	}
	return nil, fmt.Errorf("%w: no signature labelled %q", ErrNoSignature, label)
}

// MemoryNonceCache is an in-process replay cache. Production uses a shared
// store (Redis in the reference deployment) so that replay protection holds
// across gateway instances; a per-instance cache would let an attacker replay a
// request by reaching a different pod.
type MemoryNonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryNonceCache returns an empty in-process cache.
func NewMemoryNonceCache() *MemoryNonceCache {
	return &MemoryNonceCache{seen: make(map[string]time.Time)}
}

// Seen records the nonce and reports whether it had already been used.
func (c *MemoryNonceCache) Seen(kid, nonce string, expiry time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	key := kid + "\x00" + nonce
	if _, dup := c.seen[key]; dup {
		return true
	}
	c.seen[key] = expiry
	return false
}
