package uai

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Client talks to a UAI gateway on behalf of exactly one identity.
//
// One identity per client is deliberate. A client that could sign as several
// agents would make "which identity performed this" a parameter at the call
// site, and the first bug in passing it would be a misattributed action.
type Client struct {
	baseURL  *url.URL
	http     *http.Client
	signer   uaicrypto.Signer
	uaiID    string
	agentDID string
	ownerDID string

	// head caches the tip of the event chain so an attestation can name its
	// predecessor without a round trip. It is a cache of a value the server
	// owns: on UAI_CHAIN_CONFLICT it is refreshed from the refusal, which
	// carries the real head precisely so a caller need not guess.
	head Head
	now  func() time.Time
}

// Head is the tip of an agent's event chain.
type Head struct {
	Hash     string `json:"hash"`
	Sequence int64  `json:"sequence"`
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithOwnerDID sets the owner recorded in attestations.
func WithOwnerDID(did string) Option { return func(c *Client) { c.ownerDID = did } }

// WithClock overrides the clock, for tests.
func WithClock(f func() time.Time) Option { return func(c *Client) { c.now = f } }

// New builds a client for one identity.
//
// signer is supplied by the caller and never created here: a client library
// that generated a key would be a client library that could impersonate its
// user, and an operator would have no way to tell which key signed what.
func New(baseURL, uaiID string, signer uaicrypto.Signer, opts ...Option) (*Client, error) {
	if signer == nil {
		return nil, errors.New("uai: a signer is required; this package does not create keys")
	}
	if uaiID == "" {
		return nil, errors.New("uai: the agent's UAI-ID is required")
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("uai: base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("uai: base url must be absolute, got %q", baseURL)
	}
	did, _, _ := strings.Cut(signer.KID(), "#")
	c := &Client{
		baseURL: u, http: &http.Client{Timeout: 30 * time.Second},
		signer: signer, uaiID: uaiID, agentDID: did, now: time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// UAIID returns the identity this client signs as.
func (c *Client) UAIID() string { return c.uaiID }

// AgentDID returns the DID this client signs as.
func (c *Client) AgentDID() string { return c.agentDID }

// Problem is an RFC 9457 problem document returned by the gateway.
//
// It is an error value rather than a wrapped string because the fields matter:
// a caller that hits UAI_CHAIN_CONFLICT needs ChainHead, and one that hits a
// policy refusal needs the decision id to look the refusal up. Flattening this
// into a message would force callers back to string matching, which is what
// typed errors exist to stop.
type Problem struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Detail        string `json:"detail,omitempty"`
	DecisionID    string `json:"decision_id,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	CaseID        string `json:"case_id,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ChainHead     *Head  `json:"chain_head,omitempty"`
}

// Error renders the problem.
func (p *Problem) Error() string {
	msg := p.Title
	if p.Detail != "" {
		msg += ": " + p.Detail
	}
	if p.Remediation != "" {
		msg += " (" + p.Remediation + ")"
	}
	return fmt.Sprintf("uai: %s [%d]", msg, p.Status)
}

// Code returns the UAI_* error code.
func (p *Problem) Code() string { return p.Title }

// IsCode reports whether err is a Problem with the given UAI_* code.
func IsCode(err error, code string) bool {
	var p *Problem
	return errors.As(err, &p) && p.Title == code
}

// Nonce returns a fresh 128-bit replay nonce.
func Nonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// A nonce that is not random is a replay window. Failing loudly beats
		// continuing with a predictable value that would verify fine today.
		panic("uai: system randomness unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// get performs an unauthenticated read.
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL.String()+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

// post signs a state-changing call and sends it.
//
// domain is the UAI domain the signature is made in, carried as the RFC 9421
// tag. It is an argument rather than a constant because a signature valid for
// one endpoint must not be replayable against another.
func (c *Client) post(ctx context.Context, path string, domain uaicrypto.Domain, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("uai: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL.String()+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "sdk-"+Nonce())
	if err := pop.SignRequest(c.signer, req, raw, domain, c.uaiID, Nonce()); err != nil {
		return fmt.Errorf("uai: sign request: %w", err)
	}
	return c.do(req, out)
}

// postPublic sends an unsigned call to a public endpoint.
//
// Separate from post so that reaching a public surface never silently requires
// a key: a relying party checking somebody else's passport is not a UAI
// participant, and an SDK that made them sign to ask would have put an account
// in front of verification.
func (c *Client) postPublic(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("uai: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL.String()+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "sdk-"+Nonce())
	return c.do(req, out)
}

// maxResponse caps what the client will read. A client that read an unbounded
// body would let a compromised or confused gateway exhaust the agent's memory.
const maxResponse = 4 << 20

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("uai: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("uai: read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		p := &Problem{Status: resp.StatusCode, Title: "UAI_UNKNOWN_ERROR"}
		// A non-JSON error body is reported as what it is rather than being
		// parsed into a plausible-looking problem: a proxy's HTML error page
		// must not read as a verdict from the gateway.
		if err := json.Unmarshal(body, p); err != nil || p.Title == "" {
			p.Title, p.Detail = "UAI_UNKNOWN_ERROR", strings.TrimSpace(string(body))
		}
		if p.Status == 0 {
			p.Status = resp.StatusCode
		}
		if p.ChainHead != nil {
			c.head = *p.ChainHead
		}
		return p
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("uai: decode response: %w", err)
	}
	return nil
}
