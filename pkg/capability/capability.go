// Package capability implements the two signed statements of a capability
// request: the agent asking, and the owner deciding.
//
// They are separate statements, signed by separate keys, and the role each one
// claims is INSIDE the signed bytes. That redundancy is the point. The two
// statements already differ by their content, so naming the role adds nothing
// today — and it is exactly what stops a future change to either shape from
// silently making an agent's request replayable as its owner's approval.
//
// §22.9 states the rule this package serves: no MCP tool, no API route and no
// SDK method grants a capability. A grant requires a signature over a Decision,
// and producing one requires the owner's key, which the agent's process does not
// have. That is the whole mechanism; everything else is bookkeeping.
package capability

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Role names the side of the exchange a statement is signed from.
type Role string

// The two sides.
const (
	RoleRequest  Role = "request"
	RoleDecision Role = "decision"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleRequest || r == RoleDecision }

// Effect is what an owner decided.
type Effect string

// Decision effects. There is no third value: an owner either grants or does
// not, and an "acknowledged" state would be a grant that nobody has to own.
const (
	EffectApprove Effect = "APPROVE"
	EffectDeny    Effect = "DENY"
)

// Valid reports whether e is a known effect.
func (e Effect) Valid() bool { return e == EffectApprove || e == EffectDeny }

// Errors returned by this package.
var (
	// ErrIncomplete means a statement is missing a member that must be signed.
	ErrIncomplete = errors.New("capability: statement is incomplete")
	// ErrInvalidRole means the role is outside the registry.
	ErrInvalidRole = errors.New("capability: unknown role")
	// ErrMismatch means a decision does not answer the request it names.
	ErrMismatch = errors.New("capability: the decision does not match the request it names")
)

// Request is the statement an agent signs when it asks for a capability.
type Request struct {
	Role          Role   `json:"role"`
	RequestID     string `json:"request_id"`
	AgentDID      string `json:"agent_did"`
	OwnerDID      string `json:"owner_did"`
	Capability    string `json:"capability"`
	Justification string `json:"justification"`
}

// Validate reports whether every member that must be signed is present.
func (r Request) Validate() error {
	if r.Role != RoleRequest {
		return fmt.Errorf("%w: %q", ErrInvalidRole, r.Role)
	}
	switch {
	case r.RequestID == "":
		return fmt.Errorf("%w: request_id", ErrIncomplete)
	case r.AgentDID == "":
		return fmt.Errorf("%w: agent_did", ErrIncomplete)
	case r.OwnerDID == "":
		return fmt.Errorf("%w: owner_did", ErrIncomplete)
	case r.Capability == "":
		return fmt.Errorf("%w: capability", ErrIncomplete)
	case r.Justification == "":
		// Required, because it is what the owner reads. Without it they would
		// be approving a capability name.
		return fmt.Errorf("%w: justification", ErrIncomplete)
	}
	return nil
}

// Decision is the statement an owner signs when answering a request.
//
// It repeats the agent, the owner and the capability rather than only naming
// the request id. An approval that said no more than "yes to capreq-01J" would
// be an approval whose meaning lived in a row someone could later edit; here the
// signature covers what was actually granted.
type Decision struct {
	Role       Role      `json:"role"`
	RequestID  string    `json:"request_id"`
	AgentDID   string    `json:"agent_did"`
	OwnerDID   string    `json:"owner_did"`
	Capability string    `json:"capability"`
	Effect     Effect    `json:"effect"`
	DecidedAt  time.Time `json:"decided_at"`
	// ExpiresAt bounds the grant. Zero means no expiry, which an owner may
	// choose but never gets by default: see tools/uai-grant.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	Note      string    `json:"note,omitempty"`
}

// Validate reports whether every member that must be signed is present.
func (d Decision) Validate() error {
	if d.Role != RoleDecision {
		return fmt.Errorf("%w: %q", ErrInvalidRole, d.Role)
	}
	if !d.Effect.Valid() {
		return fmt.Errorf("%w: effect %q", ErrIncomplete, d.Effect)
	}
	switch {
	case d.RequestID == "":
		return fmt.Errorf("%w: request_id", ErrIncomplete)
	case d.AgentDID == "":
		return fmt.Errorf("%w: agent_did", ErrIncomplete)
	case d.OwnerDID == "":
		return fmt.Errorf("%w: owner_did", ErrIncomplete)
	case d.Capability == "":
		return fmt.Errorf("%w: capability", ErrIncomplete)
	case d.DecidedAt.IsZero():
		return fmt.Errorf("%w: decided_at", ErrIncomplete)
	}
	return nil
}

// Answers reports whether d decides exactly the request r describes.
//
// Every member is compared, not just the id. A decision naming the right
// request but a different capability would otherwise grant something nobody
// asked for, which is the substitution this check exists to stop.
func (d Decision) Answers(r Request) error {
	switch {
	case d.RequestID != r.RequestID:
		return fmt.Errorf("%w: request %s vs %s", ErrMismatch, d.RequestID, r.RequestID)
	case d.AgentDID != r.AgentDID:
		return fmt.Errorf("%w: agent %s vs %s", ErrMismatch, d.AgentDID, r.AgentDID)
	case d.OwnerDID != r.OwnerDID:
		return fmt.Errorf("%w: owner %s vs %s", ErrMismatch, d.OwnerDID, r.OwnerDID)
	case d.Capability != r.Capability:
		return fmt.Errorf("%w: capability %s vs %s", ErrMismatch, d.Capability, r.Capability)
	}
	return nil
}

// SigningBytes returns the RFC 8785 canonical form of the statement.
func (r Request) SigningBytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return uaicrypto.Canonicalize(r)
}

// SigningBytes returns the RFC 8785 canonical form of the statement.
func (d Decision) SigningBytes() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return uaicrypto.Canonicalize(d)
}

// SignRequest signs an agent's request.
func SignRequest(s uaicrypto.Signer, r Request) (uaicrypto.Signature, error) {
	payload, err := r.SigningBytes()
	if err != nil {
		return uaicrypto.Signature{}, err
	}
	return s.Sign(uaicrypto.DomainCapabilityRequest, payload)
}

// SignDecision signs an owner's decision.
func SignDecision(s uaicrypto.Signer, d Decision) (uaicrypto.Signature, error) {
	payload, err := d.SigningBytes()
	if err != nil {
		return uaicrypto.Signature{}, err
	}
	return s.Sign(uaicrypto.DomainCapabilityRequest, payload)
}

// VerifyDecision checks an owner's signature over a decision.
func VerifyDecision(pub crypto.PublicKey, d Decision, sig uaicrypto.Signature) error {
	payload, err := d.SigningBytes()
	if err != nil {
		return err
	}
	return uaicrypto.Verify(pub, uaicrypto.DomainCapabilityRequest, payload, sig)
}
