package challenge

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Binding operations (§9).
const (
	OpBind   = "BIND_AGENT"
	OpUnbind = "UNBIND_AGENT"
	OpRebind = "REBIND_AGENT"
)

// ErrInvalidOperation is returned for an operation outside the three.
var ErrInvalidOperation = errors.New("challenge: unknown binding operation")

// Binding is the statement signed for BIND_AGENT, UNBIND_AGENT and
// REBIND_AGENT (§9.1).
//
// For a bind, the signature covers the server-issued challenge AND the SVID
// identifiers. That is what cryptographically ties "who I am" to "where I am
// running": either half alone would be forgeable by an attacker holding the
// other. An attacker with the persistent key but no workload attestation cannot
// name a running instance, and one who steals an SVID cannot produce the
// signature that claims it.
//
// Audience is inside the signed bytes so a statement produced for one registry
// cannot be presented to another. Without it, a federated deployment would
// accept a binding intended for a different operator.
type Binding struct {
	Challenge string `json:"challenge"`
	Operation string `json:"operation"`
	UAIID     string `json:"uai_id"`
	Audience  string `json:"audience"`
	// Bind only.
	// The JSON name is svid_spiffe_id, matching §9.1 and the request body. It
	// was "spiffe_id" until the SDKs were written against the spec and produced
	// a canonical form this verifier rejected: one name, in one place, is the
	// only version of this that two implementations can both get right.
	SpiffeID     string `json:"svid_spiffe_id,omitempty"`
	SVIDCertHash string `json:"svid_cert_hash,omitempty"`
	ImageDigest  string `json:"image_digest,omitempty"`
	// Unbind only. A reason is recorded, never required to be true: an agent
	// leaving is not obliged to justify itself (§9.2).
	Reason string `json:"reason,omitempty"`
	// Rebind only: the last event before unbinding (§9.3).
	PreviousEventHash string `json:"previous_event_hash,omitempty"`
}

// ValidOperation reports whether op is one of the three.
func ValidOperation(op string) bool {
	return op == OpBind || op == OpUnbind || op == OpRebind
}

// Validate checks that the statement carries what its operation requires.
func (b Binding) Validate() error {
	if !ValidOperation(b.Operation) {
		return fmt.Errorf("%w: %q", ErrInvalidOperation, b.Operation)
	}
	switch {
	case b.Challenge == "":
		return fmt.Errorf("%w: challenge", ErrIncomplete)
	case b.UAIID == "":
		return fmt.Errorf("%w: uai_id", ErrIncomplete)
	case b.Audience == "":
		return fmt.Errorf("%w: audience", ErrIncomplete)
	}
	switch b.Operation {
	case OpBind:
		// A bind with no runtime records who, but not where. That is the half
		// of the claim the operation exists to establish.
		if b.SpiffeID == "" || b.SVIDCertHash == "" {
			return fmt.Errorf("%w: a bind must name the runtime it binds (svid_spiffe_id, svid_cert_hash)", ErrIncomplete)
		}
	case OpRebind:
		if b.PreviousEventHash == "" {
			return fmt.Errorf("%w: a rebind must reference the last event before unbinding", ErrIncomplete)
		}
		if b.SpiffeID != "" || b.SVIDCertHash != "" {
			// Rebinding restores participation; attaching a runtime is a
			// separate, separately attested act. Allowing both in one statement
			// would make the event mean two things.
			return fmt.Errorf("%w: a rebind does not carry runtime identifiers; bind afterwards", ErrIncomplete)
		}
	case OpUnbind:
		if b.SpiffeID != "" || b.SVIDCertHash != "" || b.PreviousEventHash != "" {
			return fmt.Errorf("%w: an unbind carries only a reason", ErrIncomplete)
		}
	}
	return nil
}

// SigningBytes returns the RFC 8785 canonical form of the statement.
func (b Binding) SigningBytes() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return uaicrypto.Canonicalize(b)
}

// SignBinding produces a signature over the statement under the challenge domain.
func SignBinding(s uaicrypto.Signer, b Binding) (uaicrypto.Signature, error) {
	if err := b.Validate(); err != nil {
		return uaicrypto.Signature{}, err
	}
	return uaicrypto.SignObject(s, uaicrypto.DomainChallenge, b)
}

// VerifyBinding checks a signature over the statement.
func VerifyBinding(pub crypto.PublicKey, b Binding, sig uaicrypto.Signature) error {
	if err := b.Validate(); err != nil {
		return err
	}
	return uaicrypto.VerifyObject(pub, uaicrypto.DomainChallenge, b, sig)
}
