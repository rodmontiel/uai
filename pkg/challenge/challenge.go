// Package challenge implements the signed challenge-response statements that
// prove control of a key before that key has any standing in UAI.
//
// Registration is the only write path in the system that cannot require proof
// of possession against a key the registry already knows — establishing that
// key is what registration IS. This package is what stands in its place: the
// registry issues an unpredictable, single-use challenge, and a caller proves
// control by signing a statement that names the exact relationship being
// claimed. Nothing here is a secret: both challenges are handed to whoever
// opens the registration. Their job is to be unpredictable before issuance and
// single-use after it, and the security of the flow rests on the two signatures
// requiring two different private keys.
package challenge

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Role names the side of the relationship a statement is signed from.
//
// The role is inside the signed bytes on purpose. The two statements already
// differ by their challenge, so this is redundant today — and it is exactly the
// redundancy that keeps a future change to challenge issuance from silently
// making an owner's signature replayable as an agent's.
type Role string

// The two sides of a registration proof.
const (
	RoleOwner Role = "owner"
	RoleAgent Role = "agent"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleOwner || r == RoleAgent }

// Size is the length in bytes of an issued challenge.
const Size = 32

// Errors returned by this package.
var (
	// ErrProofMismatch means the two halves do not describe the same
	// relationship. It maps to UAI_PROOF_MISMATCH (§8.5).
	ErrProofMismatch = errors.New("challenge: the owner and agent proofs do not name the same subject")
	// ErrIncomplete means a statement is missing a field that must be signed.
	ErrIncomplete = errors.New("challenge: statement is incomplete")
	// ErrInvalidRole means the role is outside the registry.
	ErrInvalidRole = errors.New("challenge: unknown role")
)

// New issues a fresh challenge, base64url without padding.
func New() (string, error) {
	b := make([]byte, Size)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("challenge: generate: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Ownership is the statement signed by BOTH the owner and the agent during
// registration (§8.2).
//
// The agent is named by the thumbprint of its public key rather than by a DID,
// because at this point in the flow it has no DID: the UAI-ID is minted only
// after both proofs verify. Naming the key is also the stronger binding — a DID
// is an assertion about a key, while the thumbprint IS the key.
//
// Both signatures cover the same AgentKeyThumbprint and the same OwnerDID.
// That is the entire mechanism behind "ownership is proven, not declared"
// (§6.4.1): a party signing only its own half asserts nothing about the
// relationship, and two halves naming different subjects do not compose into a
// proof.
type Ownership struct {
	Challenge          string `json:"challenge"`
	RegistrationID     string `json:"registration_id"`
	Role               Role   `json:"role"`
	AgentKeyThumbprint string `json:"agent_key_thumbprint"`
	OwnerDID           string `json:"owner_did"`
}

// Validate reports whether every member that must be signed is present.
func (o Ownership) Validate() error {
	if !o.Role.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidRole, o.Role)
	}
	switch {
	case o.Challenge == "":
		return fmt.Errorf("%w: challenge", ErrIncomplete)
	case o.RegistrationID == "":
		return fmt.Errorf("%w: registration_id", ErrIncomplete)
	case o.AgentKeyThumbprint == "":
		return fmt.Errorf("%w: agent_key_thumbprint", ErrIncomplete)
	case o.OwnerDID == "":
		return fmt.Errorf("%w: owner_did", ErrIncomplete)
	}
	return nil
}

// SigningBytes returns the RFC 8785 canonical form of the statement. These are
// the bytes the signature covers, before domain separation is applied.
func (o Ownership) SigningBytes() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return uaicrypto.Canonicalize(o)
}

// Sign produces a signature over the statement under the challenge domain.
func Sign(s uaicrypto.Signer, o Ownership) (uaicrypto.Signature, error) {
	if err := o.Validate(); err != nil {
		return uaicrypto.Signature{}, err
	}
	return uaicrypto.SignObject(s, uaicrypto.DomainChallenge, o)
}

// Verify checks a signature over the statement.
func Verify(pub crypto.PublicKey, o Ownership, sig uaicrypto.Signature) error {
	if err := o.Validate(); err != nil {
		return err
	}
	return uaicrypto.VerifyObject(pub, uaicrypto.DomainChallenge, o, sig)
}

// SameSubject reports whether two halves of a registration proof describe the
// same relationship.
//
// It compares everything except the role and the challenge, which are the only
// two members that are SUPPOSED to differ. Anything else differing means the
// two parties did not agree on what was being claimed, and combining them would
// manufacture consent that neither gave.
func SameSubject(owner, agent Ownership) error {
	switch {
	case owner.Role != RoleOwner || agent.Role != RoleAgent:
		return fmt.Errorf("%w: proofs are not one owner half and one agent half", ErrProofMismatch)
	case owner.RegistrationID != agent.RegistrationID:
		return fmt.Errorf("%w: registration %q vs %q", ErrProofMismatch, owner.RegistrationID, agent.RegistrationID)
	case owner.AgentKeyThumbprint != agent.AgentKeyThumbprint:
		return fmt.Errorf("%w: agent key %q vs %q", ErrProofMismatch, owner.AgentKeyThumbprint, agent.AgentKeyThumbprint)
	case owner.OwnerDID != agent.OwnerDID:
		return fmt.Errorf("%w: owner %q vs %q", ErrProofMismatch, owner.OwnerDID, agent.OwnerDID)
	case owner.Challenge == agent.Challenge:
		// Two halves answering one challenge is not a two-sided proof; it is
		// one proof submitted twice. Issuance keeps them distinct, so this
		// means either a tampered submission or a broken issuer.
		return fmt.Errorf("%w: both halves answer the same challenge", ErrProofMismatch)
	}
	return nil
}
