package credential

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// ErrOwnershipUnproven means the embedded two-sided proof does not hold.
var ErrOwnershipUnproven = errors.New("credential: the embedded ownership proof does not verify")

// IdentitySubject is the credentialSubject of an AgentIdentityCredential.
//
// It says what the agent IS, and deliberately not that it is safe or competent.
// AssuranceLevel records how strongly the identity was established — nothing
// more (P1).
type IdentitySubject struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Version             string `json:"version,omitempty"`
	AgentType           string `json:"agentType"`
	Vendor              string `json:"vendor,omitempty"`
	ModelFamily         string `json:"modelFamily,omitempty"`
	ModelPinned         bool   `json:"modelPinned"`
	Framework           string `json:"framework,omitempty"`
	PrimaryJurisdiction string `json:"primaryJurisdiction"`
	AssuranceLevel      string `json:"assuranceLevel"`
	AgentKeyThumbprint  string `json:"agentKeyThumbprint"`
}

// ProofHalf is one side of the registration exchange, kept verbatim.
type ProofHalf struct {
	Challenge string              `json:"challenge"`
	Signature uaicrypto.Signature `json:"signature"`
}

// BindingProof is the two-sided registration proof, embedded whole.
//
// Embedding it is what makes the ownership claim checkable by a third party
// without contacting UAI. The issuer's own signature attests only "UAI saw this
// exchange and minted this identifier"; the ownership claim itself stands or
// falls on these two signatures, which anyone can verify against the agent key
// carried here and the owner key published by the owner.
type BindingProof struct {
	RegistrationID     string          `json:"registrationId"`
	AgentKeyThumbprint string          `json:"agentKeyThumbprint"`
	AgentPublicKeyJwk  json.RawMessage `json:"agentPublicKeyJwk"`
	OwnerKeyID         string          `json:"ownerKeyId"`
	OwnerProof         ProofHalf       `json:"ownerProof"`
	AgentProof         ProofHalf       `json:"agentProof"`
}

// OwnershipSubject is the credentialSubject of an AgentOwnershipCredential.
type OwnershipSubject struct {
	ID            string       `json:"id"`
	OwnerDID      string       `json:"ownerDid"`
	OrgDID        string       `json:"orgDid,omitempty"`
	EffectiveFrom time.Time    `json:"effectiveFrom"`
	BindingProof  BindingProof `json:"bindingProof"`
}

// VerifyOwnership checks the embedded two-sided proof.
//
// This is the function a relying party runs. It needs the owner's public key —
// which for a did:web owner comes from the owner's own domain, and for a did:uai
// owner from UAI's resolver — and nothing else. In particular it never asks UAI
// whether the agent is real: the agent's key travels inside the proof, and both
// signatures are checked against the same subject.
func VerifyOwnership(s OwnershipSubject, ownerKey crypto.PublicKey) error {
	bp := s.BindingProof
	agentJWK, err := uaicrypto.ParseJWK(bp.AgentPublicKeyJwk)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOwnershipUnproven, err)
	}
	// The carried key must be the key the proof names. Without this the
	// credential could ship one key and vouch for another.
	thumbprint, err := agentJWK.ThumbprintString()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOwnershipUnproven, err)
	}
	if thumbprint != bp.AgentKeyThumbprint {
		return fmt.Errorf("%w: the embedded key is %s, the proof names %s",
			ErrOwnershipUnproven, thumbprint, bp.AgentKeyThumbprint)
	}
	agentKey, err := agentJWK.Public()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOwnershipUnproven, err)
	}

	ownerStmt := challenge.Ownership{
		Challenge: bp.OwnerProof.Challenge, RegistrationID: bp.RegistrationID,
		Role: challenge.RoleOwner, AgentKeyThumbprint: bp.AgentKeyThumbprint, OwnerDID: s.OwnerDID,
	}
	agentStmt := challenge.Ownership{
		Challenge: bp.AgentProof.Challenge, RegistrationID: bp.RegistrationID,
		Role: challenge.RoleAgent, AgentKeyThumbprint: bp.AgentKeyThumbprint, OwnerDID: s.OwnerDID,
	}
	// Both halves must describe the same relationship before either signature
	// is checked. Two valid signatures over different subjects are two
	// unrelated statements, not a proof of ownership.
	if err := challenge.SameSubject(ownerStmt, agentStmt); err != nil {
		return fmt.Errorf("%w: %v", ErrOwnershipUnproven, err)
	}
	if err := challenge.Verify(ownerKey, ownerStmt, bp.OwnerProof.Signature); err != nil {
		return fmt.Errorf("%w: owner half: %v", ErrOwnershipUnproven, err)
	}
	if err := challenge.Verify(agentKey, agentStmt, bp.AgentProof.Signature); err != nil {
		return fmt.Errorf("%w: agent half: %v", ErrOwnershipUnproven, err)
	}
	return nil
}

// OwnershipFrom decodes the subject of an AgentOwnershipCredential.
func OwnershipFrom(c Credential) (OwnershipSubject, error) {
	var s OwnershipSubject
	if err := json.Unmarshal(c.CredentialSubject, &s); err != nil {
		return OwnershipSubject{}, fmt.Errorf("credential: ownership subject: %w", err)
	}
	return s, nil
}

// IdentityFrom decodes the subject of an AgentIdentityCredential.
func IdentityFrom(c Credential) (IdentitySubject, error) {
	var s IdentitySubject
	if err := json.Unmarshal(c.CredentialSubject, &s); err != nil {
		return IdentitySubject{}, fmt.Errorf("credential: identity subject: %w", err)
	}
	return s, nil
}

// New builds an unsigned credential of the given type.
func New(credType, id, issuer string, subjectDoc any, from time.Time, until *time.Time) (Credential, error) {
	raw, err := json.Marshal(subjectDoc)
	if err != nil {
		return Credential{}, fmt.Errorf("credential: subject: %w", err)
	}
	return Credential{
		Context:           []string{ContextW3C, ContextUAI},
		Type:              []string{"VerifiableCredential", credType},
		ID:                id,
		Issuer:            issuer,
		ValidFrom:         from.UTC().Truncate(time.Second),
		ValidUntil:        until,
		CredentialSubject: raw,
	}, nil
}
