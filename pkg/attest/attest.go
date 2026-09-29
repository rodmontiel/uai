// Package attest implements the UAI Action Attestation wire format, its hash
// chain and its verification rules.
//
// An attestation is a signed statement that an identity CLAIMS to have
// performed an action. It is not proof that the action's side effects occurred
// in the world: proving that requires the target system to counter-attest.
// Every doc comment here keeps that distinction, because the moment the code
// starts treating an attestation as proof of effect, the product starts making
// a promise it cannot keep.
package attest

import (
	"errors"
	"fmt"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Version is the wire version this package produces.
const Version = "0.1"

// Outcome is the result of an attempted action. Failures are attested too: an
// accountability record that only contains successes is an advertisement.
type Outcome string

// Action outcomes.
const (
	OutcomeSuccess         Outcome = "SUCCESS"
	OutcomeFailure         Outcome = "FAILURE"
	OutcomePartial         Outcome = "PARTIAL"
	OutcomeAbortedByPolicy Outcome = "ABORTED_BY_POLICY"
)

// Action describes what was attempted.
type Action struct {
	Type       string `json:"type"`
	Resource   string `json:"resource,omitempty"`
	Capability string `json:"capability"`
	RiskClass  string `json:"risk_class,omitempty"`
}

// Jurisdiction is the computed jurisdiction context. Basis records WHY the
// system concluded what it concluded, which is what an auditor asks first.
type Jurisdiction struct {
	Origin               string   `json:"origin"`
	Targets              []string `json:"targets"`
	DataLocations        []string `json:"data_locations,omitempty"`
	SubjectJurisdictions []string `json:"subject_jurisdictions,omitempty"`
	CrossBorder          bool     `json:"cross_border"`
	Basis                string   `json:"basis"`
}

// Policy references the decision that authorized the action.
type Policy struct {
	Version    string   `json:"version"`
	BundleHash string   `json:"bundle_hash"`
	DecisionID string   `json:"decision_id"`
	Decision   string   `json:"decision"`
	RulesFired []string `json:"rules_fired,omitempty"`
}

// Passport records passport state at decision time, so the state survives the
// passport's later expiry or revocation.
type Passport struct {
	Required         bool   `json:"required"`
	CredentialHash   string `json:"credential_hash,omitempty"`
	StatusAtDecision string `json:"status_at_decision,omitempty"`
}

// Timestamp is uaicrypto.Timestamp, kept here under its original name.
//
// It moved because it is not a fact about attestations: every signed wire object
// in this protocol carries an instant, and every one of them needs the spelling
// that arrived rather than Go's re-serialization of it. Federation learned that
// from this package rather than rediscovering it.
type Timestamp = uaicrypto.Timestamp

// NewTimestamp wraps an instant produced locally.
func NewTimestamp(t time.Time) Timestamp { return uaicrypto.NewTimestamp(t) }

// Attestation is the wire object.
type Attestation struct {
	UAIVersion        string              `json:"uai_version"`
	EventID           string              `json:"event_id"`
	AgentDID          string              `json:"agent_did"`
	OwnerDID          string              `json:"owner_did"`
	RuntimeIdentity   string              `json:"runtime_identity,omitempty"`
	Timestamp         Timestamp           `json:"timestamp"`
	Nonce             string              `json:"nonce"`
	Action            Action              `json:"action"`
	Purpose           string              `json:"purpose"`
	Jurisdiction      Jurisdiction        `json:"jurisdiction"`
	Policy            Policy              `json:"policy"`
	Passport          *Passport           `json:"passport,omitempty"`
	InputCommitment   string              `json:"input_commitment,omitempty"`
	OutputCommitment  string              `json:"output_commitment,omitempty"`
	Outcome           Outcome             `json:"outcome"`
	PreviousEventHash string              `json:"previous_event_hash,omitempty"`
	Sequence          int64               `json:"sequence"`
	Signature         uaicrypto.Signature `json:"signature"`
}

// Validation errors.
var (
	// ErrUnsigned is returned for an attestation with no signature.
	ErrUnsigned = errors.New("attest: attestation is not signed")
	// ErrWrongDomain is returned when the signature was not made in the attestation domain.
	ErrWrongDomain = errors.New("attest: signature was not made in the attestation domain")
	// ErrPolicyUnreferenced is returned when no policy decision is named.
	ErrPolicyUnreferenced = errors.New("attest: attestation does not name a policy decision")
	// ErrIncomplete is returned when a required field is missing.
	ErrIncomplete = errors.New("attest: attestation is incomplete")
	// ErrIdentityMismatch is returned when the signer is not the declared agent.
	ErrIdentityMismatch = errors.New("attest: signing key does not belong to the declared agent")
	// ErrPassportUnrecorded is returned when a passport was required but its
	// state at decision time was not captured.
	ErrPassportUnrecorded = errors.New("attest: passport required but its state at decision time is absent")
)

// SigningBytes returns the canonical bytes covered by the signature: §10.4's
// "jcs-canonicalize A minus signature".
//
// The member is REMOVED, not blanked. An implementation that blanked it would
// hash four empty strings nobody else knows to add, and its attestations would
// verify only against itself.
func (a Attestation) SigningBytes() ([]byte, error) {
	return uaicrypto.CanonicalizeWithout(a, "signature")
}

// Hash returns the event hash: the domain-separated digest of the SIGNED
// attestation. Successors reference this value, so the chain binds the
// signature and not merely the payload.
func (a Attestation) Hash() (string, error) {
	canonical, err := uaicrypto.Canonicalize(a)
	if err != nil {
		return "", err
	}
	sum, err := uaicrypto.Digest(uaicrypto.DomainAttestation, canonical)
	if err != nil {
		return "", err
	}
	return uaicrypto.FormatDigest(sum), nil
}

// Sign produces a signed attestation.
func Sign(signer uaicrypto.Signer, a Attestation) (Attestation, error) {
	a.UAIVersion = Version
	payload, err := a.SigningBytes()
	if err != nil {
		return Attestation{}, err
	}
	sig, err := signer.Sign(uaicrypto.DomainAttestation, payload)
	if err != nil {
		return Attestation{}, err
	}
	a.Signature = sig
	return a, nil
}

// Validate checks structural rules that do not need a key.
//
// The policy reference is mandatory: an attestation with no decision behind it
// is POLICY_UNEVALUATED and must never be presented as compliant (INV-009).
func (a Attestation) Validate() error {
	switch {
	case a.UAIVersion != Version:
		return fmt.Errorf("%w: uai_version %q, want %q", ErrIncomplete, a.UAIVersion, Version)
	case a.EventID == "":
		return fmt.Errorf("%w: event_id", ErrIncomplete)
	case a.AgentDID == "":
		return fmt.Errorf("%w: agent_did", ErrIncomplete)
	case a.OwnerDID == "":
		return fmt.Errorf("%w: owner_did", ErrIncomplete)
	case a.Nonce == "":
		return fmt.Errorf("%w: nonce", ErrIncomplete)
	case a.Action.Type == "" || a.Action.Capability == "":
		return fmt.Errorf("%w: action.type and action.capability", ErrIncomplete)
	case a.Purpose == "":
		return fmt.Errorf("%w: purpose", ErrIncomplete)
	case a.Jurisdiction.Origin == "" || a.Jurisdiction.Basis == "":
		return fmt.Errorf("%w: jurisdiction.origin and jurisdiction.basis", ErrIncomplete)
	case a.Outcome == "":
		return fmt.Errorf("%w: outcome", ErrIncomplete)
	case a.Signature.Value == "":
		return ErrUnsigned
	case a.Signature.Domain != uaicrypto.DomainAttestation:
		return fmt.Errorf("%w: signed for %q", ErrWrongDomain, a.Signature.Domain)
	case a.Policy.Version == "" || a.Policy.BundleHash == "" || a.Policy.DecisionID == "":
		return ErrPolicyUnreferenced
	}
	if a.Jurisdiction.CrossBorder && len(a.Jurisdiction.Targets) == 0 {
		return fmt.Errorf("%w: a cross-border action must name a target jurisdiction", ErrIncomplete)
	}
	if a.Passport != nil && a.Passport.Required &&
		(a.Passport.CredentialHash == "" || a.Passport.StatusAtDecision == "") {
		return ErrPassportUnrecorded
	}
	return nil
}

// Verify checks the structure, the signer's identity and the signature.
//
// The signing key must belong to the declared agent. Without that check an
// attestation could name one identity and be signed by another, which is
// attribution by string comparison — exactly what INV-002 forbids.
func Verify(pub any, a Attestation) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if !belongsTo(a.Signature.KID, a.AgentDID) {
		return fmt.Errorf("%w: signed by %s, declared %s", ErrIdentityMismatch, a.Signature.KID, a.AgentDID)
	}
	payload, err := a.SigningBytes()
	if err != nil {
		return err
	}
	return uaicrypto.Verify(pub, uaicrypto.DomainAttestation, payload, a.Signature)
}

// belongsTo reports whether a DID URL identifies a verification method of a DID.
func belongsTo(didURL, did string) bool {
	return len(didURL) > len(did) && didURL[:len(did)] == did && didURL[len(did)] == '#'
}

// LinksTo reports whether this attestation extends the given predecessor.
func (a Attestation) LinksTo(previousHash string) bool {
	return a.PreviousEventHash == previousHash
}
