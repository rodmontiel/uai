// Package credential implements the UAI credential family: W3C Verifiable
// Credentials 2.0 carrying Data Integrity proofs over RFC 8785 canonical bytes.
//
// The point of this package is that a relying party can validate a credential
// WITHOUT asking UAI anything. A credential that only means something while the
// issuer's API is reachable is an API response with extra steps, and it would
// make every participant depend on UAI's uptime and honesty — the two things
// this protocol is supposed to remove from the trust equation.
package credential

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Credential types.
const (
	TypeIdentity   = "AgentIdentityCredential"
	TypeOwnership  = "AgentOwnershipCredential"
	TypeCapability = "AgentCapabilityCredential"
	TypePassport   = "AgentPassportCredential"
	TypeRevocation = "AgentRevocationCredential"
)

// JSON-LD contexts.
const (
	ContextW3C = "https://www.w3.org/ns/credentials/v2"
	ContextUAI = "https://uai.world/ns/credentials/v1"
)

// Errors.
var (
	ErrUnsigned       = errors.New("credential: no proof")
	ErrProofMalformed = errors.New("credential: proof is malformed")
	ErrNotYetValid    = errors.New("credential: not yet valid")
	ErrExpired        = errors.New("credential: expired")
	ErrIncomplete     = errors.New("credential: incomplete")
)

// Status is a BitstringStatusList entry.
type Status struct {
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose"`
	StatusListIndex      string `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential"`
}

// Proof is a W3C Data Integrity proof.
type Proof struct {
	Type               string    `json:"type"`
	Cryptosuite        string    `json:"cryptosuite"`
	Created            time.Time `json:"created"`
	VerificationMethod string    `json:"verificationMethod"`
	ProofPurpose       string    `json:"proofPurpose"`
	Domain             string    `json:"domain"`
	Challenge          string    `json:"challenge,omitempty"`
	ProofValue         string    `json:"proofValue,omitempty"`
}

// Credential is a Verifiable Credential.
type Credential struct {
	Context           []string        `json:"@context"`
	Type              []string        `json:"type"`
	ID                string          `json:"id"`
	Issuer            string          `json:"issuer"`
	ValidFrom         time.Time       `json:"validFrom"`
	ValidUntil        *time.Time      `json:"validUntil,omitempty"`
	CredentialStatus  *Status         `json:"credentialStatus,omitempty"`
	CredentialSubject json.RawMessage `json:"credentialSubject"`
	Proof             *Proof          `json:"proof,omitempty"`
}

// cryptosuiteFor maps a UAI algorithm to its Data Integrity cryptosuite.
func cryptosuiteFor(alg uaicrypto.Algorithm) (string, error) {
	switch alg {
	case uaicrypto.AlgEdDSA:
		return "eddsa-jcs-2022", nil
	case uaicrypto.AlgES256, uaicrypto.AlgES384:
		return "ecdsa-jcs-2019", nil
	default:
		return "", fmt.Errorf("credential: no cryptosuite for %s", alg)
	}
}

// signingPayload builds the bytes a Data Integrity JCS proof covers.
//
// The construction is the one the *-jcs-* cryptosuites specify: hash the proof
// configuration and the unsecured document separately, then sign the
// concatenation. Hashing them apart is what stops a value moving between the
// document and the proof options without changing the signature.
//
// UAI then applies its own domain separation on top, so a credential proof can
// never be replayed as an attestation or a vote.
func signingPayload(c Credential, p Proof) ([]byte, error) {
	options := p
	options.ProofValue = ""
	optionBytes, err := uaicrypto.Canonicalize(options)
	if err != nil {
		return nil, err
	}
	unsecured := c
	unsecured.Proof = nil
	docBytes, err := uaicrypto.Canonicalize(unsecured)
	if err != nil {
		return nil, err
	}
	optionHash, err := uaicrypto.Digest(uaicrypto.DomainCredential, optionBytes)
	if err != nil {
		return nil, err
	}
	docHash, err := uaicrypto.Digest(uaicrypto.DomainCredential, docBytes)
	if err != nil {
		return nil, err
	}
	return append(optionHash, docHash...), nil
}

// Validate reports whether the document carries everything a credential needs.
func (c Credential) Validate() error {
	switch {
	case len(c.Context) < 2 || c.Context[0] != ContextW3C:
		return fmt.Errorf("%w: @context must start with %s", ErrIncomplete, ContextW3C)
	case len(c.Type) < 2 || c.Type[0] != "VerifiableCredential":
		return fmt.Errorf("%w: type must start with VerifiableCredential", ErrIncomplete)
	case c.ID == "":
		return fmt.Errorf("%w: id", ErrIncomplete)
	case c.Issuer == "":
		return fmt.Errorf("%w: issuer", ErrIncomplete)
	case c.ValidFrom.IsZero():
		return fmt.Errorf("%w: validFrom", ErrIncomplete)
	case len(c.CredentialSubject) == 0:
		return fmt.Errorf("%w: credentialSubject", ErrIncomplete)
	case c.ValidUntil != nil && !c.ValidUntil.After(c.ValidFrom):
		return fmt.Errorf("%w: validUntil is not after validFrom", ErrIncomplete)
	}
	return nil
}

// Issue signs a credential.
func Issue(signer uaicrypto.Signer, c Credential, at time.Time) (Credential, error) {
	if err := c.Validate(); err != nil {
		return Credential{}, err
	}
	suite, err := cryptosuiteFor(signer.Algorithm())
	if err != nil {
		return Credential{}, err
	}
	p := Proof{
		Type: "DataIntegrityProof", Cryptosuite: suite, Created: at.UTC().Truncate(time.Second),
		VerificationMethod: signer.KID(), ProofPurpose: "assertionMethod",
		Domain: string(uaicrypto.DomainCredential),
	}
	payload, err := signingPayload(c, p)
	if err != nil {
		return Credential{}, err
	}
	sig, err := signer.Sign(uaicrypto.DomainCredential, payload)
	if err != nil {
		return Credential{}, err
	}
	raw, err := sig.Bytes()
	if err != nil {
		return Credential{}, err
	}
	p.ProofValue = encodeProofValue(raw)
	c.Proof = &p
	return c, nil
}

// Verify checks a credential's proof.
//
// It deliberately does NOT check the status list or the issuer's standing.
// Those are separate questions with separate answers, and collapsing them here
// would let "the signature is valid" and "the credential is still honored" hide
// behind one boolean.
func Verify(pub crypto.PublicKey, c Credential) error {
	if c.Proof == nil {
		return ErrUnsigned
	}
	if err := c.Validate(); err != nil {
		return err
	}
	p := *c.Proof
	switch {
	case p.Type != "DataIntegrityProof":
		return fmt.Errorf("%w: type %q", ErrProofMalformed, p.Type)
	case p.ProofPurpose != "assertionMethod":
		return fmt.Errorf("%w: proofPurpose %q", ErrProofMalformed, p.ProofPurpose)
	case p.Domain != string(uaicrypto.DomainCredential):
		// A proof made in another domain must not verify here even if the bytes
		// happen to line up. This is the check that makes domain separation
		// real rather than documentary.
		return fmt.Errorf("%w: domain %q, want %s", ErrProofMalformed, p.Domain, uaicrypto.DomainCredential)
	}
	alg, err := algForCryptosuite(p.Cryptosuite, pub)
	if err != nil {
		return err
	}
	raw, err := decodeProofValue(p.ProofValue)
	if err != nil {
		return err
	}
	payload, err := signingPayload(c, p)
	if err != nil {
		return err
	}
	return uaicrypto.Verify(pub, uaicrypto.DomainCredential, payload, uaicrypto.Signature{
		Alg: alg, KID: p.VerificationMethod, Domain: uaicrypto.DomainCredential,
		Value: base64.RawURLEncoding.EncodeToString(raw),
	})
}

// ValidAt reports whether the credential's own window covers t.
func (c Credential) ValidAt(t time.Time) error {
	if t.Before(c.ValidFrom) {
		return fmt.Errorf("%w: valid from %s", ErrNotYetValid, c.ValidFrom.UTC().Format(time.RFC3339))
	}
	if c.ValidUntil != nil && !t.Before(*c.ValidUntil) {
		return fmt.Errorf("%w: expired %s", ErrExpired, c.ValidUntil.UTC().Format(time.RFC3339))
	}
	return nil
}

// Hash returns the digest of the SIGNED credential, which is what the
// transparency log and the database record.
//
// Hashing the signed form rather than the payload matters: two credentials with
// identical claims and different issuers are different credentials, and a
// digest that could not tell them apart would let one be substituted for the
// other in any index keyed by it.
func (c Credential) Hash() (string, error) {
	if c.Proof == nil || c.Proof.ProofValue == "" {
		return "", ErrUnsigned
	}
	sum, err := uaicrypto.DigestObject(uaicrypto.DomainCredential, c)
	if err != nil {
		return "", err
	}
	return uaicrypto.FormatDigest(sum), nil
}

func algForCryptosuite(suite string, pub crypto.PublicKey) (uaicrypto.Algorithm, error) {
	switch suite {
	case "eddsa-jcs-2022":
		return uaicrypto.AlgEdDSA, nil
	case "ecdsa-jcs-2019":
		// P-256 and P-384 share a cryptosuite name, so the curve of the key
		// decides. Guessing would make a P-384 proof fail against its own key.
		jwk, err := uaicrypto.JWKFromPublic(pub)
		if err != nil {
			return "", err
		}
		if jwk.Crv == "P-384" {
			return uaicrypto.AlgES384, nil
		}
		return uaicrypto.AlgES256, nil
	default:
		return "", fmt.Errorf("%w: unsupported cryptosuite %q", ErrProofMalformed, suite)
	}
}

func b64urlDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
