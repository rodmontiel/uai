// Package webauthn verifies the hardware assertions that carry a delegate's
// vote (§16.1).
//
// # Why the challenge is the vote digest
//
// A conventional design authenticates the human and then records what the
// authenticated session said. That produces a signature over a session, and a
// session is a thing an automated process can hold. By making the WebAuthn
// challenge BE the digest of the vote, the hardware signature covers the voted
// content itself: an assertion cannot be replayed onto a different vote, and no
// process that did not physically touch the authenticator can produce one.
//
// That is INV-005 — no automated process casts a vote — expressed as
// cryptography rather than as an access rule. An access rule is enforced by
// whoever runs the service. This is enforced by the authenticator.
//
// # User verification is required, not preferred
//
// An assertion with the UV flag clear proves only that a device was present. It
// is refused here rather than accepted with a note, because "a vote, but we are
// not sure a human was there" has no place to go: the tally either counts it or
// does not, and counting it would make the threshold meaningless.
//
// No dependencies: this is on the verification path, and it is what an
// independent auditor runs to recompute a tally from signed statements.
package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Errors returned by this package. They are distinct types because a caller
// must be able to tell "this is not a vote" from "this vote is forged": the
// first is a client bug, the second is an attack.
var (
	// ErrNotAnAssertion is returned when clientDataJSON is not a get ceremony.
	ErrNotAnAssertion = errors.New("webauthn: clientDataJSON is not a webauthn.get ceremony")
	// ErrChallengeMismatch is returned when the signed challenge is not the
	// expected digest. This is the check that binds the assertion to the vote.
	ErrChallengeMismatch = errors.New("webauthn: the assertion does not cover the expected challenge")
	// ErrOriginMismatch is returned when the ceremony happened somewhere else.
	ErrOriginMismatch = errors.New("webauthn: the assertion was produced for a different origin")
	// ErrRelyingPartyMismatch is returned when the authenticator signed for a
	// different relying party.
	ErrRelyingPartyMismatch = errors.New("webauthn: the assertion names a different relying party")
	// ErrNoUserPresence is returned when the user-present flag is clear.
	ErrNoUserPresence = errors.New("webauthn: the authenticator did not report user presence")
	// ErrNoUserVerification is returned when the user-verified flag is clear.
	// INV-005 rests on this: an assertion without it is not a vote.
	ErrNoUserVerification = errors.New("webauthn: the authenticator did not verify the user")
	// ErrBadSignature is returned when the assertion signature does not verify.
	ErrBadSignature = errors.New("webauthn: assertion signature does not verify")
	// ErrMalformed is returned for structurally invalid input.
	ErrMalformed = errors.New("webauthn: malformed assertion")
)

// Authenticator data flag bits (WebAuthn §6.1).
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

// authDataMinLen is rpIdHash(32) + flags(1) + signCount(4).
const authDataMinLen = 37

// Assertion is the material a browser returns from navigator.credentials.get.
type Assertion struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// Expectation is what the assertion must turn out to cover.
//
// Every field is required. A verifier that defaulted the origin or the relying
// party would accept an assertion produced by a different site for a different
// purpose, which is the substitution the ceremony exists to prevent.
type Expectation struct {
	// Challenge is the raw bytes the assertion must have signed: the vote
	// digest. Not a nonce, not a session id.
	Challenge []byte
	// Origin is the exact origin string the browser recorded.
	Origin string
	// RelyingPartyID is the domain the authenticator scoped the credential to.
	RelyingPartyID string
}

// clientData is the subset of clientDataJSON that is checked.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// Flags reports what the authenticator asserted about the ceremony.
type Flags struct {
	UserPresent  bool
	UserVerified bool
}

// ParseFlags reads the flag byte of authenticator data.
func ParseFlags(authenticatorData []byte) (Flags, error) {
	if len(authenticatorData) < authDataMinLen {
		return Flags{}, fmt.Errorf("%w: authenticator data is %d bytes, need at least %d",
			ErrMalformed, len(authenticatorData), authDataMinLen)
	}
	b := authenticatorData[32]
	return Flags{
		UserPresent:  b&flagUserPresent != 0,
		UserVerified: b&flagUserVerified != 0,
	}, nil
}

// SignedBytes returns what the authenticator actually signed:
//
//	authenticatorData || SHA-256(clientDataJSON)
//
// Exported because an auditor recomputing a tally needs to reproduce it without
// trusting this package's verification path.
func SignedBytes(a Assertion) []byte {
	sum := sha256.Sum256(a.ClientDataJSON)
	out := make([]byte, 0, len(a.AuthenticatorData)+len(sum))
	out = append(out, a.AuthenticatorData...)
	out = append(out, sum[:]...)
	return out
}

// Verify checks an assertion against a registered credential.
//
// The checks run in the order a reviewer would ask about them, and each one is
// its own error: a caller that cannot tell WHY an assertion was refused will
// eventually treat all refusals alike.
func Verify(pub crypto.PublicKey, a Assertion, want Expectation) error {
	if len(a.AuthenticatorData) < authDataMinLen || len(a.ClientDataJSON) == 0 || len(a.Signature) == 0 {
		return fmt.Errorf("%w: an assertion needs authenticator data, client data and a signature",
			ErrMalformed)
	}
	if len(want.Challenge) == 0 || want.Origin == "" || want.RelyingPartyID == "" {
		return fmt.Errorf("%w: the expectation must state the challenge, origin and relying party",
			ErrMalformed)
	}

	var data clientData
	if err := json.Unmarshal(a.ClientDataJSON, &data); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	// "webauthn.create" is a registration, not a vote. Accepting one here would
	// let the ceremony that enrolled a delegate be replayed as their vote.
	if data.Type != "webauthn.get" {
		return fmt.Errorf("%w: type is %q", ErrNotAnAssertion, data.Type)
	}
	got, err := base64.RawURLEncoding.DecodeString(data.Challenge)
	if err != nil {
		return fmt.Errorf("%w: challenge is not base64url: %v", ErrMalformed, err)
	}
	// Constant time, because this compares a value an attacker chooses against
	// one they are trying to guess.
	if subtle.ConstantTimeCompare(got, want.Challenge) != 1 {
		return ErrChallengeMismatch
	}
	if data.Origin != want.Origin {
		return fmt.Errorf("%w: %q, want %q", ErrOriginMismatch, data.Origin, want.Origin)
	}

	rpIDHash := sha256.Sum256([]byte(want.RelyingPartyID))
	if subtle.ConstantTimeCompare(a.AuthenticatorData[:32], rpIDHash[:]) != 1 {
		return ErrRelyingPartyMismatch
	}

	flags, err := ParseFlags(a.AuthenticatorData)
	if err != nil {
		return err
	}
	if !flags.UserPresent {
		return ErrNoUserPresence
	}
	// INV-005. Checked before the signature so that an assertion which is
	// cryptographically fine but not user-verified is refused for the reason
	// that actually disqualifies it.
	if !flags.UserVerified {
		return ErrNoUserVerification
	}

	return verifySignature(pub, SignedBytes(a), a.Signature)
}

func verifySignature(pub crypto.PublicKey, message, signature []byte) error {
	sum := sha256.Sum256(message)
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		// WebAuthn ES256 signatures are ASN.1 DER. VerifyASN1 rejects trailing
		// bytes and non-canonical encodings, which a hand-rolled parser would
		// have to be careful to do.
		if !ecdsa.VerifyASN1(key, sum[:], signature) {
			return ErrBadSignature
		}
		return nil
	case ed25519.PublicKey:
		// Ed25519 signs the message, not a pre-hash: passing the digest here
		// would verify a different statement than the one the caller thinks.
		if !ed25519.Verify(key, message, signature) {
			return ErrBadSignature
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported key type %T", ErrMalformed, pub)
	}
}
