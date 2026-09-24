package webauthn_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rodmontiel/uai/pkg/webauthn"
)

const (
	rpID   = "governance.uai.world"
	origin = "https://governance.uai.world"
)

// authenticator is a software stand-in for a hardware token.
//
// It exists to produce assertions this package can check. It is NOT what makes
// the invariant true in production: INV-005 rests on the assertion coming from
// hardware that requires a human gesture, and a test double cannot demonstrate
// that. What these tests demonstrate is that the verifier refuses everything it
// must refuse, which is the half that lives in this repository.
type authenticator struct {
	key       *ecdsa.PrivateKey
	rpID      string
	signCount uint32
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{key: key, rpID: rpID}
}

func (a *authenticator) authData(userPresent, userVerified bool) []byte {
	sum := sha256.Sum256([]byte(a.rpID))
	out := make([]byte, 0, 37)
	out = append(out, sum[:]...)
	var flags byte
	if userPresent {
		flags |= 0x01
	}
	if userVerified {
		flags |= 0x04
	}
	out = append(out, flags)
	a.signCount++
	out = append(out, byte(a.signCount>>24), byte(a.signCount>>16), byte(a.signCount>>8), byte(a.signCount))
	return out
}

func (a *authenticator) get(t *testing.T, challenge []byte, org string, up, uv bool) webauthn.Assertion {
	t.Helper()
	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      org,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertion := webauthn.Assertion{
		AuthenticatorData: a.authData(up, uv), ClientDataJSON: clientData,
	}
	sum := sha256.Sum256(webauthn.SignedBytes(assertion))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	assertion.Signature = sig
	return assertion
}

func expect(challenge []byte) webauthn.Expectation {
	return webauthn.Expectation{Challenge: challenge, Origin: origin, RelyingPartyID: rpID}
}

func TestAGenuineAssertionVerifies(t *testing.T) {
	a := newAuthenticator(t)
	challenge := []byte("the vote digest, 32 bytes exactly")[:32]
	if err := webauthn.Verify(&a.key.PublicKey, a.get(t, challenge, origin, true, true),
		expect(challenge)); err != nil {
		t.Fatalf("a genuine assertion was refused: %v", err)
	}
}

// TestAnAssertionWithoutUserVerificationIsNotAVote is INV-005.
//
// The token signed correctly. Nothing is cryptographically wrong. It is refused
// because it proves a device was present, not that a human decided — and a
// tally that counted it would make the threshold mean something else.
func TestAnAssertionWithoutUserVerificationIsNotAVote(t *testing.T) {
	a := newAuthenticator(t)
	challenge := []byte("the vote digest, 32 bytes exactly")[:32]
	err := webauthn.Verify(&a.key.PublicKey, a.get(t, challenge, origin, true, false), expect(challenge))
	if !errors.Is(err, webauthn.ErrNoUserVerification) {
		t.Fatalf("err = %v, want ErrNoUserVerification", err)
	}
}

func TestAnAssertionWithoutUserPresenceIsRefused(t *testing.T) {
	a := newAuthenticator(t)
	challenge := []byte("the vote digest, 32 bytes exactly")[:32]
	err := webauthn.Verify(&a.key.PublicKey, a.get(t, challenge, origin, false, true), expect(challenge))
	if !errors.Is(err, webauthn.ErrNoUserPresence) {
		t.Fatalf("err = %v, want ErrNoUserPresence", err)
	}
}

// TestAnAssertionCannotBeLiftedOntoAnotherVote is the property that makes the
// challenge-is-the-digest design worth having: a YES on one case cannot be
// replayed as a YES on another.
func TestAnAssertionCannotBeLiftedOntoAnotherVote(t *testing.T) {
	a := newAuthenticator(t)
	signed := []byte("digest of the vote actually cast!")[:32]
	other := []byte("digest of a different vote entire")[:32]
	err := webauthn.Verify(&a.key.PublicKey, a.get(t, signed, origin, true, true), expect(other))
	if !errors.Is(err, webauthn.ErrChallengeMismatch) {
		t.Fatalf("err = %v, want ErrChallengeMismatch", err)
	}
}

func TestAnAssertionFromAnotherOriginIsRefused(t *testing.T) {
	a := newAuthenticator(t)
	challenge := []byte("the vote digest, 32 bytes exactly")[:32]
	err := webauthn.Verify(&a.key.PublicKey,
		a.get(t, challenge, "https://not-uai.example", true, true), expect(challenge))
	if !errors.Is(err, webauthn.ErrOriginMismatch) {
		t.Fatalf("err = %v, want ErrOriginMismatch", err)
	}
}

func TestAnAssertionForAnotherRelyingPartyIsRefused(t *testing.T) {
	a := newAuthenticator(t)
	a.rpID = "someone-else.example"
	challenge := []byte("the vote digest, 32 bytes exactly")[:32]
	err := webauthn.Verify(&a.key.PublicKey, a.get(t, challenge, origin, true, true), expect(challenge))
	if !errors.Is(err, webauthn.ErrRelyingPartyMismatch) {
		t.Fatalf("err = %v, want ErrRelyingPartyMismatch", err)
	}
}

// TestARegistrationCeremonyIsNotAVote: accepting webauthn.create here would let
// the ceremony that enrolled a delegate be replayed as their vote.
func TestARegistrationCeremonyIsNotAVote(t *testing.T) {
	a := newAuthenticator(t)
	challenge := []byte("the vote digest, 32 bytes exactly")[:32]
	assertion := a.get(t, challenge, origin, true, true)
	var data map[string]any
	if err := json.Unmarshal(assertion.ClientDataJSON, &data); err != nil {
		t.Fatal(err)
	}
	data["type"] = "webauthn.create"
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	assertion.ClientDataJSON = raw
	err = webauthn.Verify(&a.key.PublicKey, assertion, expect(challenge))
	if !errors.Is(err, webauthn.ErrNotAnAssertion) {
		t.Fatalf("err = %v, want ErrNotAnAssertion", err)
	}
}

// TestAnotherDelegatesKeyDoesNotVerify: the assertion is bound to the
// credential the delegate registered, not to any credential at all.
func TestAnotherDelegatesKeyDoesNotVerify(t *testing.T) {
	a, b := newAuthenticator(t), newAuthenticator(t)
	challenge := []byte("the vote digest, 32 bytes exactly")[:32]
	err := webauthn.Verify(&b.key.PublicKey, a.get(t, challenge, origin, true, true), expect(challenge))
	if !errors.Is(err, webauthn.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// TestTamperingWithTheClientDataBreaksTheSignature: the challenge lives in the
// client data, so an attacker who edits it to match a different vote breaks
// exactly the thing they need intact.
func TestTamperingWithTheClientDataBreaksTheSignature(t *testing.T) {
	a := newAuthenticator(t)
	signed := []byte("digest of the vote actually cast!")[:32]
	other := []byte("digest of a different vote entire")[:32]
	assertion := a.get(t, signed, origin, true, true)

	var data map[string]any
	if err := json.Unmarshal(assertion.ClientDataJSON, &data); err != nil {
		t.Fatal(err)
	}
	data["challenge"] = base64.RawURLEncoding.EncodeToString(other)
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	assertion.ClientDataJSON = raw

	// The challenge now matches, and the signature does not.
	if err := webauthn.Verify(&a.key.PublicKey, assertion, expect(other)); !errors.Is(err, webauthn.ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestMalformedInputIsRefusedRatherThanGuessedAt(t *testing.T) {
	a := newAuthenticator(t)
	challenge := []byte("the vote digest, 32 bytes exactly")[:32]
	good := a.get(t, challenge, origin, true, true)

	for name, assertion := range map[string]webauthn.Assertion{
		"no authenticator data": {ClientDataJSON: good.ClientDataJSON, Signature: good.Signature},
		"truncated authenticator data": {
			AuthenticatorData: good.AuthenticatorData[:20],
			ClientDataJSON:    good.ClientDataJSON, Signature: good.Signature,
		},
		"no client data": {AuthenticatorData: good.AuthenticatorData, Signature: good.Signature},
		"no signature":   {AuthenticatorData: good.AuthenticatorData, ClientDataJSON: good.ClientDataJSON},
		"client data is not JSON": {
			AuthenticatorData: good.AuthenticatorData,
			ClientDataJSON:    []byte("not json"), Signature: good.Signature,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := webauthn.Verify(&a.key.PublicKey, assertion, expect(challenge)); err == nil {
				t.Fatal("malformed input was accepted")
			}
		})
	}

	// And an expectation that does not state what it expects.
	for name, want := range map[string]webauthn.Expectation{
		"no challenge":     {Origin: origin, RelyingPartyID: rpID},
		"no origin":        {Challenge: challenge, RelyingPartyID: rpID},
		"no relying party": {Challenge: challenge, Origin: origin},
	} {
		t.Run(name, func(t *testing.T) {
			if err := webauthn.Verify(&a.key.PublicKey, good, want); err == nil {
				t.Fatal("an incomplete expectation was accepted")
			}
		})
	}
}
