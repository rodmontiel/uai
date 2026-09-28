package attest_test

import (
	"errors"
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/attest"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

const (
	agentDID = "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"
	ownerDID = "did:uai:owner:01JY8R9ZB00000000000000000"
	digestA  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func sample() attest.Attestation {
	return attest.Attestation{
		UAIVersion: attest.Version,
		EventID:    "01JY8RA3C7K2V9M0QW4T6Z8XPD",
		AgentDID:   agentDID,
		OwnerDID:   ownerDID,
		Timestamp:  attest.NewTimestamp(time.Date(2026, 9, 22, 14, 2, 4, 0, time.UTC)),
		Nonce:      "8f1c2b9d4e6a7c3f0b1d2e3a4c5b6d7e",
		Action:     attest.Action{Type: "route.optimize", Capability: "route.optimize"},
		Purpose:    "delivery_optimization",
		Jurisdiction: attest.Jurisdiction{
			Origin: "AR", Targets: []string{}, CrossBorder: false, Basis: "owner_jurisdiction",
		},
		Policy: attest.Policy{
			Version: "GASC-2027.4", BundleHash: digestA,
			DecisionID: "01JY8RA3C0000000000000000Z", Decision: "ALLOW",
		},
		Outcome:  attest.OutcomeSuccess,
		Sequence: 1,
	}
}

func signer(t *testing.T, kid string) (uaicrypto.Signer, any) {
	t.Helper()
	s, pub, err := uaicrypto.GenerateEd25519Signer(kid)
	if err != nil {
		t.Fatal(err)
	}
	return s, pub
}

func TestSignAndVerify(t *testing.T) {
	s, pub := signer(t, agentDID+"#key-1")
	signed, err := attest.Sign(s, sample())
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.Verify(pub, signed); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignatureCoversEveryField(t *testing.T) {
	s, pub := signer(t, agentDID+"#key-1")
	signed, err := attest.Sign(s, sample())
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*attest.Attestation){
		"outcome":        func(a *attest.Attestation) { a.Outcome = attest.OutcomeFailure },
		"capability":     func(a *attest.Attestation) { a.Action.Capability = "wire.transfer" },
		"purpose":        func(a *attest.Attestation) { a.Purpose = "something_else" },
		"decision":       func(a *attest.Attestation) { a.Policy.Decision = "DENY" },
		"policy version": func(a *attest.Attestation) { a.Policy.Version = "GASC-2026.1" },
		"jurisdiction":   func(a *attest.Attestation) { a.Jurisdiction.Origin = "DE" },
		"previous hash":  func(a *attest.Attestation) { a.PreviousEventHash = digestA },
		"sequence":       func(a *attest.Attestation) { a.Sequence = 99 },
		"owner":          func(a *attest.Attestation) { a.OwnerDID = "did:web:someone.example" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			tampered := signed
			mutate(&tampered)
			if err := attest.Verify(pub, tampered); err == nil {
				t.Fatalf("mutating %s did not invalidate the signature", name)
			}
		})
	}
}

func TestUnsignedRejected(t *testing.T) {
	a := sample()
	if err := a.Validate(); !errors.Is(err, attest.ErrUnsigned) {
		t.Fatalf("expected ErrUnsigned, got %v", err)
	}
}

func TestPolicyReferenceIsMandatory(t *testing.T) {
	// INV-009: an attestation with no decision behind it is POLICY_UNEVALUATED
	// and must never pass as compliant.
	s, _ := signer(t, agentDID+"#key-1")
	for name, strip := range map[string]func(*attest.Attestation){
		"no version":     func(a *attest.Attestation) { a.Policy.Version = "" },
		"no bundle hash": func(a *attest.Attestation) { a.Policy.BundleHash = "" },
		"no decision id": func(a *attest.Attestation) { a.Policy.DecisionID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			a := sample()
			strip(&a)
			signed, err := attest.Sign(s, a)
			if err != nil {
				t.Fatal(err)
			}
			if err := signed.Validate(); !errors.Is(err, attest.ErrPolicyUnreferenced) {
				t.Fatalf("expected ErrPolicyUnreferenced, got %v", err)
			}
		})
	}
}

func TestSignerMustBelongToTheDeclaredAgent(t *testing.T) {
	// An attestation that names one identity and is signed by another would be
	// attribution by string comparison.
	other := "did:uai:agent:01JY8R9ZC00000000000000000"
	s, pub := signer(t, other+"#key-1")
	signed, err := attest.Sign(s, sample())
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.Verify(pub, signed); !errors.Is(err, attest.ErrIdentityMismatch) {
		t.Fatalf("expected ErrIdentityMismatch, got %v", err)
	}
}

func TestCrossBorderNeedsATarget(t *testing.T) {
	s, _ := signer(t, agentDID+"#key-1")
	a := sample()
	a.Jurisdiction.CrossBorder = true
	a.Jurisdiction.Targets = nil
	signed, err := attest.Sign(s, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.Validate(); !errors.Is(err, attest.ErrIncomplete) {
		t.Fatalf("expected ErrIncomplete, got %v", err)
	}
}

func TestPassportStateMustBeCaptured(t *testing.T) {
	// The passport's state at decision time must survive the passport's later
	// expiry or revocation, so it is recorded in the attestation itself.
	s, _ := signer(t, agentDID+"#key-1")
	a := sample()
	a.Passport = &attest.Passport{Required: true}
	signed, err := attest.Sign(s, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.Validate(); !errors.Is(err, attest.ErrPassportUnrecorded) {
		t.Fatalf("expected ErrPassportUnrecorded, got %v", err)
	}
}

func TestWrongDomainRejected(t *testing.T) {
	s, _ := signer(t, agentDID+"#key-1")
	a := sample()
	payload, err := a.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(uaicrypto.DomainVote, payload)
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = sig
	if err := a.Validate(); !errors.Is(err, attest.ErrWrongDomain) {
		t.Fatalf("expected ErrWrongDomain, got %v", err)
	}
}

func TestHashBindsTheSignature(t *testing.T) {
	// Successors reference the hash of the SIGNED attestation, so re-signing the
	// same payload with a different key yields a different chain link.
	s1, _ := signer(t, agentDID+"#key-1")
	s2, _ := signer(t, agentDID+"#key-2")
	a1, err := attest.Sign(s1, sample())
	if err != nil {
		t.Fatal(err)
	}
	a2, err := attest.Sign(s2, sample())
	if err != nil {
		t.Fatal(err)
	}
	h1, err := a1.Hash()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := a2.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("the event hash does not bind the signature")
	}
}

func TestChainLinkage(t *testing.T) {
	s, _ := signer(t, agentDID+"#key-1")
	first, err := attest.Sign(s, sample())
	if err != nil {
		t.Fatal(err)
	}
	h, err := first.Hash()
	if err != nil {
		t.Fatal(err)
	}
	next := sample()
	next.EventID = "01JY8RA4D8L3W0N1RX5U7A9YQE"
	next.Sequence = 2
	next.PreviousEventHash = h
	signedNext, err := attest.Sign(s, next)
	if err != nil {
		t.Fatal(err)
	}
	if !signedNext.LinksTo(h) {
		t.Fatal("successor does not link to its predecessor")
	}
	if signedNext.LinksTo(digestA) {
		t.Fatal("successor claims to link to an unrelated predecessor")
	}
}
