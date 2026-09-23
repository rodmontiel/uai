package credential_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/credential"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

const (
	agentDID = "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"
	ownerDID = "did:uai:owner:01JY8R9ZB00000000000000000"
	issuer   = "did:web:credentials.uai.world"
	regID    = "reg_01JY8R9ZAF392N7QX2T81JH6KM"
)

func identityCred(t *testing.T) credential.Credential {
	t.Helper()
	until := time.Now().Add(365 * 24 * time.Hour)
	c, err := credential.New(credential.TypeIdentity,
		"urn:uai:credential:01JY8R9ZAF392N7QX2T81JH6KM", issuer,
		credential.IdentitySubject{
			ID: agentDID, Name: "DeliveryOptimizer", AgentType: "autonomous_task_agent",
			PrimaryJurisdiction: "AR", AssuranceLevel: "UAI-AL0",
			AgentKeyThumbprint: "sha256:" + strings.Repeat("a", 64),
		}, time.Now(), &until)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIssueAndVerify(t *testing.T) {
	for _, alg := range []uaicrypto.Algorithm{uaicrypto.AlgEdDSA, uaicrypto.AlgES256, uaicrypto.AlgES384} {
		t.Run(string(alg), func(t *testing.T) {
			var signer uaicrypto.Signer
			var pub any
			var err error
			if alg == uaicrypto.AlgEdDSA {
				signer, pub, err = uaicrypto.GenerateEd25519Signer(issuer + "#key-1")
			} else {
				signer, pub, err = uaicrypto.GenerateECDSASigner(alg, issuer+"#key-1")
			}
			if err != nil {
				t.Fatal(err)
			}
			signed, err := credential.Issue(signer, identityCred(t), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if signed.Proof == nil || signed.Proof.ProofValue == "" {
				t.Fatal("issued credential carries no proof")
			}
			// Multibase base58btc, which is what the VC ecosystem emits.
			if !strings.HasPrefix(signed.Proof.ProofValue, "z") {
				t.Errorf("proofValue %q is not multibase base58btc", signed.Proof.ProofValue[:1])
			}
			if err := credential.Verify(pub, signed); err != nil {
				t.Fatalf("a freshly issued credential must verify: %v", err)
			}
		})
	}
}

// TestProofCoversEveryClaim: if a field could change without breaking the
// proof, the credential would assert something the issuer never signed.
func TestProofCoversEveryClaim(t *testing.T) {
	signer, pub, err := uaicrypto.GenerateEd25519Signer(issuer + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := credential.Issue(signer, identityCred(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*credential.Credential){
		"issuer":     func(c *credential.Credential) { c.Issuer = "did:web:attacker.example" },
		"id":         func(c *credential.Credential) { c.ID = "urn:uai:credential:01ZZZZZZZZZZZZZZZZZZZZZZZZ" },
		"validFrom":  func(c *credential.Credential) { c.ValidFrom = c.ValidFrom.Add(-time.Hour) },
		"validUntil": func(c *credential.Credential) { t := c.ValidFrom.Add(100 * 365 * 24 * time.Hour); c.ValidUntil = &t },
		"type":       func(c *credential.Credential) { c.Type = []string{"VerifiableCredential", credential.TypePassport} },
		"subject": func(c *credential.Credential) {
			var s credential.IdentitySubject
			_ = json.Unmarshal(c.CredentialSubject, &s)
			s.AssuranceLevel = "UAI-AL3"
			c.CredentialSubject, _ = json.Marshal(s)
		},
		"verificationMethod": func(c *credential.Credential) { c.Proof.VerificationMethod = "did:web:attacker.example#key-1" },
		"created":            func(c *credential.Credential) { c.Proof.Created = c.Proof.Created.Add(time.Hour) },
		"proofPurpose":       func(c *credential.Credential) { c.Proof.ProofPurpose = "authentication" },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := signed
			proof := *signed.Proof
			tampered.Proof = &proof
			mutate(&tampered)
			if err := credential.Verify(pub, tampered); err == nil {
				t.Errorf("%s is not covered by the proof", name)
			}
		})
	}
}

// TestDomainIsEnforced: a proof labelled with another domain must not verify,
// even when the signature bytes are otherwise well formed.
func TestDomainIsEnforced(t *testing.T) {
	signer, pub, err := uaicrypto.GenerateEd25519Signer(issuer + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := credential.Issue(signer, identityCred(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	relabelled := signed
	proof := *signed.Proof
	proof.Domain = string(uaicrypto.DomainAttestation)
	relabelled.Proof = &proof
	if err := credential.Verify(pub, relabelled); err == nil {
		t.Error("a proof relabelled into the attestation domain verified as a credential")
	}
}

// TestOwnershipVerifiesWithoutTheIssuer is the promise of §6.4.1: a relying
// party checks ownership from the credential alone.
func TestOwnershipVerifiesWithoutTheIssuer(t *testing.T) {
	ownerSigner, ownerPub, err := uaicrypto.GenerateEd25519Signer(ownerDID + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	agentSigner, agentPub, err := uaicrypto.GenerateEd25519Signer(agentDID + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	agentJWK, err := uaicrypto.JWKFromPublic(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := agentJWK.ThumbprintString()
	if err != nil {
		t.Fatal(err)
	}
	jwkBytes, err := json.Marshal(agentJWK)
	if err != nil {
		t.Fatal(err)
	}

	ownerStmt := challenge.Ownership{Challenge: "chal-owner", RegistrationID: regID,
		Role: challenge.RoleOwner, AgentKeyThumbprint: tp, OwnerDID: ownerDID}
	agentStmt := challenge.Ownership{Challenge: "chal-agent", RegistrationID: regID,
		Role: challenge.RoleAgent, AgentKeyThumbprint: tp, OwnerDID: ownerDID}
	ownerSig, err := challenge.Sign(ownerSigner, ownerStmt)
	if err != nil {
		t.Fatal(err)
	}
	agentSig, err := challenge.Sign(agentSigner, agentStmt)
	if err != nil {
		t.Fatal(err)
	}

	subject := credential.OwnershipSubject{
		ID: agentDID, OwnerDID: ownerDID, EffectiveFrom: time.Now(),
		BindingProof: credential.BindingProof{
			RegistrationID: regID, AgentKeyThumbprint: tp, AgentPublicKeyJwk: jwkBytes,
			OwnerKeyID: ownerDID + "#key-1",
			OwnerProof: credential.ProofHalf{Challenge: "chal-owner", Signature: ownerSig},
			AgentProof: credential.ProofHalf{Challenge: "chal-agent", Signature: agentSig},
		},
	}
	if err := credential.VerifyOwnership(subject, ownerPub); err != nil {
		t.Fatalf("a genuine two-sided proof must verify standalone: %v", err)
	}

	t.Run("a swapped agent key is caught", func(t *testing.T) {
		_, otherPub, err := uaicrypto.GenerateEd25519Signer("did:key:other#key-1")
		if err != nil {
			t.Fatal(err)
		}
		otherJWK, err := uaicrypto.JWKFromPublic(otherPub)
		if err != nil {
			t.Fatal(err)
		}
		bad := subject
		bad.BindingProof.AgentPublicKeyJwk, _ = json.Marshal(otherJWK)
		if err := credential.VerifyOwnership(bad, ownerPub); !errors.Is(err, credential.ErrOwnershipUnproven) {
			t.Errorf("got %v, want ErrOwnershipUnproven", err)
		}
	})

	t.Run("a different owner key does not satisfy it", func(t *testing.T) {
		_, wrongOwner, err := uaicrypto.GenerateEd25519Signer(ownerDID + "#key-1")
		if err != nil {
			t.Fatal(err)
		}
		if err := credential.VerifyOwnership(subject, wrongOwner); !errors.Is(err, credential.ErrOwnershipUnproven) {
			t.Errorf("got %v, want ErrOwnershipUnproven", err)
		}
	})

	t.Run("the owner cannot be renamed after the fact", func(t *testing.T) {
		bad := subject
		bad.OwnerDID = "did:uai:owner:01JY8R9ZB00000000000000001"
		if err := credential.VerifyOwnership(bad, ownerPub); !errors.Is(err, credential.ErrOwnershipUnproven) {
			t.Errorf("got %v, want ErrOwnershipUnproven", err)
		}
	})
}

func TestUnsignedAndMalformedAreRefused(t *testing.T) {
	_, pub, err := uaicrypto.GenerateEd25519Signer(issuer + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.Verify(pub, identityCred(t)); !errors.Is(err, credential.ErrUnsigned) {
		t.Errorf("an unsigned credential must be refused: %v", err)
	}
	if _, err := identityCred(t).Hash(); !errors.Is(err, credential.ErrUnsigned) {
		t.Errorf("hashing an unsigned credential must fail: %v", err)
	}

	incomplete := identityCred(t)
	incomplete.Issuer = ""
	if _, err := credential.Issue(mustSigner(t), incomplete, time.Now()); err == nil {
		t.Error("a credential with no issuer was signed")
	}
}

func TestValidityWindow(t *testing.T) {
	c := identityCred(t)
	if err := c.ValidAt(c.ValidFrom.Add(-time.Second)); !errors.Is(err, credential.ErrNotYetValid) {
		t.Errorf("got %v, want ErrNotYetValid", err)
	}
	if err := c.ValidAt(c.ValidFrom.Add(time.Hour)); err != nil {
		t.Errorf("inside the window: %v", err)
	}
	if err := c.ValidAt(c.ValidUntil.Add(time.Second)); !errors.Is(err, credential.ErrExpired) {
		t.Errorf("got %v, want ErrExpired", err)
	}
}

func TestMultibaseRoundTrip(t *testing.T) {
	signer, pub, err := uaicrypto.GenerateEd25519Signer(issuer + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	// Leading zero bytes are the classic base58 bug: they carry no positional
	// value, so an encoder that drops them silently shortens the signature.
	for i := 0; i < 64; i++ {
		signed, err := credential.Issue(signer, identityCred(t), time.Now().Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if err := credential.Verify(pub, signed); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
}

func mustSigner(t *testing.T) uaicrypto.Signer {
	t.Helper()
	s, _, err := uaicrypto.GenerateEd25519Signer(issuer + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
