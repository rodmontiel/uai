package challenge_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

func statement(role challenge.Role, ch string) challenge.Ownership {
	return challenge.Ownership{
		Challenge: ch, RegistrationID: "reg_01JY8R9ZAF392N7QX2T81JH6KM", Role: role,
		AgentKeyThumbprint: "sha256:" + strings.Repeat("a", 64),
		OwnerDID:           "did:uai:owner:01JY8R9ZB00000000000000000",
	}
}

func TestSignAndVerify(t *testing.T) {
	signer, pub, err := uaicrypto.GenerateEd25519Signer("did:uai:owner:01JY8R9ZB00000000000000000#key-1")
	if err != nil {
		t.Fatal(err)
	}
	stmt := statement(challenge.RoleOwner, "chal-owner")
	sig, err := challenge.Sign(signer, stmt)
	if err != nil {
		t.Fatal(err)
	}
	if err := challenge.Verify(pub, stmt, sig); err != nil {
		t.Fatalf("a signature over the statement must verify: %v", err)
	}
}

// TestEveryMemberIsCovered: if a member could be changed without breaking the
// signature, the registry could record something other than what was signed.
func TestEveryMemberIsCovered(t *testing.T) {
	signer, pub, err := uaicrypto.GenerateEd25519Signer("did:uai:owner:01JY8R9ZB00000000000000000#key-1")
	if err != nil {
		t.Fatal(err)
	}
	stmt := statement(challenge.RoleOwner, "chal-owner")
	sig, err := challenge.Sign(signer, stmt)
	if err != nil {
		t.Fatal(err)
	}

	tampered := map[string]challenge.Ownership{}
	m := stmt
	m.Challenge = "other-challenge"
	tampered["challenge"] = m
	m = stmt
	m.RegistrationID = "reg_01JY8R9ZAF392N7QX2T81JH6KN"
	tampered["registration_id"] = m
	m = stmt
	m.Role = challenge.RoleAgent
	tampered["role"] = m
	m = stmt
	m.AgentKeyThumbprint = "sha256:" + strings.Repeat("b", 64)
	tampered["agent_key_thumbprint"] = m
	m = stmt
	m.OwnerDID = "did:uai:owner:01JY8R9ZB00000000000000001"
	tampered["owner_did"] = m

	for member, changed := range tampered {
		t.Run(member, func(t *testing.T) {
			if err := challenge.Verify(pub, changed, sig); err == nil {
				t.Errorf("%s is not covered by the signature", member)
			}
		})
	}
}

// TestDomainIsSeparated: the same bytes signed for another purpose must not
// verify as a registration proof.
func TestDomainIsSeparated(t *testing.T) {
	signer, pub, err := uaicrypto.GenerateEd25519Signer("did:uai:owner:01JY8R9ZB00000000000000000#key-1")
	if err != nil {
		t.Fatal(err)
	}
	stmt := statement(challenge.RoleOwner, "chal-owner")
	elsewhere, err := uaicrypto.SignObject(signer, uaicrypto.DomainAttestation, stmt)
	if err != nil {
		t.Fatal(err)
	}
	if err := challenge.Verify(pub, stmt, elsewhere); err == nil {
		t.Error("a signature made in the attestation domain verified as a registration proof")
	}
}

func TestSameSubject(t *testing.T) {
	owner := statement(challenge.RoleOwner, "chal-owner")
	agent := statement(challenge.RoleAgent, "chal-agent")
	if err := challenge.SameSubject(owner, agent); err != nil {
		t.Fatalf("matching halves must compose: %v", err)
	}

	for name, mutate := range map[string]func(*challenge.Ownership){
		"different agent key": func(o *challenge.Ownership) {
			o.AgentKeyThumbprint = "sha256:" + strings.Repeat("c", 64)
		},
		"different owner":        func(o *challenge.Ownership) { o.OwnerDID = "did:uai:owner:01ZZ" },
		"different registration": func(o *challenge.Ownership) { o.RegistrationID = "reg_other" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := agent
			mutate(&bad)
			if err := challenge.SameSubject(owner, bad); !errors.Is(err, challenge.ErrProofMismatch) {
				t.Errorf("got %v, want ErrProofMismatch", err)
			}
		})
	}

	t.Run("two halves of the same role", func(t *testing.T) {
		if err := challenge.SameSubject(owner, statement(challenge.RoleOwner, "chal-agent")); !errors.Is(err, challenge.ErrProofMismatch) {
			t.Error("two owner halves must not compose into a two-sided proof")
		}
	})
	t.Run("one challenge answered twice", func(t *testing.T) {
		if err := challenge.SameSubject(owner, statement(challenge.RoleAgent, "chal-owner")); !errors.Is(err, challenge.ErrProofMismatch) {
			t.Error("both halves answering one challenge is one proof submitted twice")
		}
	})
}

// TestIncompleteStatementsAreRefused: a statement missing a member would be
// signed with that member absent, and absent is not the same as agreed.
func TestIncompleteStatementsAreRefused(t *testing.T) {
	signer, _, err := uaicrypto.GenerateEd25519Signer("did:uai:owner:01JY8R9ZB00000000000000000#key-1")
	if err != nil {
		t.Fatal(err)
	}
	full := statement(challenge.RoleOwner, "chal-owner")
	for name, mutate := range map[string]func(*challenge.Ownership){
		"no challenge":    func(o *challenge.Ownership) { o.Challenge = "" },
		"no registration": func(o *challenge.Ownership) { o.RegistrationID = "" },
		"no thumbprint":   func(o *challenge.Ownership) { o.AgentKeyThumbprint = "" },
		"no owner":        func(o *challenge.Ownership) { o.OwnerDID = "" },
		"no role":         func(o *challenge.Ownership) { o.Role = "" },
		"unknown role":    func(o *challenge.Ownership) { o.Role = "auditor" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := full
			mutate(&bad)
			if _, err := challenge.Sign(signer, bad); err == nil {
				t.Error("an incomplete statement was signed")
			}
			if _, err := bad.SigningBytes(); err == nil {
				t.Error("an incomplete statement produced signing bytes")
			}
		})
	}
}

// TestChallengesAreUnpredictable is a smoke test: identical draws would make
// the whole flow replayable.
func TestChallengesAreUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		c, err := challenge.New()
		if err != nil {
			t.Fatal(err)
		}
		if seen[c] {
			t.Fatalf("challenge %q was issued twice", c)
		}
		seen[c] = true
	}
}
