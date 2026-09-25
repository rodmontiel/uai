package assurance_test

import (
	"testing"

	"github.com/rodmontiel/uai/pkg/assurance"
)

// TestTodaysAgentIsAL0AndSaysWhy is the state of the whole registry right now:
// software keys, self-asserted owners, and — after phase 12 — an attested
// runtime. The level does not move, and that is correct; what changes is that
// it now says which dimension is holding it.
func TestTodaysAgentIsAL0AndSaysWhy(t *testing.T) {
	got := assurance.Derive(assurance.Evidence{
		Key:     assurance.Software,
		Owner:   assurance.SelfAsserted,
		Runtime: assurance.SVIDWithImage,
	})
	if got.Level != assurance.AL0 {
		t.Fatalf("level = %s, want UAI-AL0: an attested runtime does not verify an owner", got.Level)
	}
	if got.LimitedBy != assurance.DimOwner {
		t.Errorf("limited by %q, want %q", got.LimitedBy, assurance.DimOwner)
	}
	if got.Reached[assurance.DimRuntime] != assurance.AL2 {
		t.Errorf("the runtime dimension reached %s, want UAI-AL2", got.Reached[assurance.DimRuntime])
	}
}

// TestAttestationAloneNeverRaisesTheLevel is the reading §6.8 has to exclude.
//
// If meeting one column were enough, workload attestation on its own would
// advertise an identity as suitable for "business operations, CRM, email".
func TestAttestationAloneNeverRaisesTheLevel(t *testing.T) {
	for name, e := range map[string]assurance.Evidence{
		"runtime only": {Key: assurance.Software, Owner: assurance.SelfAsserted,
			Runtime: assurance.RemoteAttestation},
		"key only": {Key: assurance.HSM, Owner: assurance.SelfAsserted, Runtime: assurance.NoRuntime},
		"owner only": {Key: assurance.Software, Owner: assurance.LegalEntityProof,
			Runtime: assurance.NoRuntime},
	} {
		t.Run(name, func(t *testing.T) {
			if got := assurance.Derive(e); got.Level != assurance.AL0 {
				t.Fatalf("level = %s, want UAI-AL0 (%s)", got.Level, got.Detail)
			}
		})
	}
}

// TestTheLevelIsTheMinimum walks the ladder.
func TestTheLevelIsTheMinimum(t *testing.T) {
	cases := []struct {
		name string
		e    assurance.Evidence
		want assurance.Level
	}{
		{"nothing", assurance.Evidence{Key: assurance.Software, Owner: assurance.SelfAsserted,
			Runtime: assurance.NoRuntime}, assurance.AL0},
		{"AL1 across the board", assurance.Evidence{Key: assurance.Software,
			Owner: assurance.DomainControl, Runtime: assurance.SVIDOnly}, assurance.AL1},
		{"AL2 across the board", assurance.Evidence{Key: assurance.TPM2,
			Owner: assurance.OrgCredential, Runtime: assurance.SVIDWithImage}, assurance.AL2},
		{"AL3 across the board", assurance.Evidence{Key: assurance.HSM,
			Owner: assurance.LegalEntityProof, Runtime: assurance.RemoteAttestation}, assurance.AL3},
		{"one weak dimension caps the rest", assurance.Evidence{Key: assurance.HSM,
			Owner: assurance.LegalEntityProof, Runtime: assurance.SVIDOnly}, assurance.AL1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := assurance.Derive(c.e)
			if got.Level != c.want {
				t.Fatalf("level = %s, want %s (%s)", got.Level, c.want, got.Detail)
			}
			if c.want < assurance.AL3 && got.Detail == "" {
				t.Error("a level below AL3 must say what limits it")
			}
		})
	}
}

// TestAnUnknownProtectionIsNotEvidence: guessing upward is the one direction
// this must never guess in.
func TestAnUnknownProtectionIsNotEvidence(t *testing.T) {
	got := assurance.Derive(assurance.Evidence{
		Key: "QUANTUM_VAULT_9000", Owner: assurance.LegalEntityProof,
		Runtime: assurance.RemoteAttestation})
	if got.Level != assurance.AL1 {
		t.Fatalf("level = %s, want UAI-AL1: an unrecognised protection is worth no more than software",
			got.Level)
	}
}

func TestLevelRoundTrips(t *testing.T) {
	for _, l := range []assurance.Level{assurance.AL0, assurance.AL1, assurance.AL2, assurance.AL3} {
		back, err := assurance.Parse(l.String())
		if err != nil || back != l {
			t.Errorf("%s did not round-trip: %v %v", l, back, err)
		}
	}
	if _, err := assurance.Parse("UAI-AL9"); err == nil {
		t.Error("UAI-AL9 was accepted")
	}
}
