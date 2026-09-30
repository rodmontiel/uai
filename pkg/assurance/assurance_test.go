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

// TestFromEvidenceIsTheOnlyTranslation covers the step that used to live
// privately in the API: raw stored strings to a level. It is here and not
// there because the API is not the only reader, and a second implementation of
// §6.8 is a second answer.
func TestFromEvidenceIsTheOnlyTranslation(t *testing.T) {
	cases := []struct {
		name          string
		protections   []string
		owner         string
		attestor      string
		imageDigest   string
		wantLevel     assurance.Level
		wantLimitedBy assurance.Dimension
	}{
		{
			name: "nothing bound", protections: []string{"SOFTWARE"}, owner: "SELF_ASSERTED",
			wantLevel: assurance.AL0, wantLimitedBy: assurance.DimRuntime,
		},
		{
			// The case the whole runtime dimension exists for: the agent said
			// where it runs, and its word is worth exactly nothing.
			name: "self-declared runtime", protections: []string{"SOFTWARE"},
			owner: "SELF_ASSERTED", attestor: "self-declared",
			wantLevel: assurance.AL0, wantLimitedBy: assurance.DimRuntime,
		},
		{
			name: "attested runtime, owner is now the ceiling", protections: []string{"SOFTWARE"},
			owner: "SELF_ASSERTED", attestor: "spiffe://uai.test",
			wantLevel: assurance.AL0, wantLimitedBy: assurance.DimOwner,
		},
		{
			// An image digest only counts when the attestor supplied it. The
			// caller is responsible for not passing one the agent typed.
			// Key AL3, owner AL2, runtime AL2: the minimum is AL2 and two
			// dimensions hold it there. The tie goes to the one a reader can act
			// on soonest, which is the runtime -- the owner is reported in
			// Reached either way, so nothing is hidden by the choice.
			name: "attested with an image digest", protections: []string{"HSM"},
			owner: "ORG_CREDENTIAL_VERIFIED", attestor: "spiffe://uai.test",
			imageDigest: "sha256:abc",
			wantLevel:   assurance.AL2, wantLimitedBy: assurance.DimRuntime,
		},
		{
			// Evidence the registry cannot read is not evidence. An empty
			// protection list means no valid key, and guessing upward here is
			// the one direction this must never guess in.
			name: "no valid key", protections: nil, owner: "LEGAL_ENTITY_VERIFIED",
			attestor: "spiffe://uai.test", imageDigest: "sha256:abc",
			wantLevel: assurance.AL1, wantLimitedBy: assurance.DimKey,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := assurance.FromEvidence(c.protections, c.owner, c.attestor, c.imageDigest)
			if got.Level != c.wantLevel {
				t.Errorf("level = %s, want %s (reached %v)", got.Level, c.wantLevel, got.Reached)
			}
			if got.LimitedBy != c.wantLimitedBy {
				t.Errorf("limited by %q, want %q", got.LimitedBy, c.wantLimitedBy)
			}
			if got.Detail == "" {
				t.Error("a level below AL3 must say what would have to change")
			}
		})
	}
}
