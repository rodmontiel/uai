package governance_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/governance"
)

const evidence = "sha256:3e7b000000000000000000000000000000000000000000000000000000000000"

func vote(id, delegate, country, value string) governance.Vote {
	return governance.Vote{
		VoteID: id, CaseID: "UAI-INC-000041", Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
		EvidenceDigest:  evidence, DelegateDID: "did:uai:delegate:" + delegate,
		Country: country, Value: value,
		AssertionCommitment: "sha256:" + strings.Repeat("a", 64),
		CastAt:              time.Date(2026, 9, 25, 11, 0, 0, 0, time.UTC),
	}
}

func fourOfFive() governance.Threshold {
	t, err := governance.ParseThreshold("4-of-5")
	if err != nil {
		panic(err)
	}
	t.MinCountries = 3
	return t
}

// TestTheDemoTally is criterion 17: four YES, one NO, threshold met.
func TestTheDemoTally(t *testing.T) {
	votes := []governance.Vote{
		vote("01A", "01AR", "AR", "YES"),
		vote("01B", "01DE", "DE", "YES"),
		vote("01C", "01JP", "JP", "YES"),
		vote("01D", "01CA", "CA", "YES"),
		vote("01E", "01IN", "IN", "NO"),
	}
	got, err := governance.Count(votes, evidence, fourOfFive())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Authorized {
		t.Fatalf("4-of-5 with 4 YES was not authorized: %s", got.Why)
	}
	if got.Yes != 4 || got.No != 1 || got.Pending != 0 || got.Countries != 4 {
		t.Fatalf("tally = %+v", got)
	}
}

// TestOneJurisdictionCannotDecideAlone is why the country minimum exists.
//
// Four YES votes meet 4-of-5. All four from one country is a national decision
// wearing an international label, and the threshold alone cannot tell the
// difference.
func TestOneJurisdictionCannotDecideAlone(t *testing.T) {
	votes := []governance.Vote{
		vote("01A", "01AR1", "AR", "YES"),
		vote("01B", "01AR2", "AR", "YES"),
		vote("01C", "01AR3", "AR", "YES"),
		vote("01D", "01AR4", "AR", "YES"),
		vote("01E", "01IN", "IN", "NO"),
	}
	got, err := governance.Count(votes, evidence, fourOfFive())
	if err != nil {
		t.Fatal(err)
	}
	if got.Authorized {
		t.Fatal("four YES votes from one country authorized a revocation")
	}
	if got.Yes != 4 {
		t.Fatalf("the threshold itself should be met: %+v", got)
	}
	if !strings.Contains(got.Why, "countries") {
		t.Errorf("the reason does not say what was missing: %q", got.Why)
	}
}

// TestNoVotesDoNotCount: only YES votes contribute countries. A NO from a fifth
// country must not help a revocation reach its jurisdictional spread.
func TestNoVotesDoNotCountTowardsCountries(t *testing.T) {
	votes := []governance.Vote{
		vote("01A", "01AR", "AR", "YES"),
		vote("01B", "01DE", "DE", "YES"),
		vote("01C", "01AR2", "AR", "YES"),
		vote("01D", "01JP", "JP", "NO"),
		vote("01E", "01CA", "CA", "NO"),
	}
	got, err := governance.Count(votes, evidence, fourOfFive())
	if err != nil {
		t.Fatal(err)
	}
	if got.Countries != 2 {
		t.Fatalf("countries = %d, want 2: NO votes must not widen the spread", got.Countries)
	}
	if got.Authorized {
		t.Fatal("3 YES against a 4-of-5 threshold authorized a revocation")
	}
}

// TestADelegateCannotVoteTwice: without this, one compromised authenticator
// reaches any threshold on its own.
func TestADelegateCannotVoteTwice(t *testing.T) {
	votes := []governance.Vote{
		vote("01A", "01AR", "AR", "YES"),
		vote("01B", "01AR", "AR", "YES"),
	}
	if _, err := governance.Count(votes, evidence, fourOfFive()); !errors.Is(err, governance.ErrDuplicateDelegate) {
		t.Fatalf("err = %v, want ErrDuplicateDelegate", err)
	}
}

// TestStaleEvidenceIsAnError, not a silently dropped row: a delegate who voted
// against different evidence answered a different question.
func TestStaleEvidenceIsAnError(t *testing.T) {
	stale := vote("01A", "01AR", "AR", "YES")
	stale.EvidenceDigest = "sha256:" + strings.Repeat("f", 64)
	votes := []governance.Vote{stale, vote("01B", "01DE", "DE", "YES")}
	if _, err := governance.Count(votes, evidence, fourOfFive()); !errors.Is(err, governance.ErrStaleEvidence) {
		t.Fatalf("err = %v, want ErrStaleEvidence", err)
	}
}

// TestTheProofDoesNotDependOnVoteOrder. Two parties recomputing it from the
// same statements must get the same bytes, whatever order their database
// returned the rows in.
func TestTheProofDoesNotDependOnVoteOrder(t *testing.T) {
	in := governance.ProofInput{
		CaseID: "UAI-INC-000041", Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
		EvidenceDigest:  evidence,
		Policy: governance.Policy{Version: "GASC-2027.4",
			BundleHash: "sha256:" + strings.Repeat("1", 64), Threshold: "4-of-5"},
		Votes: []governance.Vote{
			vote("01A", "01AR", "AR", "YES"),
			vote("01B", "01DE", "DE", "YES"),
			vote("01C", "01JP", "JP", "YES"),
		},
	}
	first, err := governance.Proof(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Votes[0], in.Votes[2] = in.Votes[2], in.Votes[0]
	second, err := governance.Proof(in)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("the proof depends on row order: %s vs %s", first, second)
	}
}

// TestTheProofCoversEveryConsequence. §16.3 says the administrator supplies one
// input and every consequence is fixed by the proof. That is only true if
// changing any consequence changes the proof.
func TestTheProofCoversEveryConsequence(t *testing.T) {
	base := governance.ProofInput{
		CaseID: "UAI-INC-000041", Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
		EvidenceDigest:  evidence,
		Policy: governance.Policy{Version: "GASC-2027.4",
			BundleHash: "sha256:" + strings.Repeat("1", 64), Threshold: "4-of-5"},
		Votes: []governance.Vote{vote("01A", "01AR", "AR", "YES")},
	}
	original, err := governance.Proof(base)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*governance.ProofInput){
		"a different subject":   func(p *governance.ProofInput) { p.SubjectAgentDID = "did:uai:agent:01OTHER" },
		"a different case":      func(p *governance.ProofInput) { p.CaseID = "UAI-INC-000042" },
		"a different proposal":  func(p *governance.ProofInput) { p.Proposal = governance.KindClearance },
		"different evidence":    func(p *governance.ProofInput) { p.EvidenceDigest = "sha256:" + strings.Repeat("9", 64) },
		"a lowered threshold":   func(p *governance.ProofInput) { p.Policy.Threshold = "1-of-5" },
		"another policy bundle": func(p *governance.ProofInput) { p.Policy.BundleHash = "sha256:" + strings.Repeat("2", 64) },
		"a flipped vote":        func(p *governance.ProofInput) { p.Votes[0].Value = governance.VoteNo },
		"an extra vote": func(p *governance.ProofInput) {
			p.Votes = append(p.Votes, vote("01Z", "01ZZ", "ZZ", "YES"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			altered := base
			altered.Votes = append([]governance.Vote(nil), base.Votes...)
			mutate(&altered)
			got, err := governance.Proof(altered)
			if err != nil {
				t.Fatal(err)
			}
			if got == original {
				t.Fatalf("%s did not change the governance proof", name)
			}
		})
	}
}

// TestRecomputeRejectsAForgedDecision: the only forgery this design leaves room
// for is a decision whose stated outcome does not follow from its own votes.
//
// This is INV-010 -- "permanent revocation requires valid human decision
// evidence" -- at the application layer. The contract is the primary check
// (§16.3); this is the one that runs before anything reaches a chain, and it
// refuses the same four forgeries: a tally that does not match the votes, a
// vote removed after the fact, a subject swapped after authorization, and a
// threshold lowered to fit the votes that arrived.
func TestRecomputeRejectsAForgedDecision(t *testing.T) {
	votes := []governance.Vote{
		vote("01A", "01AR", "AR", "YES"),
		vote("01B", "01DE", "DE", "YES"),
		vote("01C", "01JP", "JP", "YES"),
		vote("01D", "01CA", "CA", "YES"),
		vote("01E", "01IN", "IN", "NO"),
	}
	policy := governance.Policy{Version: "GASC-2027.4",
		BundleHash: "sha256:" + strings.Repeat("1", 64), Threshold: "4-of-5"}
	proof, err := governance.Proof(governance.ProofInput{
		CaseID: "UAI-INC-000041", Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
		EvidenceDigest:  evidence, Policy: policy, Votes: votes,
	})
	if err != nil {
		t.Fatal(err)
	}
	honest := governance.Decision{
		DecisionID: "01JY8RF6", CaseID: "UAI-INC-000041",
		SubjectAgentDID: "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
		Proposal:        governance.KindPermanentRevocation, Policy: policy,
		EvidenceDigest: evidence, Tally: governance.Tally{Yes: 4, No: 1},
		Votes: votes, GovernanceProof: proof, Status: "AUTHORIZED",
	}
	if err := governance.Recompute(honest); err != nil {
		t.Fatalf("an honest decision was rejected: %v", err)
	}

	for name, mutate := range map[string]func(*governance.Decision){
		"a tally that does not match the votes": func(d *governance.Decision) {
			d.Tally = governance.Tally{Yes: 5, No: 0}
		},
		"a vote removed after the fact": func(d *governance.Decision) {
			d.Votes = d.Votes[:3]
			d.Tally = governance.Tally{Yes: 3, No: 0}
		},
		"a subject swapped after authorization": func(d *governance.Decision) {
			d.SubjectAgentDID = "did:uai:agent:01SOMEONEELSE"
		},
		"a threshold lowered to fit the votes": func(d *governance.Decision) {
			d.Policy.Threshold = "1-of-5"
		},
	} {
		t.Run(name, func(t *testing.T) {
			forged := honest
			forged.Votes = append([]governance.Vote(nil), honest.Votes...)
			mutate(&forged)
			if err := governance.Recompute(forged); err == nil {
				t.Fatalf("%s survived recomputation", name)
			}
		})
	}
}

// TestThresholdParsing refuses what cannot be satisfied.
func TestThresholdParsing(t *testing.T) {
	for _, bad := range []string{"", "4of5", "4-of-", "-of-5", "0-of-5", "6-of-5", "x-of-5"} {
		if _, err := governance.ParseThreshold(bad); err == nil {
			t.Errorf("%q was accepted as a threshold", bad)
		}
	}
	got, err := governance.ParseThreshold("4-of-5")
	if err != nil || got.Required != 4 || got.Total != 5 || got.String() != "4-of-5" {
		t.Fatalf("ParseThreshold(4-of-5) = %+v, %v", got, err)
	}
}

// TestTheVoteDigestBindsEveryChoice: an assertion must not be liftable onto a
// different case, agent, evidence or answer.
func TestTheVoteDigestBindsEveryChoice(t *testing.T) {
	base := governance.Statement{
		CaseID: "UAI-INC-000041", Proposal: governance.KindPermanentRevocation,
		SubjectAgentDID: "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
		EvidenceDigest:  evidence, DelegateDID: "did:uai:delegate:01AR",
		Value: governance.VoteYes, Nonce: "8f1c2b9d4e6a7c3f0b1d2e3a4c5b6d7e",
	}
	original, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*governance.Statement){
		"the answer":   func(s *governance.Statement) { s.Value = governance.VoteNo },
		"the case":     func(s *governance.Statement) { s.CaseID = "UAI-INC-000042" },
		"the subject":  func(s *governance.Statement) { s.SubjectAgentDID = "did:uai:agent:01OTHER" },
		"the evidence": func(s *governance.Statement) { s.EvidenceDigest = "sha256:" + strings.Repeat("0", 64) },
		"the delegate": func(s *governance.Statement) { s.DelegateDID = "did:uai:delegate:01DE" },
		"the proposal": func(s *governance.Statement) { s.Proposal = governance.KindClearance },
	} {
		t.Run(name, func(t *testing.T) {
			altered := base
			mutate(&altered)
			got, err := altered.Digest()
			if err != nil {
				t.Fatal(err)
			}
			if string(got) == string(original) {
				t.Fatalf("changing %s did not change the digest the authenticator signs", name)
			}
		})
	}
}
