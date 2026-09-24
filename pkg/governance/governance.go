// Package governance implements the part of §16 that a third party must be able
// to recompute without us: the vote digest, the tally, and the governance proof.
//
// The design principle it serves is stated in §16.3 — the administrator who
// executes a revocation supplies ONE input, the decision id, and every
// consequence is already fixed by the governance proof. That is only true if
// the proof is a pure function of the signed votes. So everything here is a
// pure function of its arguments: no clock, no database, no network. An auditor
// who has the votes can rebuild the proof and check that the revocation matches
// what the delegates actually signed.
//
// No dependencies, for the same reason: this is what a relying party runs to
// decide whether a revocation was authorized, and it must be auditable in one
// sitting.
package governance

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Proposal kinds (§16.1).
const (
	KindPermanentRevocation   = "PERMANENT_REVOCATION"
	KindCapabilityRestriction = "CAPABILITY_RESTRICTION"
	KindAssuranceDowngrade    = "ASSURANCE_DOWNGRADE"
	KindPassportRevocation    = "PASSPORT_REVOCATION"
	KindClearance             = "CLEARANCE"
)

// Vote values.
const (
	VoteYes = "YES"
	VoteNo  = "NO"
)

// Errors returned by this package.
var (
	// ErrMalformedThreshold is returned for a threshold that is not "M-of-N".
	ErrMalformedThreshold = errors.New("governance: threshold must be written M-of-N")
	// ErrDuplicateDelegate is returned when one delegate appears twice.
	ErrDuplicateDelegate = errors.New("governance: a delegate voted twice on one proposal")
	// ErrStaleEvidence is returned when a vote covers different evidence than
	// the proposal. A tally that mixed them would count votes cast on facts
	// that are no longer the facts.
	ErrStaleEvidence = errors.New("governance: the vote was cast against different evidence")
	// ErrIncomplete is returned when a statement is missing a signed member.
	ErrIncomplete = errors.New("governance: statement is incomplete")
)

// Threshold is the M-of-N rule plus the minimum number of distinct countries.
//
// The country minimum exists because M-of-N alone is satisfiable by one
// jurisdiction's delegates acting together, and a revocation decided inside a
// single jurisdiction is a national decision wearing an international label.
type Threshold struct {
	Required     int
	Total        int
	MinCountries int
}

// ParseThreshold reads "4-of-5".
func ParseThreshold(s string) (Threshold, error) {
	required, total, found := strings.Cut(s, "-of-")
	if !found {
		return Threshold{}, fmt.Errorf("%w: %q", ErrMalformedThreshold, s)
	}
	m, err := strconv.Atoi(required)
	if err != nil {
		return Threshold{}, fmt.Errorf("%w: %q", ErrMalformedThreshold, s)
	}
	n, err := strconv.Atoi(total)
	if err != nil {
		return Threshold{}, fmt.Errorf("%w: %q", ErrMalformedThreshold, s)
	}
	if m <= 0 || n <= 0 || m > n {
		return Threshold{}, fmt.Errorf("%w: %q is not satisfiable", ErrMalformedThreshold, s)
	}
	return Threshold{Required: m, Total: n}, nil
}

// String renders the threshold as it is written in policy.
func (t Threshold) String() string {
	return strconv.Itoa(t.Required) + "-of-" + strconv.Itoa(t.Total)
}

// Vote is one delegate's signed statement (§16.1).
//
// AssertionCommitment is a digest of the WebAuthn assertion rather than the
// assertion itself. The proof must be reproducible by anyone holding the
// statements, and an assertion contains authenticator data that identifies a
// physical device: committing to it keeps the proof checkable without
// publishing which token a named person carries.
type Vote struct {
	VoteID              string    `json:"vote_id"`
	CaseID              string    `json:"case_id"`
	Proposal            string    `json:"proposal"`
	SubjectAgentDID     string    `json:"subject_agent_did"`
	EvidenceDigest      string    `json:"evidence_digest"`
	DelegateDID         string    `json:"delegate_did"`
	Country             string    `json:"country"`
	Value               string    `json:"vote"`
	AssertionCommitment string    `json:"assertion_commitment"`
	CastAt              time.Time `json:"cast_at"`
}

// Validate reports whether every member that must be signed is present.
func (v Vote) Validate() error {
	switch {
	case v.VoteID == "":
		return fmt.Errorf("%w: vote_id", ErrIncomplete)
	case v.CaseID == "":
		return fmt.Errorf("%w: case_id", ErrIncomplete)
	case v.SubjectAgentDID == "":
		return fmt.Errorf("%w: subject_agent_did", ErrIncomplete)
	case v.EvidenceDigest == "":
		return fmt.Errorf("%w: evidence_digest", ErrIncomplete)
	case v.DelegateDID == "":
		return fmt.Errorf("%w: delegate_did", ErrIncomplete)
	case v.Country == "":
		return fmt.Errorf("%w: country", ErrIncomplete)
	case v.Value != VoteYes && v.Value != VoteNo:
		return fmt.Errorf("%w: vote must be YES or NO, got %q", ErrIncomplete, v.Value)
	case v.AssertionCommitment == "":
		return fmt.Errorf("%w: assertion_commitment", ErrIncomplete)
	}
	return nil
}

// Statement is what a delegate's authenticator signs, as the WebAuthn
// challenge.
//
// It names the case, the proposal, the subject, the evidence and the value.
// Everything that makes the vote mean what it means is inside the digest, so an
// assertion cannot be lifted onto a different case, a different agent, or the
// opposite answer.
type Statement struct {
	CaseID          string `json:"case_id"`
	Proposal        string `json:"proposal"`
	SubjectAgentDID string `json:"subject_agent_did"`
	EvidenceDigest  string `json:"evidence_digest"`
	DelegateDID     string `json:"delegate_did"`
	Value           string `json:"vote"`
	Nonce           string `json:"nonce"`
}

// Digest returns the bytes a delegate's authenticator signs as its challenge.
func (s Statement) Digest() ([]byte, error) {
	if s.CaseID == "" || s.SubjectAgentDID == "" || s.DelegateDID == "" || s.Nonce == "" {
		return nil, fmt.Errorf("%w: a vote digest names the case, subject, delegate and nonce",
			ErrIncomplete)
	}
	if s.Value != VoteYes && s.Value != VoteNo {
		return nil, fmt.Errorf("%w: vote must be YES or NO, got %q", ErrIncomplete, s.Value)
	}
	return uaicrypto.DigestObject(uaicrypto.DomainVote, s)
}

// Tally is the recomputed outcome of a proposal.
type Tally struct {
	Yes       int
	No        int
	Pending   int
	Countries int
	// Authorized is true only when the threshold AND the country minimum are
	// both met. They are one field rather than two because a caller that had to
	// check both would eventually check one.
	Authorized bool
	// Why explains the outcome in the vocabulary of the threshold, for a record
	// that has to be readable by whoever is affected by it.
	Why string
}

// Count recomputes a tally from signed votes.
//
// Recomputed, never read from a stored counter. A counter is a number someone
// can write; this is a function of the statements, and the statements are
// signed by hardware. §16.3 precondition 5 is exactly this call.
//
// Votes must already have been verified against their delegates' credentials —
// this function counts, it does not authenticate. Separating the two is
// deliberate: an auditor recomputing a tally and a service accepting a vote
// have different inputs available, and folding them together would force the
// auditor to hold delegate keys they may not have.
func Count(votes []Vote, evidenceDigest string, threshold Threshold) (Tally, error) {
	seen := map[string]bool{}
	countries := map[string]bool{}
	var t Tally

	for _, v := range votes {
		if err := v.Validate(); err != nil {
			return Tally{}, err
		}
		if seen[v.DelegateDID] {
			return Tally{}, fmt.Errorf("%w: %s", ErrDuplicateDelegate, v.DelegateDID)
		}
		seen[v.DelegateDID] = true
		// A vote cast against a different evidence digest is STALE_EVIDENCE
		// (§16.1): the delegate answered a question about other facts. It is an
		// error rather than a skipped row, because silently dropping it would
		// change a tally without saying so.
		if evidenceDigest != "" && v.EvidenceDigest != evidenceDigest {
			return Tally{}, fmt.Errorf("%w: %s voted on %s, the proposal is on %s",
				ErrStaleEvidence, v.DelegateDID, v.EvidenceDigest, evidenceDigest)
		}
		switch v.Value {
		case VoteYes:
			t.Yes++
			countries[strings.ToUpper(v.Country)] = true
		case VoteNo:
			t.No++
		}
	}
	t.Countries = len(countries)
	t.Pending = threshold.Total - t.Yes - t.No
	if t.Pending < 0 {
		return Tally{}, fmt.Errorf("%w: %d votes cast against a %s threshold",
			ErrMalformedThreshold, t.Yes+t.No, threshold)
	}

	switch {
	case t.Yes < threshold.Required:
		t.Why = fmt.Sprintf("%d of %d required YES votes", t.Yes, threshold.Required)
	case threshold.MinCountries > 0 && t.Countries < threshold.MinCountries:
		// The threshold is met and the decision is still refused. This is the
		// case the country minimum exists for, and the reason says so rather
		// than reporting a vague failure.
		t.Why = fmt.Sprintf("%d YES votes from %d countries, %d required",
			t.Yes, t.Countries, threshold.MinCountries)
	default:
		t.Authorized = true
		t.Why = fmt.Sprintf("%d of %s YES from %d countries", t.Yes, threshold, t.Countries)
	}
	return t, nil
}

// Policy is the policy reference a decision is made under.
type Policy struct {
	Version    string `json:"version"`
	BundleHash string `json:"bundle_hash"`
	Threshold  string `json:"threshold"`
}

// ProofInput is the canonical bundle the governance proof hashes (§16.2).
//
// The votes are sorted by vote id so that the proof does not depend on the order
// rows came back from a database. Two parties recomputing it from the same
// statements must get the same bytes, or the proof proves nothing.
type ProofInput struct {
	CaseID          string `json:"case_id"`
	Proposal        string `json:"proposal"`
	SubjectAgentDID string `json:"subject_agent_did"`
	EvidenceDigest  string `json:"evidence_digest"`
	Policy          Policy `json:"policy"`
	Votes           []Vote `json:"votes"`
}

// Proof returns the governance proof: the hash of the canonical bundle
// {case_id, proposal, evidence_digest, policy, all vote statements}.
//
// This is the object the smart contract verifies, and the only input the
// administrator executing a revocation supplies is the decision id that names
// it. Every consequence is fixed here.
func Proof(in ProofInput) (string, error) {
	if in.CaseID == "" || in.Proposal == "" || in.SubjectAgentDID == "" || in.EvidenceDigest == "" {
		return "", fmt.Errorf("%w: a governance proof names the case, proposal, subject and evidence",
			ErrIncomplete)
	}
	if in.Policy.Version == "" || in.Policy.BundleHash == "" || in.Policy.Threshold == "" {
		return "", fmt.Errorf("%w: a governance proof names the policy that set the threshold",
			ErrIncomplete)
	}
	if len(in.Votes) == 0 {
		return "", fmt.Errorf("%w: a governance proof over no votes proves nothing", ErrIncomplete)
	}
	sorted := make([]Vote, len(in.Votes))
	copy(sorted, in.Votes)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].VoteID < sorted[j].VoteID })
	for _, v := range sorted {
		if err := v.Validate(); err != nil {
			return "", err
		}
	}
	in.Votes = sorted

	sum, err := uaicrypto.DigestObject(uaicrypto.DomainRevocation, in)
	if err != nil {
		return "", err
	}
	return uaicrypto.FormatDigest(sum), nil
}

// Decision is the authorized outcome (§16.2).
type Decision struct {
	DecisionID      string    `json:"decision_id"`
	CaseID          string    `json:"case_id"`
	SubjectAgentDID string    `json:"subject_agent_did"`
	Proposal        string    `json:"proposal"`
	Policy          Policy    `json:"policy"`
	EvidenceDigest  string    `json:"evidence_digest"`
	Tally           Tally     `json:"tally"`
	Votes           []Vote    `json:"votes"`
	AuthorizedAt    time.Time `json:"authorized_at"`
	GovernanceProof string    `json:"governance_proof"`
	Status          string    `json:"status"`
}

// Recompute rebuilds the tally and the proof from the decision's own votes and
// reports whether they match what the decision claims.
//
// This is §16.3 preconditions 5 and 6 as one call, and it is what uai-verify
// runs. A decision that cannot survive it is a decision whose stated outcome
// does not follow from the statements it carries — which is the only kind of
// forgery this design leaves room for.
func Recompute(d Decision) error {
	threshold, err := ParseThreshold(d.Policy.Threshold)
	if err != nil {
		return err
	}
	tally, err := Count(d.Votes, d.EvidenceDigest, threshold)
	if err != nil {
		return err
	}
	if tally.Yes != d.Tally.Yes || tally.No != d.Tally.No {
		return fmt.Errorf("governance: recomputed tally %d/%d does not match the recorded %d/%d",
			tally.Yes, tally.No, d.Tally.Yes, d.Tally.No)
	}
	if !tally.Authorized {
		return fmt.Errorf("governance: the votes do not authorize this decision: %s", tally.Why)
	}
	proof, err := Proof(ProofInput{
		CaseID: d.CaseID, Proposal: d.Proposal, SubjectAgentDID: d.SubjectAgentDID,
		EvidenceDigest: d.EvidenceDigest, Policy: d.Policy, Votes: d.Votes,
	})
	if err != nil {
		return err
	}
	if proof != d.GovernanceProof {
		return fmt.Errorf("governance: recomputed proof %s does not match the recorded %s",
			proof, d.GovernanceProof)
	}
	return nil
}
