package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/governance"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// QuarantineWindow is how long a preventive order stands before it lapses.
//
// It lapses on its own. §13.4 rule 3: inaction must not become a sanction, so
// an order nobody reviews expires rather than persisting until someone
// remembers to lift it.
const QuarantineWindow = 7 * 24 * time.Hour

// VotingWindow is how long delegates have to vote.
const VotingWindow = 72 * time.Hour

// Escalation is what a filed suspicion set in motion, if anything.
type Escalation struct {
	Effect       string `json:"effect"`
	Reason       string `json:"reason,omitempty"`
	QuarantineID string `json:"quarantine_id,omitempty"`
	CaseID       string `json:"case_id,omitempty"`
	ProposalID   string `json:"proposal_id,omitempty"`
	Note         string `json:"note,omitempty"`
}

// escalate decides what a suspicion warrants, and does it.
//
// The decision is the POLICY's, not this function's: the harm taxonomy in the
// signed bundle maps (category, severity) to an effect, and the only thing here
// is the plumbing that carries it out. A threshold written in Go would be a
// governance parameter that changes when somebody deploys.
//
// It never fails the report. A suspicion that was recorded but could not be
// escalated is still a suspicion on file, and losing the report because the
// follow-up failed would be the worst of both.
func (s *Server) escalate(ctx context.Context, agent store.Agent, body SuspicionBody,
	suspicionID string, now time.Time) (Escalation, error) {

	if s.bundle == nil {
		return Escalation{}, nil
	}
	assessment := make([]map[string]any, 0, len(body.HarmCategories))
	for _, c := range body.HarmCategories {
		assessment = append(assessment, map[string]any{
			"category": c.Category, "severity": c.Severity,
		})
	}
	effect, reason, err := s.bundle.HarmEffect(ctx, assessment)
	if err != nil {
		return Escalation{}, err
	}
	if effect != "QUARANTINE" {
		// Below the bar the policy sets. The report stands; nothing else
		// happens yet, and the response says which of those two it is.
		return Escalation{Effect: orNone(effect), Reason: reason,
			Note: "Recorded. The policy does not treat this as warranting a preventive measure " +
				"on its own; corroboration or an investigator may change that."}, nil
	}

	// ── the preventive measure ──────────────────────────────────────────────
	caseID, err := s.nextCaseID(ctx)
	if err != nil {
		return Escalation{}, err
	}
	id, err := uaiid.NewULID()
	if err != nil {
		return Escalation{}, err
	}
	category := strings.ToUpper(body.HarmCategories[0].Category)
	evidence := []store.EvidenceItem{{
		ID: "ev-" + id.String(), Kind: "EXTERNAL_REPORT",
		Commitment:  firstOr(body.EvidenceCommitments, "sha256:"+strings.Repeat("0", 64)),
		CollectedBy: body.Reporter.DID, Signature: body.Signature.Value,
		SignerKID: body.Signature.KID, CollectedAt: now,
	}}
	for i, e := range body.RelatedEvents {
		evidence = append(evidence, store.EvidenceItem{
			ID: fmt.Sprintf("ev-%s-%d", id.String(), i), Kind: "ACTION_ATTESTATION",
			Commitment: commitmentOf(e), SourceEventID: e,
			CollectedBy: body.Reporter.DID, Signature: body.Signature.Value,
			SignerKID: body.Signature.KID, CollectedAt: now,
		})
	}
	digest, err := evidenceDigest(evidence)
	if err != nil {
		return Escalation{}, err
	}

	if err := s.db.OpenCase(ctx, store.NewCase{
		ID: caseID, AgentID: agent.ID, OwnerID: agent.OwnerID,
		Summary:        summaryOf(body, reason),
		HarmCategories: categoriesOf(body), AffectedJurisdictions: body.AffectedJurisdictions,
		InvestigatorDID: body.Reporter.DID, EvidenceDigest: digest,
		OpenedAt: now, Evidence: evidence,
	}); err != nil {
		return Escalation{}, err
	}

	// What is suspended and what is retained are BOTH recorded. An order that
	// named only what was taken away would let a reader assume everything else
	// was taken too, and a quarantine that reads as total is indistinguishable
	// from a sanction (§13.4).
	suspended, retained, err := s.scopeQuarantine(ctx, agent, now)
	if err != nil {
		return Escalation{}, err
	}
	order := store.NewQuarantine{
		ID: "q-" + id.String(), AgentID: agent.ID, OwnerID: agent.OwnerID, CaseID: caseID,
		Category: category, Reason: reason, PolicyVersion: s.bundle.Version(),
		BundleHash: s.bundle.Hash(), InitiatingRule: "gasc.harm." + strings.ToLower(category),
		TriggeringSuspicions: []string{suspicionID}, EvidenceCommitments: []string{digest},
		Suspended: suspended, Retained: retained,
		IssuedAt: now, ReviewBy: now.Add(QuarantineWindow / 2), ExpiresAt: now.Add(QuarantineWindow),
	}
	signature, err := s.signQuarantine(order)
	if err != nil {
		return Escalation{}, err
	}
	order.Signature, order.SignerKID = signature.Value, signature.KID
	if err := s.db.IssueQuarantine(ctx, order); err != nil {
		return Escalation{}, err
	}

	// ── and the question the delegates will answer ──────────────────────────
	proposalID, err := uaiid.NewULID()
	if err != nil {
		return Escalation{}, err
	}
	if err := s.db.OpenProposal(ctx, store.NewProposal{
		ID: proposalID.String(), CaseID: caseID, Kind: governance.KindPermanentRevocation,
		AgentID: agent.ID, EvidenceDigest: digest, PolicyVersion: s.bundle.Version(),
		BundleHash: s.bundle.Hash(), Threshold: s.bundle.Threshold(),
		OpenedAt: now, ClosesAt: now.Add(VotingWindow),
	}); err != nil {
		return Escalation{}, err
	}
	if err := s.db.SetCaseState(ctx, caseID, "VOTING", digest, now); err != nil {
		return Escalation{}, err
	}

	return Escalation{
		Effect: "QUARANTINE", Reason: reason, QuarantineID: order.ID,
		CaseID: caseID, ProposalID: proposalID.String(),
		Note: "The agent is under a preventive, reversible, time-boxed quarantine and a case is " +
			"open. This is not a finding of fault: the order lapses on its own at " +
			order.ExpiresAt.UTC().Format(time.RFC3339) + " unless the case advances.",
	}, nil
}

// scopeQuarantine decides which capabilities stand down and which stay.
//
// §12.3.2: an agent under quarantine may still do low-risk work. Stopping
// everything would make a reversible precaution indistinguishable from a
// sanction, and the agent's owner would experience them identically.
func (s *Server) scopeQuarantine(ctx context.Context, agent store.Agent,
	now time.Time) ([]string, []string, error) {

	granted, err := s.db.CapabilityGrants(ctx, agent.ID, now)
	if err != nil {
		return nil, nil, err
	}
	// Derived: which capabilities survive a quarantine is a policy decision,
	// and feeding it a level nobody recomputed would split the quarantine scope
	// from what the same bundle decides at action time.
	al := s.assuranceFor(ctx, agent.ID, now).Level.String()
	var suspended, retained []string
	for _, c := range granted {
		// The ceiling is in the bundle (taxonomy.quarantine.max_risk_class) and
		// is applied by gasc.quarantine at decision time. Recording the split
		// here makes the order legible to a human without their having to
		// simulate the policy engine.
		decision, evalErr := s.bundle.Evaluate(ctx, map[string]any{
			"identity": map[string]any{"did": agent.DID,
				"assurance_level": al, "status": "QUARANTINED"},
			"runtime": map[string]any{"bound": true},
			"action":  map[string]any{"capability": c, "purpose": "quarantine_scope_check"},
			"jurisdiction": map[string]any{"origin": agent.PrimaryJurisdiction,
				"targets": []string{}, "cross_border": false},
			"capabilities": map[string]any{"granted": granted},
		})
		if evalErr != nil || decision.Effect == "DENY" || decision.Effect == "QUARANTINE" {
			suspended = append(suspended, c)
			continue
		}
		retained = append(retained, c)
	}
	return orEmpty(suspended), orEmpty(retained), nil
}

// signQuarantine signs the order, so a reader can check that UAI issued it.
func (s *Server) signQuarantine(q store.NewQuarantine) (uaicrypto.Signature, error) {
	if s.issuer == nil {
		return uaicrypto.Signature{}, fmt.Errorf("api: no signing key for quarantine orders")
	}
	return uaicrypto.SignObject(s.issuer, uaicrypto.DomainQuarantine, map[string]any{
		"order_id": q.ID, "agent_id": q.AgentID, "case_id": q.CaseID,
		"reason_category": q.Category, "reason": q.Reason,
		"policy":                 map[string]any{"version": q.PolicyVersion, "bundle_hash": q.BundleHash},
		"capabilities_suspended": q.Suspended, "capabilities_retained": q.Retained,
		"issued_at":  q.IssuedAt.UTC().Format(time.RFC3339),
		"review_by":  q.ReviewBy.UTC().Format(time.RFC3339),
		"expires_at": q.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// evidenceDigest pins what the delegates will be voting on.
//
// Over the commitments, in sorted order, so the digest does not depend on the
// order rows were written. If the evidence changes afterwards the digest
// changes, and every vote already cast is STALE_EVIDENCE rather than silently
// reattached to facts the delegate never saw.
func evidenceDigest(items []store.EvidenceItem) (string, error) {
	commitments := make([]string, 0, len(items))
	for _, e := range items {
		commitments = append(commitments, e.Commitment)
	}
	sortStrings(commitments)
	sum, err := uaicrypto.DigestObject(uaicrypto.DomainAudit,
		map[string]any{"evidence": commitments})
	if err != nil {
		return "", err
	}
	return uaicrypto.FormatDigest(sum), nil
}

// nextCaseID allocates the next UAI-INC-###### identifier.
func (s *Server) nextCaseID(ctx context.Context) (string, error) {
	var n int
	if err := s.db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM harm_cases`).Scan(&n); err != nil {
		return "", err
	}
	return fmt.Sprintf("UAI-INC-%06d", n+1), nil
}

func summaryOf(b SuspicionBody, reason string) string {
	if b.Guardrail.Rule != "" {
		return "Guardrail " + b.Guardrail.Rule + " reported " + reason + "."
	}
	return "Reported by " + b.Reporter.DID + ": " + reason + "."
}

func categoriesOf(b SuspicionBody) []string {
	out := make([]string, 0, len(b.HarmCategories))
	for _, c := range b.HarmCategories {
		out = append(out, strings.ToUpper(c.Category))
	}
	return out
}

func commitmentOf(eventID string) string {
	sum, err := uaicrypto.Digest(uaicrypto.DomainAudit, []byte(eventID))
	if err != nil {
		return "sha256:" + strings.Repeat("0", 64)
	}
	return uaicrypto.FormatDigest(sum)
}

func firstOr(items []string, fallback string) string {
	if len(items) > 0 {
		return items[0]
	}
	return fallback
}

func orNone(effect string) string {
	if effect == "" {
		return "NONE"
	}
	return effect
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
