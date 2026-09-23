package store

import (
	"context"
	"time"
)

// QuarantineOrder is a preventive, reversible, time-boxed restriction.
//
// Everything that reads one has to keep that framing: a quarantine is not a
// finding of fault, and a UI or an API that renders it as one turns a
// precaution into a sanction nobody decided (P13).
type QuarantineOrder struct {
	ID            string
	AgentID       string
	AgentUAIID    string
	CaseID        string
	Category      string
	Reason        string
	PolicyVersion string
	// Suspended and Retained are both reported. Naming only what was taken away
	// would let a reader assume everything else was taken away too, and a
	// quarantine that reads as total is indistinguishable from a sanction.
	Suspended []string
	Retained  []string
	IssuedAt  time.Time
	ReviewBy  time.Time
	ExpiresAt time.Time
	SignerKID string
}

// ActiveQuarantines lists orders in force at a moment.
//
// Expiry is applied in the query, not left to a sweep: §6.10 rule 5 makes
// release by expiry mandatory, and an order that outlived its window because
// nobody ran a job would be punishment by inertia.
func (db *DB) ActiveQuarantines(ctx context.Context, at time.Time, limit int) ([]QuarantineOrder, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.pool.Query(ctx, `
		SELECT q.id, q.agent_id, a.uai_id, q.case_id, q.reason_category::text, q.reason_text,
		       q.policy_version, q.capabilities_suspended, q.capabilities_retained,
		       q.issued_at, q.review_by, q.expires_at, q.signer_kid
		  FROM quarantine_orders q JOIN agents a ON a.id = q.agent_id
		 WHERE q.released_at IS NULL AND q.expires_at > $1
		 ORDER BY q.issued_at DESC LIMIT $2`, at, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []QuarantineOrder{}
	for rows.Next() {
		var q QuarantineOrder
		var caseID *string
		if err := rows.Scan(&q.ID, &q.AgentID, &q.AgentUAIID, &caseID, &q.Category, &q.Reason,
			&q.PolicyVersion, &q.Suspended, &q.Retained,
			&q.IssuedAt, &q.ReviewBy, &q.ExpiresAt, &q.SignerKID); err != nil {
			return nil, classify(err)
		}
		q.CaseID = deref(caseID)
		out = append(out, q)
	}
	return out, classify(rows.Err())
}

// HarmCase is an investigation record.
type HarmCase struct {
	ID                    string
	AgentID               string
	AgentUAIID            string
	OwnerID               string
	State                 string
	Summary               string
	HarmCategories        []string
	AffectedJurisdictions []string
	InvestigatorDID       string
	EvidenceDigest        string
	ResponseWindowEnds    *time.Time
	OpenedAt              time.Time
	ClosedAt              *time.Time
}

// CaseByID loads a harm case.
func (db *DB) CaseByID(ctx context.Context, id string) (HarmCase, error) {
	var c HarmCase
	var investigator, evidence *string
	err := db.pool.QueryRow(ctx, `
		SELECT c.id, c.agent_id, a.uai_id, c.owner_id, c.state::text, c.summary,
		       c.harm_categories::text[], c.affected_jurisdictions::text[],
		       c.investigator_did, c.evidence_digest, c.response_window_ends,
		       c.opened_at, c.closed_at
		  FROM harm_cases c JOIN agents a ON a.id = c.agent_id
		 WHERE c.id = $1`, id).
		Scan(&c.ID, &c.AgentID, &c.AgentUAIID, &c.OwnerID, &c.State, &c.Summary,
			&c.HarmCategories, &c.AffectedJurisdictions, &investigator, &evidence,
			&c.ResponseWindowEnds, &c.OpenedAt, &c.ClosedAt)
	if err != nil {
		return HarmCase{}, classify(err)
	}
	c.InvestigatorDID, c.EvidenceDigest = deref(investigator), deref(evidence)
	return c, nil
}

// Proposal is a governance proposal with its tally.
type Proposal struct {
	ID         string
	CaseID     string
	AgentUAIID string
	Kind       string
	State      string
	// Threshold as it stood when the proposal opened. Snapshotting it is what
	// stops a quorum being moved under a vote already in progress.
	Threshold string
	OpenedAt  time.Time
	ClosesAt  *time.Time
	VotesYes  int
	VotesNo   int
	Countries int
}

// OpenProposals lists proposals currently open for voting, with their tallies.
//
// Only live votes are counted: a superseded vote is a statement the delegate
// replaced, and counting both would let one delegate weigh twice.
func (db *DB) OpenProposals(ctx context.Context, limit int) ([]Proposal, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.pool.Query(ctx, `
		SELECT p.id, p.case_id, a.uai_id, p.kind::text, p.state::text, p.threshold_snapshot,
		       p.opened_at, p.closes_at,
		       COALESCE(SUM(CASE WHEN v.value = 'YES' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN v.value = 'NO'  THEN 1 ELSE 0 END), 0),
		       COUNT(DISTINCT CASE WHEN v.value = 'YES' THEN v.country_code END)
		  FROM governance_proposals p
		  JOIN agents a ON a.id = p.subject_agent_id
		  LEFT JOIN votes v ON v.proposal_id = p.id AND v.superseded_by IS NULL
		 GROUP BY p.id, p.case_id, a.uai_id, p.kind, p.state, p.threshold_snapshot,
		          p.opened_at, p.closes_at
		 ORDER BY p.opened_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []Proposal{}
	for rows.Next() {
		var p Proposal
		if err := rows.Scan(&p.ID, &p.CaseID, &p.AgentUAIID, &p.Kind, &p.State, &p.Threshold,
			&p.OpenedAt, &p.ClosesAt, &p.VotesYes, &p.VotesNo, &p.Countries); err != nil {
			return nil, classify(err)
		}
		out = append(out, p)
	}
	return out, classify(rows.Err())
}
