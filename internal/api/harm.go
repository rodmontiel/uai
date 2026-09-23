package api

import (
	"net/http"
	"strconv"
	"time"
)

// QuarantineView is one active order, rendered for a reader.
//
// Every field name and every note here is chosen so the record cannot be read
// as a finding of fault. A quarantine is preventive, reversible and time-boxed;
// a UI that presents it as a verdict turns a precaution into a sanction nobody
// decided (P13), and the API is where that framing has to start.
type QuarantineView struct {
	ID            string    `json:"id"`
	UAIID         string    `json:"uai_id"`
	CaseID        string    `json:"case_id,omitempty"`
	Category      string    `json:"reason_category"`
	Reason        string    `json:"reason"`
	PolicyVersion string    `json:"policy_version"`
	Suspended     []string  `json:"capabilities_suspended"`
	Retained      []string  `json:"capabilities_retained"`
	IssuedAt      time.Time `json:"issued_at"`
	ReviewBy      time.Time `json:"review_by"`
	ExpiresAt     time.Time `json:"expires_at"`
	ExpiresInSecs int64     `json:"expires_in_seconds"`
	Note          string    `json:"note"`
}

const quarantineNote = "Preventive, reversible and time-boxed. This is not a finding of fault, " +
	"and it lapses on its own at expires_at unless a case advances."

// listQuarantines answers GET /v1/quarantines.
func (s *Server) listQuarantines(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	orders, err := s.db.ActiveQuarantines(r.Context(), now, limit)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	out := make([]QuarantineView, 0, len(orders))
	for _, q := range orders {
		out = append(out, QuarantineView{
			ID: q.ID, UAIID: q.AgentUAIID, CaseID: q.CaseID, Category: q.Category,
			Reason: q.Reason, PolicyVersion: q.PolicyVersion,
			Suspended: orEmpty(q.Suspended), Retained: orEmpty(q.Retained),
			IssuedAt: q.IssuedAt.UTC(), ReviewBy: q.ReviewBy.UTC(), ExpiresAt: q.ExpiresAt.UTC(),
			ExpiresInSecs: int64(q.ExpiresAt.Sub(now).Seconds()), Note: quarantineNote,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"quarantines": out, "as_of": now.UTC()})
}

// CaseView is a harm case.
type CaseView struct {
	ID                    string     `json:"id"`
	UAIID                 string     `json:"uai_id"`
	State                 string     `json:"state"`
	Summary               string     `json:"summary"`
	HarmCategories        []string   `json:"harm_categories"`
	AffectedJurisdictions []string   `json:"affected_jurisdictions"`
	InvestigatorDID       string     `json:"investigator_did,omitempty"`
	EvidenceDigest        string     `json:"evidence_digest,omitempty"`
	ResponseWindowEnds    *time.Time `json:"response_window_ends,omitempty"`
	OpenedAt              time.Time  `json:"opened_at"`
	ClosedAt              *time.Time `json:"closed_at,omitempty"`
	Note                  string     `json:"note"`
}

const caseNote = "An open case is an investigation, not a conclusion. The evidence digest lets " +
	"a party check that what they were shown is what was recorded; the evidence itself is not public."

// getCase answers GET /v1/cases/{id}.
func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	c, err := s.db.CaseByID(r.Context(), r.PathValue("id"))
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, CaseView{
		ID: c.ID, UAIID: c.AgentUAIID, State: c.State, Summary: c.Summary,
		HarmCategories: orEmpty(c.HarmCategories), AffectedJurisdictions: orEmpty(c.AffectedJurisdictions),
		InvestigatorDID: c.InvestigatorDID, EvidenceDigest: c.EvidenceDigest,
		ResponseWindowEnds: c.ResponseWindowEnds, OpenedAt: c.OpenedAt.UTC(), ClosedAt: c.ClosedAt,
		Note: caseNote,
	})
}

// ProposalView is a governance proposal with its live tally.
type ProposalView struct {
	ID        string     `json:"id"`
	CaseID    string     `json:"case_id"`
	UAIID     string     `json:"uai_id"`
	Kind      string     `json:"kind"`
	State     string     `json:"state"`
	Threshold string     `json:"threshold"`
	VotesYes  int        `json:"votes_yes"`
	VotesNo   int        `json:"votes_no"`
	Countries int        `json:"countries_in_favour"`
	OpenedAt  time.Time  `json:"opened_at"`
	ClosesAt  *time.Time `json:"closes_at,omitempty"`
}

// listProposals answers GET /v1/governance/proposals.
func (s *Server) listProposals(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	proposals, err := s.db.OpenProposals(r.Context(), limit)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	out := make([]ProposalView, 0, len(proposals))
	for _, p := range proposals {
		out = append(out, ProposalView{
			ID: p.ID, CaseID: p.CaseID, UAIID: p.AgentUAIID, Kind: p.Kind, State: p.State,
			Threshold: p.Threshold, VotesYes: p.VotesYes, VotesNo: p.VotesNo,
			Countries: p.Countries, OpenedAt: p.OpenedAt.UTC(), ClosesAt: p.ClosesAt,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"proposals": out,
		// Stated on every response, because it is the sentence most likely to
		// be misread by whoever builds on this. Revocation means participants
		// stop honouring the credential; it is not a switch that stops code.
		"note": "A revocation proposal decides whether UAI participants stop honouring an " +
			"identity's credentials. It cannot stop software from running.",
	})
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
