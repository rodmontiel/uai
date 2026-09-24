package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Delegate is an appointed human who can vote (§16.1).
//
// The WebAuthn credential is the whole point: there is no software key here for
// an automated process to steal and use, and INV-005 rests on that column being
// the only way a vote can be produced.
type Delegate struct {
	ID             string
	UAIID          string
	DID            string
	Country        string
	DisplayName    string
	IsAlternate    bool
	CredentialID   []byte
	PublicJWK      json.RawMessage
	CredentialHash string
	Status         string
	AppointedAt    time.Time
}

// CreateDelegate appoints a delegate.
func (db *DB) CreateDelegate(ctx context.Context, d Delegate) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO human_delegates (id, uai_id, did, country_code, display_name, is_alternate,
		                             webauthn_credential_id, webauthn_public_key,
		                             credential_hash, status, appointed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE(NULLIF($10,''),'ACTIVE')::entity_status,
		        COALESCE($11, now()))`,
		d.ID, d.UAIID, d.DID, d.Country, d.DisplayName, d.IsAlternate,
		d.CredentialID, d.PublicJWK, d.CredentialHash, d.Status, nullableTime(d.AppointedAt))
	return classify(err)
}

// DelegateByDID loads a delegate.
func (db *DB) DelegateByDID(ctx context.Context, did string) (Delegate, error) {
	var d Delegate
	err := db.pool.QueryRow(ctx, `
		SELECT id, uai_id, did, country_code, display_name, is_alternate,
		       webauthn_credential_id, webauthn_public_key, credential_hash,
		       status::text, appointed_at
		  FROM human_delegates WHERE did = $1`, did).
		Scan(&d.ID, &d.UAIID, &d.DID, &d.Country, &d.DisplayName, &d.IsAlternate,
			&d.CredentialID, &d.PublicJWK, &d.CredentialHash, &d.Status, &d.AppointedAt)
	if err != nil {
		return Delegate{}, classify(err)
	}
	return d, nil
}

// Delegates lists the council.
func (db *DB) Delegates(ctx context.Context) ([]Delegate, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, uai_id, did, country_code, display_name, is_alternate,
		       webauthn_credential_id, webauthn_public_key, credential_hash,
		       status::text, appointed_at
		  FROM human_delegates WHERE status = 'ACTIVE' ORDER BY country_code, did`)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []Delegate{}
	for rows.Next() {
		var d Delegate
		if err := rows.Scan(&d.ID, &d.UAIID, &d.DID, &d.Country, &d.DisplayName, &d.IsAlternate,
			&d.CredentialID, &d.PublicJWK, &d.CredentialHash, &d.Status, &d.AppointedAt); err != nil {
			return nil, classify(err)
		}
		out = append(out, d)
	}
	return out, classify(rows.Err())
}

// NewCase is a harm case being opened, with the evidence it rests on.
type NewCase struct {
	ID                    string
	AgentID               string
	OwnerID               string
	Summary               string
	HarmCategories        []string
	AffectedJurisdictions []string
	InvestigatorDID       string
	EvidenceDigest        string
	ResponseWindowEnds    *time.Time
	OpenedAt              time.Time
	Evidence              []EvidenceItem
}

// EvidenceItem is one piece of evidence, committed rather than stored.
//
// Commitment, not content: §15 keeps evidence out of anything published, and
// SaltRef points at the vault entry whose destruction crypto-shreds it. A case
// that held the content would make retention a legal problem instead of a
// storage one.
type EvidenceItem struct {
	ID            string
	CaseID        string
	Kind          string
	Commitment    string
	SaltRef       string
	VaultRef      string
	SourceEventID string
	CollectedBy   string
	Signature     string
	SignerKID     string
	CollectedAt   time.Time
}

// OpenCase writes a case and its evidence in one transaction.
//
// Atomic because a case with no evidence is an accusation with nothing behind
// it, and the evidence digest that delegates will vote on is computed from the
// items: a case whose items arrived later would put a digest in front of
// delegates that did not yet cover what they were shown.
func (db *DB) OpenCase(ctx context.Context, c NewCase) error {
	return db.InTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO harm_cases (id, agent_id, owner_id, state, summary, harm_categories,
			                        affected_jurisdictions, investigator_did, evidence_digest,
			                        response_window_ends, opened_at)
			VALUES ($1,$2,$3,'OPEN',$4,$5::harm_category[],$6,$7,$8,$9,COALESCE($10, now()))`,
			c.ID, c.AgentID, c.OwnerID, c.Summary,
			orEmptyStrings(c.HarmCategories), orEmptyStrings(c.AffectedJurisdictions),
			nullable(c.InvestigatorDID), nullable(c.EvidenceDigest), c.ResponseWindowEnds,
			nullableTime(c.OpenedAt))
		if err != nil {
			return classify(err)
		}
		for _, e := range c.Evidence {
			if _, err := tx.Exec(ctx, `
				INSERT INTO evidence_items (id, case_id, kind, commitment, salt_ref, vault_ref,
				                            source_event_id, collected_by, collected_at,
				                            signature, signer_kid)
				VALUES ($1,$2,$3::evidence_kind,$4,$5,$6,$7,$8,COALESCE($9, now()),$10,$11)`,
				e.ID, c.ID, e.Kind, e.Commitment, nullable(e.SaltRef), nullable(e.VaultRef),
				nullable(e.SourceEventID), e.CollectedBy, nullableTime(e.CollectedAt),
				e.Signature, e.SignerKID); err != nil {
				return classify(err)
			}
		}
		return nil
	})
}

// CaseEvidence returns a case's evidence commitments, oldest first.
func (db *DB) CaseEvidence(ctx context.Context, caseID string) ([]EvidenceItem, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, case_id, kind::text, commitment, coalesce(source_event_id,''),
		       collected_by, signature, signer_kid, collected_at
		  FROM evidence_items WHERE case_id = $1 AND shredded_at IS NULL
		 ORDER BY collected_at, id`, caseID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []EvidenceItem{}
	for rows.Next() {
		var e EvidenceItem
		if err := rows.Scan(&e.ID, &e.CaseID, &e.Kind, &e.Commitment, &e.SourceEventID,
			&e.CollectedBy, &e.Signature, &e.SignerKID, &e.CollectedAt); err != nil {
			return nil, classify(err)
		}
		out = append(out, e)
	}
	return out, classify(rows.Err())
}

// SetCaseState moves a case along, optionally pinning the evidence digest the
// delegates will vote on.
func (db *DB) SetCaseState(ctx context.Context, caseID, state, evidenceDigest string, at time.Time) error {
	var closedAt any
	if state == "CLOSED" {
		closedAt = at
	}
	tag, err := db.pool.Exec(ctx, `
		UPDATE harm_cases
		   SET state = $2::case_state,
		       evidence_digest = COALESCE(NULLIF($3,''), evidence_digest),
		       closed_at = $4
		 WHERE id = $1`, caseID, state, evidenceDigest, closedAt)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: case %s", ErrNotFound, caseID)
	}
	return nil
}

// NewQuarantine is a preventive order being issued.
type NewQuarantine struct {
	ID                   string
	AgentID              string
	OwnerID              string
	CaseID               string
	Category             string
	Reason               string
	PolicyVersion        string
	BundleHash           string
	InitiatingRule       string
	TriggeringSuspicions []string
	EvidenceCommitments  []string
	Suspended            []string
	Retained             []string
	OwnerRestrictions    []string
	IssuedAt             time.Time
	ReviewBy             time.Time
	ExpiresAt            time.Time
	Signature            string
	SignerKID            string
}

// IssueQuarantine writes the order and moves the agent, in one transaction.
//
// One transaction because the two halves are one act: an order with the agent
// still ACTIVE restricts nothing, and an agent moved to QUARANTINED with no
// order is a restriction with no stated reason, no review date and no expiry —
// which is the shape of a sanction rather than a precaution.
func (db *DB) IssueQuarantine(ctx context.Context, q NewQuarantine) error {
	return db.InTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO quarantine_orders (id, agent_id, owner_id, case_id, reason_category,
			                               reason_text, policy_version, bundle_hash,
			                               initiating_rule, triggering_suspicions,
			                               evidence_commitments, capabilities_suspended,
			                               capabilities_retained, owner_restrictions,
			                               issued_at, review_by, expires_at, signature, signer_kid)
			VALUES ($1,$2,$3,$4,$5::harm_category,$6,$7,$8,$9,$10,$11,$12,$13,$14,
			        COALESCE($15, now()),$16,$17,$18,$19)`,
			q.ID, q.AgentID, q.OwnerID, nullable(q.CaseID), q.Category, q.Reason,
			q.PolicyVersion, q.BundleHash, q.InitiatingRule, orEmptyStrings(q.TriggeringSuspicions),
			orEmptyStrings(q.EvidenceCommitments), orEmptyStrings(q.Suspended),
			orEmptyStrings(q.Retained), orEmptyStrings(q.OwnerRestrictions),
			nullableTime(q.IssuedAt), q.ReviewBy, q.ExpiresAt, q.Signature, q.SignerKID)
		if err != nil {
			return classify(err)
		}
		return setStatus(ctx, tx, q.AgentID, "QUARANTINED", time.Time{})
	})
}

// NewProposal opens a governance proposal for voting.
type NewProposal struct {
	ID             string
	CaseID         string
	Kind           string
	AgentID        string
	EvidenceDigest string
	PolicyVersion  string
	BundleHash     string
	Threshold      string
	OpenedAt       time.Time
	ClosesAt       time.Time
}

// OpenProposal writes a proposal already in VOTING.
//
// The threshold is snapshotted here and never read live afterwards: a quorum
// that could move under a vote already in progress is not a quorum.
func (db *DB) OpenProposal(ctx context.Context, p NewProposal) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO governance_proposals (id, case_id, kind, subject_agent_id, evidence_digest,
		                                  policy_version, bundle_hash, threshold_snapshot,
		                                  state, opened_at, closes_at)
		VALUES ($1,$2,$3::proposal_kind,$4,$5,$6,$7,$8,'VOTING',COALESCE($9, now()),$10)`,
		p.ID, p.CaseID, p.Kind, p.AgentID, p.EvidenceDigest, p.PolicyVersion,
		p.BundleHash, p.Threshold, nullableTime(p.OpenedAt), p.ClosesAt)
	return classify(err)
}

// ProposalRecord is a proposal as stored.
type ProposalRecord struct {
	ID             string
	CaseID         string
	Kind           string
	AgentID        string
	AgentDID       string
	AgentUAIID     string
	EvidenceDigest string
	PolicyVersion  string
	BundleHash     string
	Threshold      string
	State          string
	OpenedAt       time.Time
	ClosesAt       time.Time
}

// ProposalByID loads a proposal with its subject.
func (db *DB) ProposalByID(ctx context.Context, id string) (ProposalRecord, error) {
	var p ProposalRecord
	err := db.pool.QueryRow(ctx, `
		SELECT p.id, p.case_id, p.kind::text, p.subject_agent_id, a.did, a.uai_id,
		       p.evidence_digest, p.policy_version, p.bundle_hash, p.threshold_snapshot,
		       p.state::text, p.opened_at, p.closes_at
		  FROM governance_proposals p
		  JOIN agents a ON a.id = p.subject_agent_id
		 WHERE p.id = $1`, id).
		Scan(&p.ID, &p.CaseID, &p.Kind, &p.AgentID, &p.AgentDID, &p.AgentUAIID,
			&p.EvidenceDigest, &p.PolicyVersion, &p.BundleHash, &p.Threshold,
			&p.State, &p.OpenedAt, &p.ClosesAt)
	if err != nil {
		return ProposalRecord{}, classify(err)
	}
	return p, nil
}

// SetProposalState resolves a proposal.
func (db *DB) SetProposalState(ctx context.Context, id, state string, at time.Time) error {
	tag, err := db.pool.Exec(ctx, `
		UPDATE governance_proposals SET state = $2::proposal_state, resolved_at = $3
		 WHERE id = $1`, id, state, at)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: proposal %s", ErrNotFound, id)
	}
	return nil
}

// CastVote is a delegate's vote with the assertion that proves a human made it.
type CastVote struct {
	ID                 string
	ProposalID         string
	DelegateID         string
	Country            string
	Value              string
	EvidenceDigest     string
	RationaleHash      string
	VoteDigest         string
	AuthenticatorData  []byte
	ClientDataJSON     []byte
	AssertionSignature []byte
	UserVerified       bool
	CastAt             time.Time
}

// RecordVote stores a verified vote.
//
// The assertion is stored whole, not summarized. A tally is only trustworthy if
// someone else can recompute it from the statements, and a summary cannot be
// re-verified against a delegate's credential.
func (db *DB) RecordVote(ctx context.Context, v CastVote) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO votes (id, proposal_id, delegate_id, country_code, value, evidence_digest,
		                   rationale_hash, vote_digest, authenticator_data, client_data_json,
		                   assertion_signature, user_verified, cast_at)
		VALUES ($1,$2,$3,$4,$5::vote_value,$6,$7,$8,$9,$10,$11,$12,COALESCE($13, now()))`,
		v.ID, v.ProposalID, v.DelegateID, v.Country, v.Value, v.EvidenceDigest,
		nullable(v.RationaleHash), v.VoteDigest, v.AuthenticatorData, v.ClientDataJSON,
		v.AssertionSignature, v.UserVerified, nullableTime(v.CastAt))
	return classify(err)
}

// VoteRecord is a stored vote with the delegate it belongs to.
type VoteRecord struct {
	ID                 string
	ProposalID         string
	DelegateID         string
	DelegateDID        string
	Country            string
	Value              string
	EvidenceDigest     string
	VoteDigest         string
	AuthenticatorData  []byte
	ClientDataJSON     []byte
	AssertionSignature []byte
	UserVerified       bool
	CastAt             time.Time
	PublicJWK          json.RawMessage
}

// ProposalVotes returns the live votes on a proposal, with the delegate keys
// needed to re-verify each assertion.
//
// Superseded votes are excluded: a delegate who changed their mind made a new
// signed statement, and counting both would count one human twice.
func (db *DB) ProposalVotes(ctx context.Context, proposalID string) ([]VoteRecord, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT v.id, v.proposal_id, v.delegate_id, d.did, v.country_code, v.value::text,
		       v.evidence_digest, v.vote_digest, v.authenticator_data, v.client_data_json,
		       v.assertion_signature, v.user_verified, v.cast_at, d.webauthn_public_key
		  FROM votes v
		  JOIN human_delegates d ON d.id = v.delegate_id
		 WHERE v.proposal_id = $1 AND v.superseded_by IS NULL
		 ORDER BY v.id`, proposalID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	out := []VoteRecord{}
	for rows.Next() {
		var v VoteRecord
		if err := rows.Scan(&v.ID, &v.ProposalID, &v.DelegateID, &v.DelegateDID, &v.Country,
			&v.Value, &v.EvidenceDigest, &v.VoteDigest, &v.AuthenticatorData, &v.ClientDataJSON,
			&v.AssertionSignature, &v.UserVerified, &v.CastAt, &v.PublicJWK); err != nil {
			return nil, classify(err)
		}
		out = append(out, v)
	}
	return out, classify(rows.Err())
}

// NewRevocationDecision is an authorized outcome.
type NewRevocationDecision struct {
	ID              string
	ProposalID      string
	CaseID          string
	AgentID         string
	TallyYes        int
	TallyNo         int
	TallyPending    int
	Threshold       string
	EvidenceDigest  string
	GovernanceProof string
	AuthorizedAt    time.Time
}

// AuthorizeRevocation records the decision and resolves the proposal together.
func (db *DB) AuthorizeRevocation(ctx context.Context, d NewRevocationDecision) error {
	return db.InTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO revocation_decisions (id, proposal_id, case_id, subject_agent_id,
			                                  tally_yes, tally_no, tally_pending,
			                                  threshold_applied, evidence_digest,
			                                  governance_proof, authorized_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE($11, now()))`,
			d.ID, d.ProposalID, d.CaseID, d.AgentID, d.TallyYes, d.TallyNo, d.TallyPending,
			d.Threshold, d.EvidenceDigest, d.GovernanceProof, nullableTime(d.AuthorizedAt))
		if err != nil {
			return classify(err)
		}
		_, err = tx.Exec(ctx, `
			UPDATE governance_proposals SET state = 'AUTHORIZED', resolved_at = COALESCE($2, now())
			 WHERE id = $1 AND state = 'VOTING'`, d.ProposalID, nullableTime(d.AuthorizedAt))
		return classify(err)
	})
}

// RevocationDecisionRecord is a stored decision.
type RevocationDecisionRecord struct {
	ID              string
	ProposalID      string
	CaseID          string
	AgentID         string
	AgentDID        string
	AgentUAIID      string
	TallyYes        int
	TallyNo         int
	TallyPending    int
	Threshold       string
	EvidenceDigest  string
	GovernanceProof string
	AuthorizedAt    time.Time
	ExecutedAt      *time.Time
	TxHash          string
}

// RevocationDecisionByID loads a decision and whether it has been executed.
func (db *DB) RevocationDecisionByID(ctx context.Context, id string) (RevocationDecisionRecord, error) {
	var d RevocationDecisionRecord
	var executedAt *time.Time
	var txHash *string
	err := db.pool.QueryRow(ctx, `
		SELECT d.id, d.proposal_id, d.case_id, d.subject_agent_id, a.did, a.uai_id,
		       d.tally_yes, d.tally_no, d.tally_pending, d.threshold_applied,
		       d.evidence_digest, d.governance_proof, d.authorized_at,
		       r.executed_at, r.tx_hash
		  FROM revocation_decisions d
		  JOIN agents a ON a.id = d.subject_agent_id
		  LEFT JOIN revocations r ON r.decision_id = d.id
		 WHERE d.id = $1`, id).
		Scan(&d.ID, &d.ProposalID, &d.CaseID, &d.AgentID, &d.AgentDID, &d.AgentUAIID,
			&d.TallyYes, &d.TallyNo, &d.TallyPending, &d.Threshold, &d.EvidenceDigest,
			&d.GovernanceProof, &d.AuthorizedAt, &executedAt, &txHash)
	if err != nil {
		return RevocationDecisionRecord{}, classify(err)
	}
	d.ExecutedAt, d.TxHash = executedAt, deref(txHash)
	return d, nil
}

// ExecuteRevocation records the execution and moves the agent to REVOKED.
//
// One transaction, and the UNIQUE constraint on revocations.decision_id makes
// executing twice impossible rather than merely discouraged: a second execution
// would be a second on-chain event for one decision, and a reader of the chain
// would have to guess which one counted.
func (db *DB) ExecuteRevocation(ctx context.Context, id, decisionID, agentID, executorDID,
	executorSignature, governanceProof, txHash string, chainID int64, at time.Time) error {

	return db.InTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO revocations (id, decision_id, agent_id, executed_by_did, executor_signature,
			                         governance_proof, chain_id, tx_hash, executed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9, now()))`,
			id, decisionID, agentID, executorDID, executorSignature, governanceProof,
			nullableInt(chainID), nullable(txHash), nullableTime(at))
		if err != nil {
			return classify(err)
		}
		return setStatus(ctx, tx, agentID, "REVOKED", at)
	})
}

// setStatus is the shared body of a status move inside a larger transaction.
func setStatus(ctx context.Context, tx pgx.Tx, agentID, status string, at time.Time) error {
	var revokedAt any
	if status == "REVOKED" {
		if at.IsZero() {
			at = time.Now().UTC()
		}
		revokedAt = at
	}
	tag, err := tx.Exec(ctx, `
		UPDATE agents SET status = $2::agent_status, revoked_at = $3, updated_at = now()
		 WHERE id = $1`, agentID, status, revokedAt)
	if err != nil {
		return classify(err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: agent %s", ErrNotFound, agentID)
	}
	return nil
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func nullableInt(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func orEmptyStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// AgentRevocation is the decision that revoked an agent, for a reader who needs
// to check it.
type AgentRevocation struct {
	DecisionID      string
	CaseID          string
	GovernanceProof string
	TxHash          string
	ExecutedAt      time.Time
}

// RevocationForAgent returns what revoked an agent.
//
// Exposed on the public identity card, because "REVOKED" with nothing to
// recompute is a status an operator could set alone. Naming the decision turns
// it into a claim a stranger can check against the signed votes.
func (db *DB) RevocationForAgent(ctx context.Context, agentID string) (AgentRevocation, error) {
	var r AgentRevocation
	var txHash *string
	err := db.pool.QueryRow(ctx, `
		SELECT r.decision_id, d.case_id, r.governance_proof, r.tx_hash, r.executed_at
		  FROM revocations r
		  JOIN revocation_decisions d ON d.id = r.decision_id
		 WHERE r.agent_id = $1
		 ORDER BY r.executed_at DESC LIMIT 1`, agentID).
		Scan(&r.DecisionID, &r.CaseID, &r.GovernanceProof, &txHash, &r.ExecutedAt)
	if err != nil {
		return AgentRevocation{}, classify(err)
	}
	r.TxHash = deref(txHash)
	return r, nil
}
