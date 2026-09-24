package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/governance"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
	"github.com/rodmontiel/uai/pkg/webauthn"
)

// VoteBody is the body of POST /v1/governance/proposals/{id}/vote.
//
// The assertion is carried whole. A summary could not be re-verified against
// the delegate's credential later, and a tally nobody can recompute is a number
// somebody wrote down.
type VoteBody struct {
	DelegateDID   string `json:"delegate_did"`
	Value         string `json:"vote"`
	Nonce         string `json:"nonce"`
	RationaleHash string `json:"rationale_hash,omitempty"`
	Assertion     struct {
		AuthenticatorData string `json:"authenticator_data"`
		ClientDataJSON    string `json:"client_data_json"`
		Signature         string `json:"signature"`
		UserVerified      bool   `json:"user_verified"`
	} `json:"assertion"`
}

// castVote records a delegate's vote (§16.1).
//
// It is not behind proof of possession by a UAI key, and that is deliberate:
// the WebAuthn assertion IS the authentication, and it authenticates something
// stronger than a session. A delegate does not hold a software key that a
// process could use on their behalf — that is the whole of INV-005, and adding
// a second software credential in front of it would reintroduce exactly the
// thing the hardware requirement removes.
func (s *Server) castVote(w http.ResponseWriter, r *http.Request) {
	proposal, err := s.db.ProposalByID(r.Context(), r.PathValue("id"))
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	if proposal.State != "VOTING" {
		WriteProblem(w, r, http.StatusConflict, "UAI_PROPOSAL_NOT_OPEN",
			"Proposal "+proposal.ID+" is "+proposal.State+", so it is not accepting votes.")
		return
	}
	now := s.now().UTC()
	if now.After(proposal.ClosesAt) {
		WriteProblem(w, r, http.StatusConflict, "UAI_PROPOSAL_CLOSED",
			"Voting on "+proposal.ID+" closed at "+proposal.ClosesAt.UTC().Format(time.RFC3339)+".")
		return
	}
	body, ok := decode[VoteBody](w, r)
	if !ok {
		return
	}
	if body.Value != governance.VoteYes && body.Value != governance.VoteNo {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", `vote must be "YES" or "NO".`)
		return
	}
	delegate, err := s.db.DelegateByDID(r.Context(), body.DelegateDID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	if delegate.Status != "ACTIVE" {
		WriteProblem(w, r, http.StatusForbidden, "UAI_DELEGATE_NOT_ELIGIBLE",
			"Delegate "+delegate.DID+" is "+delegate.Status+".")
		return
	}

	// The digest the authenticator was supposed to sign, rebuilt here from what
	// the server knows. Taking it from the request would let a caller nominate
	// the bytes their own assertion already covers.
	statement := governance.Statement{
		CaseID: proposal.CaseID, Proposal: proposal.Kind,
		SubjectAgentDID: proposal.AgentDID, EvidenceDigest: proposal.EvidenceDigest,
		DelegateDID: delegate.DID, Value: body.Value, Nonce: body.Nonce,
	}
	digest, err := statement.Digest()
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", err.Error())
		return
	}

	assertion := webauthn.Assertion{
		AuthenticatorData: b64urlBytes(body.Assertion.AuthenticatorData),
		ClientDataJSON:    b64urlBytes(body.Assertion.ClientDataJSON),
		Signature:         b64urlBytes(body.Assertion.Signature),
	}
	pub, err := uaicrypto.PublicFromJWKBytes(delegate.PublicJWK)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL",
			"The delegate's registered credential could not be read.")
		return
	}
	if err := webauthn.Verify(pub, assertion, webauthn.Expectation{
		Challenge: digest, Origin: s.governanceOrigin, RelyingPartyID: s.governanceRPID,
	}); err != nil {
		code := "UAI_VOTE_ASSERTION_INVALID"
		if errors.Is(err, webauthn.ErrNoUserVerification) {
			// Named separately because it is the one refusal that is not a bug
			// in the caller: the ceremony happened, and it did not verify a
			// human. INV-005 says that is not a vote.
			code = "UAI_VOTE_NOT_USER_VERIFIED"
		}
		WriteProblem(w, r, http.StatusUnauthorized, code, err.Error(),
			WithRemediation("A vote is a hardware assertion over the vote digest, with user "+
				"verification. No automated process can produce one."))
		return
	}

	id, err := uaiid.NewULID()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not allocate a vote id.")
		return
	}
	err = s.db.RecordVote(r.Context(), store.CastVote{
		ID: id.String(), ProposalID: proposal.ID, DelegateID: delegate.ID,
		Country: delegate.Country, Value: body.Value,
		EvidenceDigest: proposal.EvidenceDigest, RationaleHash: body.RationaleHash,
		VoteDigest:        uaicrypto.FormatDigest(digest),
		AuthenticatorData: assertion.AuthenticatorData, ClientDataJSON: assertion.ClientDataJSON,
		AssertionSignature: assertion.Signature, UserVerified: true, CastAt: now,
		Nonce: body.Nonce,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			WriteProblem(w, r, http.StatusConflict, "UAI_ALREADY_VOTED",
				"Delegate "+delegate.DID+" has already voted on "+proposal.ID+".",
				WithRemediation("Changing a vote is a new signed statement that supersedes the "+
					"old one; nothing is modified in place."))
			return
		}
		WriteStoreError(w, r, err)
		return
	}

	tally, decisionID, err := s.tallyAndMaybeAuthorize(r.Context(), proposal, now)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	out := map[string]any{
		"vote_id": id.String(), "proposal": proposal.ID, "recorded": body.Value,
		"tally": map[string]any{
			"yes": tally.Yes, "no": tally.No, "pending": tally.Pending,
			"countries": tally.Countries, "threshold": proposal.Threshold,
		},
		"authorized": tally.Authorized,
		"reason":     tally.Why,
		"note": "The tally is recomputed from the signed assertions on every read. It is not a " +
			"counter anyone can write.",
	}
	if decisionID != "" {
		out["decision_id"] = decisionID
		out["next"] = "An authorized decision still has to be executed by an administrator, whose " +
			"only input is this decision id."
	}
	WriteJSON(w, http.StatusCreated, out)
}

// tallyAndMaybeAuthorize recomputes the outcome and, when the threshold is met,
// records the decision.
//
// Recomputed from the stored assertions on every call, and each assertion is
// re-verified against its delegate's credential before it counts. §16.3
// precondition 5 says the tally must be recomputed from signed statements; a
// stored counter would satisfy the words and none of the point.
func (s *Server) tallyAndMaybeAuthorize(ctx context.Context, proposal store.ProposalRecord,
	now time.Time) (governance.Tally, string, error) {

	votes, err := s.db.ProposalVotes(ctx, proposal.ID)
	if err != nil {
		return governance.Tally{}, "", err
	}
	counted, err := s.verifiedVotes(proposal, votes)
	if err != nil {
		return governance.Tally{}, "", err
	}
	threshold, err := governance.ParseThreshold(proposal.Threshold)
	if err != nil {
		return governance.Tally{}, "", err
	}
	threshold.MinCountries = s.minCountries
	tally, err := governance.Count(counted, proposal.EvidenceDigest, threshold)
	if err != nil {
		return governance.Tally{}, "", err
	}
	if !tally.Authorized || proposal.State != "VOTING" {
		return tally, "", nil
	}
	// The threshold is met, and the vote is not over.
	//
	// Authorizing here and closing the proposal would refuse every delegate who
	// had not voted yet — which in practice means refusing the dissent, since
	// the threshold is reached by the majority. The record would then show 4-0
	// where five delegates voted 4-1, and the minority position would have been
	// erased by arithmetic.
	//
	// A decision whose record cannot show who objected is weaker, not stronger.
	// So authorization waits for the vote to actually finish: every eligible
	// delegate has answered, or the window closed.
	finished, err := s.votingFinished(proposal, len(counted), now)
	if err != nil {
		return tally, "", err
	}
	if !finished {
		tally.Why = fmt.Sprintf("%s — waiting for the remaining delegates or for voting to close at %s",
			tally.Why, proposal.ClosesAt.UTC().Format(time.RFC3339))
		tally.Authorized = false
		return tally, "", nil
	}

	proof, err := governance.Proof(governance.ProofInput{
		CaseID: proposal.CaseID, Proposal: proposal.Kind, SubjectAgentDID: proposal.AgentDID,
		EvidenceDigest: proposal.EvidenceDigest,
		Policy: governance.Policy{Version: proposal.PolicyVersion,
			BundleHash: proposal.BundleHash, Threshold: proposal.Threshold},
		Votes: counted,
	})
	if err != nil {
		return tally, "", err
	}
	id, err := uaiid.NewULID()
	if err != nil {
		return tally, "", err
	}
	if err := s.db.AuthorizeRevocation(ctx, store.NewRevocationDecision{
		ID: id.String(), ProposalID: proposal.ID, CaseID: proposal.CaseID,
		AgentID: proposal.AgentID, TallyYes: tally.Yes, TallyNo: tally.No,
		TallyPending: tally.Pending, Threshold: proposal.Threshold,
		EvidenceDigest: proposal.EvidenceDigest, GovernanceProof: proof, AuthorizedAt: now,
	}); err != nil {
		return tally, "", err
	}
	return tally, id.String(), nil
}

// verifiedVotes re-checks every stored assertion before it is counted.
//
// A vote that no longer verifies is dropped from the tally AND reported as an
// error, not silently skipped: a stored assertion that stopped verifying means
// either the row was edited or the delegate's credential changed, and both are
// things somebody has to look at.
func (s *Server) verifiedVotes(proposal store.ProposalRecord,
	votes []store.VoteRecord) ([]governance.Vote, error) {

	out := make([]governance.Vote, 0, len(votes))
	for _, v := range votes {
		pub, err := uaicrypto.PublicFromJWKBytes(v.PublicJWK)
		if err != nil {
			return nil, fmt.Errorf("vote %s: delegate credential: %w", v.ID, err)
		}
		// The challenge is REBUILT from the statement, not read from the row.
		//
		// Verifying the assertion against the stored vote_digest proves the
		// delegate signed that digest -- it proves nothing about the value
		// stored beside it. A genuine assertion from another proposal, filed
		// here with the opposite value, would have passed that check; the
		// contract would have refused it on execution and nothing before then
		// would have. So the value is not read, it is TESTED: change it and
		// the digest changes and the signature stops verifying.
		if v.Nonce == "" {
			return nil, fmt.Errorf(
				"vote %s stores no nonce, so its digest cannot be rebuilt and its value "+
					"cannot be checked against its signature (predates migration 0007)", v.ID)
		}
		statement := governance.Statement{
			CaseID: proposal.CaseID, Proposal: proposal.Kind,
			SubjectAgentDID: proposal.AgentDID, EvidenceDigest: v.EvidenceDigest,
			DelegateDID: v.DelegateDID, Value: v.Value, Nonce: v.Nonce,
		}
		digest, err := statement.Digest()
		if err != nil {
			return nil, fmt.Errorf("vote %s: rebuilding the digest: %w", v.ID, err)
		}
		// Said separately from the signature check so the two failures do not
		// read alike: a digest that disagrees with the stored one means the row
		// was edited, and a signature that fails against a rebuilt digest means
		// the assertion never covered this statement. Both are refusals; only
		// one of them is someone rewriting the record.
		if stored := uaicrypto.FormatDigest(digest); stored != v.VoteDigest {
			return nil, fmt.Errorf(
				"vote %s does not match its own statement: stored digest %s, rebuilt %s",
				v.ID, v.VoteDigest, stored)
		}
		assertion := webauthn.Assertion{
			AuthenticatorData: v.AuthenticatorData, ClientDataJSON: v.ClientDataJSON,
			Signature: v.AssertionSignature,
		}
		if err := webauthn.Verify(pub, assertion, webauthn.Expectation{
			Challenge: digest, Origin: s.governanceOrigin, RelyingPartyID: s.governanceRPID,
		}); err != nil {
			return nil, fmt.Errorf("vote %s no longer verifies against %s: %w",
				v.ID, v.DelegateDID, err)
		}
		commitment, err := uaicrypto.Digest(uaicrypto.DomainVote, webauthn.SignedBytes(assertion))
		if err != nil {
			return nil, err
		}
		out = append(out, governance.Vote{
			VoteID: v.ID, CaseID: proposal.CaseID, Proposal: proposal.Kind,
			SubjectAgentDID: proposal.AgentDID, EvidenceDigest: v.EvidenceDigest,
			DelegateDID: v.DelegateDID, Country: v.Country, Value: v.Value,
			AssertionCommitment: uaicrypto.FormatDigest(commitment),
			CastAt:              v.CastAt.UTC().Truncate(time.Second),
		})
	}
	return out, nil
}

// getProposal returns a proposal with its recomputed tally.
func (s *Server) getProposal(w http.ResponseWriter, r *http.Request) {
	proposal, err := s.db.ProposalByID(r.Context(), r.PathValue("id"))
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	tally, _, err := s.tallyAndMaybeAuthorize(r.Context(), proposal, s.now().UTC())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"proposal_id": proposal.ID, "case_id": proposal.CaseID, "kind": proposal.Kind,
		"subject": proposal.AgentUAIID, "state": proposal.State,
		"evidence_digest": proposal.EvidenceDigest,
		"policy": map[string]any{"version": proposal.PolicyVersion,
			"bundle_hash": proposal.BundleHash, "threshold": proposal.Threshold,
			"min_countries": s.minCountries},
		"tally": map[string]any{"yes": tally.Yes, "no": tally.No, "pending": tally.Pending,
			"countries": tally.Countries},
		"authorized": tally.Authorized, "reason": tally.Why,
		"opened_at": proposal.OpenedAt.UTC(), "closes_at": proposal.ClosesAt.UTC(),
		"note": REVOCATION_NOTE,
	})
}

// REVOCATION_NOTE is the sentence most likely to be misread by whoever builds
// on this, so it is attached to everything that mentions revocation.
const REVOCATION_NOTE = "A revocation decides whether UAI participants stop honouring an " +
	"identity's credentials. It cannot stop software from running."

// getRevocationDecision returns a decision with everything needed to check it
// without us.
func (s *Server) getRevocationDecision(w http.ResponseWriter, r *http.Request) {
	decision, err := s.db.RevocationDecisionByID(r.Context(), r.PathValue("decisionId"))
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	proposal, err := s.db.ProposalByID(r.Context(), decision.ProposalID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	votes, err := s.db.ProposalVotes(r.Context(), decision.ProposalID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	counted, err := s.verifiedVotes(proposal, votes)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", err.Error())
		return
	}
	status := "AUTHORIZED"
	if decision.ExecutedAt != nil {
		status = "EXECUTED"
	}
	WriteJSON(w, http.StatusOK, governance.Decision{
		DecisionID: decision.ID, CaseID: decision.CaseID,
		SubjectAgentDID: decision.AgentDID, Proposal: proposal.Kind,
		Policy: governance.Policy{Version: proposal.PolicyVersion,
			BundleHash: proposal.BundleHash, Threshold: decision.Threshold},
		EvidenceDigest: decision.EvidenceDigest,
		Tally: governance.Tally{Yes: decision.TallyYes, No: decision.TallyNo,
			Pending: decision.TallyPending, Authorized: true},
		Votes: counted, AuthorizedAt: decision.AuthorizedAt.UTC(),
		GovernanceProof: decision.GovernanceProof, Status: status,
	})
}

// ExecuteBody is the administrator's entire input.
type ExecuteBody struct {
	DecisionID string `json:"decision_id"`
}

// executeRevocation is the one write the Global Read-only Admin may perform
// (§16.3).
//
// The administrator cannot choose the agent, the reason, the votes or any
// parameter. The only input is a decision id, and every consequence is already
// fixed by the governance proof — which is recomputed here from the signed
// assertions before anything happens, not read back from the row that claims it.
func (s *Server) executeRevocation(w http.ResponseWriter, r *http.Request) {
	adminDID, ok := agentFromPoP(r)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_REQUIRED",
			"Executing a governance decision requires a signature from the administrator.")
		return
	}
	decisionID := r.PathValue("decisionId")
	decision, err := s.db.RevocationDecisionByID(r.Context(), decisionID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	if decision.ExecutedAt != nil {
		WriteProblem(w, r, http.StatusConflict, "UAI_ALREADY_EXECUTED",
			"Decision "+decisionID+" was executed at "+
				decision.ExecutedAt.UTC().Format(time.RFC3339)+".")
		return
	}
	proposal, err := s.db.ProposalByID(r.Context(), decision.ProposalID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	votes, err := s.db.ProposalVotes(r.Context(), decision.ProposalID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	// §16.3 preconditions 3, 4, 5 and 6, in order. Each one is recomputed; none
	// is read back from a column that says it was already checked.
	counted, err := s.verifiedVotes(proposal, votes)
	if err != nil {
		WriteProblem(w, r, http.StatusForbidden, "UAI_GOVERNANCE_PROOF_INVALID", err.Error(),
			WithRemediation("A vote that no longer verifies means the record changed after the "+
				"decision. Nothing is executed on it."))
		return
	}
	rebuilt := governance.Decision{
		DecisionID: decision.ID, CaseID: decision.CaseID, SubjectAgentDID: decision.AgentDID,
		Proposal: proposal.Kind,
		Policy: governance.Policy{Version: proposal.PolicyVersion,
			BundleHash: proposal.BundleHash, Threshold: decision.Threshold},
		EvidenceDigest: decision.EvidenceDigest,
		Tally:          governance.Tally{Yes: decision.TallyYes, No: decision.TallyNo},
		Votes:          counted, GovernanceProof: decision.GovernanceProof,
	}
	if err := governance.Recompute(rebuilt); err != nil {
		WriteProblem(w, r, http.StatusForbidden, "UAI_GOVERNANCE_PROOF_INVALID", err.Error(),
			WithRemediation("The stated outcome does not follow from the votes this decision "+
				"carries. That is the only forgery this design leaves room for, and it is refused."))
		return
	}

	now := s.now().UTC()
	signature, _ := PoPParams(r)
	id, err := uaiid.NewULID()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not allocate an id.")
		return
	}
	// The on-chain step is separate and may be absent: §18.5 is explicit that a
	// ledger outage must not block a decision the delegates already made. The
	// response says whether it happened rather than implying it did.
	txHash := ""
	if s.revoker != nil {
		if hash, chainErr := s.revoker.ExecuteRevocation(r.Context(), decision.CaseID,
			decision.AgentDID, decision.GovernanceProof); chainErr == nil {
			txHash = hash
		} else {
			problemLog(r, "on-chain revocation failed", chainErr)
		}
	}
	if err := s.db.ExecuteRevocation(r.Context(), "rev-"+id.String(), decision.ID,
		decision.AgentID, adminDID, signature.KeyID, decision.GovernanceProof,
		txHash, s.chainID, now); err != nil {
		WriteStoreError(w, r, err)
		return
	}
	if err := s.db.SetCaseState(r.Context(), decision.CaseID, "CLOSED", "", now); err != nil {
		problemLog(r, "close case", err)
	}

	anchored := "NOT_ANCHORED"
	if txHash != "" {
		anchored = "ANCHORED"
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"decision_id": decision.ID, "subject": decision.AgentUAIID,
		"status": "REVOKED", "executed_at": now, "executed_by": adminDID,
		"governance_proof": decision.GovernanceProof,
		"chain":            map[string]any{"status": anchored, "tx_hash": txHash},
		// Said here, at the moment it is least convenient to say it.
		"note": REVOCATION_NOTE + " The agent's code can still run; what changed is that no " +
			"participant will accept its identity.",
	})
}

// Revoker publishes a revocation on the consortium chain.
type Revoker interface {
	ExecuteRevocation(ctx context.Context, caseID, agentDID, governanceProof string) (string, error)
}

func b64urlBytes(s string) []byte {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Standard base64 with padding is what some browsers hand back. Trying
		// both beats refusing a genuine assertion over an encoding detail.
		if padded, padErr := base64.StdEncoding.DecodeString(s); padErr == nil {
			return padded
		}
		return nil
	}
	return raw
}

var _ = json.Marshal

// votingFinished reports whether the council has finished answering.
//
// Measured against the proposal's SNAPSHOTTED threshold, not a live count of
// appointed delegates. §16 snapshots the threshold at open time so a quorum
// cannot move under a vote already in progress, and reading the council's
// current size here would reintroduce exactly that: appointing a delegate
// mid-vote would change when the vote finishes.
func (s *Server) votingFinished(proposal store.ProposalRecord, cast int, now time.Time) (bool, error) {
	if !now.Before(proposal.ClosesAt) {
		return true, nil
	}
	threshold, err := governance.ParseThreshold(proposal.Threshold)
	if err != nil {
		return false, err
	}
	return cast >= threshold.Total, nil
}
