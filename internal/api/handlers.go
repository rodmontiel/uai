package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/internal/translog"
	"github.com/rodmontiel/uai/pkg/assurance"
	"github.com/rodmontiel/uai/pkg/attest"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// attest records a signed action attestation.
//
// The order of checks is what makes the record trustworthy:
//
//  1. Proof of possession established the signer (middleware).
//  2. The attestation must declare that same identity. An attestation naming one
//     agent and signed by another is attribution by string comparison.
//  3. The attestation's own signature is verified against the key that was valid
//     at the attestation's time, not the current key.
//  4. The agent's status is checked, so a revoked identity cannot keep writing.
//  5. Only then is the event appended, atomically, at the chain head.
func (s *Server) attest(w http.ResponseWriter, r *http.Request) {
	signerDID, ok := agentFromPoP(r)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_POP_REQUIRED",
			"No verified signature is attached to this request.")
		return
	}
	a, ok := attestationFromBody(w, r)
	if !ok {
		return
	}
	if a.AgentDID != signerDID {
		WriteProblem(w, r, http.StatusForbidden, "UAI_IDENTITY_MISMATCH",
			"The attestation declares "+a.AgentDID+" but the request was signed by "+signerDID+".",
			WithRemediation("An agent may only attest its own actions."))
		return
	}

	params, _ := PoPParams(r)
	at := time.Unix(params.Created, 0)
	if params.Created == 0 {
		at = s.now()
	}
	pub, err := s.resolver.Resolve(a.Signature.KID, at)
	if err != nil {
		WritePoPError(w, r, err)
		return
	}
	if err := attest.Verify(pub, a); err != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_ATTESTATION_SIGNATURE_INVALID", err.Error())
		return
	}

	agent, err := s.db.AgentByDID(r.Context(), a.AgentDID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	if requireActive(w, r, agent) {
		return
	}

	eventHash, err := a.Hash()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "The event hash could not be computed.")
		return
	}
	payload, err := json.Marshal(a)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "The attestation could not be stored.")
		return
	}

	ev := store.ActionEvent{
		ID: a.EventID, AgentID: agent.ID, OwnerID: agent.OwnerID,
		DecisionID:          "",
		Sequence:            a.Sequence,
		ActionType:          a.Action.Type,
		Resource:            a.Action.Resource,
		Capability:          a.Action.Capability,
		Risk:                a.Action.RiskClass,
		Purpose:             a.Purpose,
		JurisdictionOrigin:  a.Jurisdiction.Origin,
		JurisdictionTargets: a.Jurisdiction.Targets,
		CrossBorder:         a.Jurisdiction.CrossBorder,
		JurisdictionBasis:   a.Jurisdiction.Basis,
		InputCommitment:     a.InputCommitment,
		OutputCommitment:    a.OutputCommitment,
		Outcome:             string(a.Outcome),
		PreviousEventHash:   a.PreviousEventHash,
		EventHash:           eventHash,
		AssertedAt:          a.Timestamp.Time,
	}
	if a.Passport != nil {
		ev.PassportRequired = a.Passport.Required
	}
	att := store.Attestation{
		EventID: a.EventID, AgentID: agent.ID, Payload: payload,
		Alg: string(a.Signature.Alg), Signature: a.Signature.Value,
		SignerKID: a.Signature.KID, Nonce: a.Nonce,
	}

	if err := s.db.AppendAction(r.Context(), ev, att); err != nil {
		WriteStoreError(w, r, err)
		return
	}

	logTime := s.now().UTC()

	// Register the signed statement in the transparency log and hand back the
	// receipt. It is issued AFTER the append, because a receipt for an event
	// the chain rejected would be evidence of something that did not happen.
	//
	// A log failure does not fail the attestation: §10.5 is explicit that a log
	// outage must not force unattested execution. The action is already signed
	// and chained; what is missing is third-party evidence, and the response
	// says so instead of pretending.
	var rcpt any
	transparency := "UNLOGGED"
	if s.translog != nil {
		// §18.1: leaf = SHA-256(0x00 || jcs(signed_statement)). Canonical bytes,
		// not the bytes that happened to arrive. Hashing the wire form would
		// make the leaf depend on key order and whitespace, so a verifier who
		// re-serialized the statement -- which is what any verifier does -- would
		// compute a different leaf and conclude the receipt was forged.
		signed, err := uaicrypto.Canonicalize(a)
		if err == nil {
			if got, logErr := s.translog.Append(r.Context(), signed,
				translog.KindAttestation, a.EventID, logTime); logErr == nil {
				rcpt = got
				transparency = "LOGGED"
			} else {
				problemLog(r, "transparency log append failed", logErr)
				transparency = "LOG_UNAVAILABLE"
			}
		}
	}

	WriteJSON(w, http.StatusCreated, map[string]any{
		"event_id":     a.EventID,
		"event_hash":   eventHash,
		"transparency": transparency,
		"receipt":      rcpt,
		"sequence":     ev.Sequence,
		// The log time is recorded alongside the agent's self-asserted
		// timestamp. The asserted value is untrusted input; the log's ordering
		// is the authority, and a large divergence is itself a signal.
		"log_time":     logTime.Format(time.RFC3339Nano),
		"asserted_at":  a.Timestamp.UTC().Format(time.RFC3339Nano),
		"clock_skew_s": int64(logTime.Sub(a.Timestamp.Time).Seconds()),
	})
}

// getAgent returns the Universal Agent Identity Card.
func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUAIID(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	agent, err := s.db.AgentByUAIID(r.Context(), id.String())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	// Derived, never the stored column. The identity card is what a relying
	// party reads about an identity, so it is the last place that may report a
	// level nobody recomputed.
	card := identityCard(agent, s.assuranceFor(r.Context(), agent.ID, s.now()))
	// A revoked identity names the decision that revoked it. Without this, an
	// independent verifier reading REVOKED has nothing to check: "revoked" with
	// no decision to recompute is exactly the state an operator acting alone
	// would produce, and it must not be indistinguishable from a governance
	// outcome (§16.3).
	if agent.Status == "REVOKED" {
		if rev, err := s.db.RevocationForAgent(r.Context(), agent.ID); err == nil {
			card["revocation"] = map[string]any{
				"decision_id":      rev.DecisionID,
				"case_id":          rev.CaseID,
				"governance_proof": rev.GovernanceProof,
				"executed_at":      rev.ExecutedAt.UTC().Format(time.RFC3339),
				"tx_hash":          rev.TxHash,
				"note": "Recompute it: GET /v1/revocations/" + rev.DecisionID + " carries the " +
					"signed votes, and the tally and proof rebuild from them.",
			}
		}
	}
	WriteJSON(w, http.StatusOK, card)
}

// getEvents returns an agent's event chain.
func (s *Server) getEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUAIID(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	agent, err := s.db.AgentByUAIID(r.Context(), id.String())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.db.Chain(r.Context(), agent.ID, limit)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	head, err := s.db.ChainHead(r.Context(), agent.ID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		out = append(out, map[string]any{
			"event_id":            ev.ID,
			"sequence":            ev.Sequence,
			"action_type":         ev.ActionType,
			"outcome":             ev.Outcome,
			"previous_event_hash": ev.PreviousEventHash,
			"event_hash":          ev.EventHash,
			"asserted_at":         ev.AssertedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"agent":  agent.UAIID,
		"events": out,
		"head":   ChainHead{Hash: head.Hash, Sequence: head.Sequence},
	})
}

// getAction returns one attestation.
func (s *Server) getAction(w http.ResponseWriter, r *http.Request) {
	ev, att, err := s.db.ActionByID(r.Context(), r.PathValue("eventId"))
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	out := map[string]any{
		"event_id":            ev.ID,
		"sequence":            ev.Sequence,
		"event_hash":          ev.EventHash,
		"previous_event_hash": ev.PreviousEventHash,
		"attestation":         json.RawMessage(att.Payload),
	}
	// The receipt travels with the statement, always. §18.1's promise is that a
	// party holding both needs nothing from us; serving them from two places
	// would make a verifier fetch twice and, more to the point, would let one
	// be available when the other is not.
	if s.translog != nil {
		if r, err := s.db.ReceiptBySubject(r.Context(), s.translog.Origin(),
			translog.KindAttestation, ev.ID); err == nil {
			out["receipt"] = map[string]any{
				"log_origin": r.Origin, "log_index": r.LogIndex, "leaf_hash": r.LeafHash,
				"checkpoint_size": r.CheckpointSize, "checkpoint_root": r.CheckpointRoot,
				"inclusion_proof": r.InclusionProof, "log_signature": r.LogSignature,
				"witness_signatures": r.WitnessSignatures, "issued_at": r.IssuedAt.UTC(),
			}
		} else {
			// Said rather than omitted. A missing key would read as "no receipt
			// was asked for"; this says the action is recorded and unlogged,
			// which is a different and checkable fact.
			out["transparency"] = "UNLOGGED"
		}
	}
	WriteJSON(w, http.StatusOK, out)
}

// verify is the universal, unauthenticated verification endpoint.
//
// It always returns 200 with an explicit status, including for an identifier it
// has never seen. Reporting "not found" would invite the reading that silence
// means something; it does not.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("uaiId")
	asOf := s.now().UTC().Format(time.RFC3339)

	id, err := parseUAIIDQuiet(raw)
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{
			"identity": raw, "verified": false, "status": "UAI_UNVERIFIED",
			"quarantined": false, "revoked": false, "as_of": asOf,
			"note": "This identifier is not a well-formed UAI-ID. This is not an assertion that any agent is malicious.",
		})
		return
	}

	agent, err := s.db.AgentByUAIID(r.Context(), id.String())
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{
			"identity": id.String(), "verified": false, "status": "UAI_UNVERIFIED",
			"quarantined": false, "revoked": false, "as_of": asOf,
			"note": "No verifiable UAI identity exists for this identifier; this is not an assertion that the agent is malicious.",
		})
		return
	}

	revoked := agent.Status == "REVOKED"
	quarantined := agent.Status == "QUARANTINED"
	status := "UAI_REGISTERED"
	switch {
	case revoked:
		status = "UAI_REVOKED"
	case quarantined:
		status = "UAI_QUARANTINED"
	case agent.Status == "ACTIVE" || agent.Status == "VERIFIED":
		status = "UAI_VERIFIED"
	}
	// Derived from evidence on every read, not read from the column written at
	// registration (§6.8). A relying party gets the level AND the dimension
	// holding it there, because a bare UAI-AL0 is indistinguishable from a
	// misconfiguration while "limited by owner verification" says what would
	// have to change.
	al := s.assuranceFor(r.Context(), agent.ID, s.now())
	w.Header().Set("Cache-Control", "public, max-age=60")
	out := map[string]any{
		"identity":             agent.UAIID,
		"did":                  agent.DID,
		"verified":             status == "UAI_VERIFIED",
		"status":               status,
		"assurance_level":      al.Level.String(),
		"quarantined":          quarantined,
		"revoked":              revoked,
		"primary_jurisdiction": agent.PrimaryJurisdiction,
		"policy_version":       agent.PolicyVersion,
		"as_of":                asOf,
		"cache_max_age":        60,
	}
	if al.LimitedBy != "" {
		out["assurance_limited_by"] = string(al.LimitedBy)
		out["assurance_detail"] = al.Detail
	}
	WriteJSON(w, http.StatusOK, out)
}

func identityCard(a store.Agent, al assurance.Result) map[string]any {
	card := map[string]any{
		"uai_id":               a.UAIID,
		"did":                  a.DID,
		"logical_name":         a.LogicalName,
		"version":              a.Version,
		"agent_type":           a.AgentType,
		"status":               a.Status,
		"assurance_level":      al.Level.String(),
		"primary_jurisdiction": a.PrimaryJurisdiction,
		"identity_commitment":  a.IdentityCommitment,
		"policy_version":       a.PolicyVersion,
		"registered_at":        a.RegisteredAt.UTC().Format(time.RFC3339),
	}
	if a.Vendor != "" {
		card["vendor"] = a.Vendor
	}
	if a.ModelFamily != "" {
		card["model_family"] = a.ModelFamily
		card["model_pinned"] = a.ModelPinned
	}
	if a.RevokedAt != nil {
		card["revoked_at"] = a.RevokedAt.UTC().Format(time.RFC3339)
	}
	return card
}
