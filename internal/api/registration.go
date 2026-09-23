package api

import (
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// ChallengeTTL is the lifetime of a registration challenge (§8.2).
const ChallengeTTL = 300 * time.Second

// RegistrationIDPrefix keeps a registration identifier from ever being mistaken
// for a UAI-ID.
//
// They share a path position -- POST /v1/agents/{rid}/prove sits next to
// GET /v1/agents/{uai_id} -- because at prove time no agent identifier exists
// yet: the ULID is minted only after both proofs verify (§8.2). Rather than let
// the ambiguity reach implementers, the two are made impossible to confuse.
const RegistrationIDPrefix = "reg_"

// RegistrationRequest is the draft an owner submits.
type RegistrationRequest struct {
	LogicalName           string   `json:"logical_name"`
	Version               string   `json:"version,omitempty"`
	AgentType             string   `json:"agent_type"`
	OwnerDID              string   `json:"owner_did"`
	OrgDID                string   `json:"org_did,omitempty"`
	Vendor                string   `json:"vendor,omitempty"`
	ModelFamily           string   `json:"model_family,omitempty"`
	ModelPinned           bool     `json:"model_pinned,omitempty"`
	Framework             string   `json:"framework,omitempty"`
	PrimaryJurisdiction   string   `json:"primary_jurisdiction,omitempty"`
	RequestedCapabilities []string `json:"requested_capabilities,omitempty"`
}

// RegistrationChallenge is the 202 response of POST /v1/agents.
type RegistrationChallenge struct {
	RegistrationID string `json:"registration_id"`
	ChallengeOwner string `json:"challenge_owner"`
	ChallengeAgent string `json:"challenge_agent"`
	ExpiresIn      int    `json:"expires_in"`
}

// ProofSubmission is one half of the two-sided ownership proof.
type ProofSubmission struct {
	Role      challenge.Role      `json:"role"`
	Challenge string              `json:"challenge"`
	Signature uaicrypto.Signature `json:"signature"`
	// AgentKeyThumbprint names the agent key this proof vouches for. The owner
	// MUST send it: without a way to name the subject, an owner signature would
	// vouch for whatever key happened to arrive next, which is not a proof of
	// anything. The agent MAY send it, and it must then match its own key.
	AgentKeyThumbprint string `json:"agent_key_thumbprint,omitempty"`
	// PublicJWK carries the agent's key, which is being introduced here and
	// cannot be looked up. It is accepted ONLY for the agent half: taking an
	// owner's key from the request body would turn "ownership is proven" into
	// "ownership is whatever the caller claimed".
	PublicJWK json.RawMessage `json:"public_jwk,omitempty"`
}

// RegisteredAgent is the identity card (§8.3).
type RegisteredAgent struct {
	UAIID              string `json:"uai_id"`
	DID                string `json:"did"`
	LogicalName        string `json:"logical_name,omitempty"`
	Status             string `json:"status"`
	AssuranceLevel     string `json:"assurance_level,omitempty"`
	IdentityCommitment string `json:"identity_commitment,omitempty"`
	PolicyVersion      string `json:"policy_version,omitempty"`
	GenesisEventHash   string `json:"genesis_event_hash,omitempty"`
}

// PendingRegistration is the 202 response to the first of the two proofs.
type PendingRegistration struct {
	RegistrationID string `json:"registration_id"`
	Status         string `json:"status"`
	Awaiting       string `json:"awaiting"`
	ExpiresIn      int    `json:"expires_in"`
}

// registerAgent opens a registration and issues the two challenges (§8.2).
//
// This is the only write path in UAI that is not behind proof of possession,
// and it cannot be otherwise: establishing the agent's key is what registration
// does. That is exactly why it mints nothing. An unanswered registration
// produces no identifier, no DID and no record a verifier can see -- the cost of
// spamming this endpoint is a row that expires in five minutes.
func (s *Server) registerAgent(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[RegistrationRequest](w, r)
	if !ok {
		return
	}
	switch {
	case strings.TrimSpace(req.LogicalName) == "":
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", "logical_name is required.")
		return
	case strings.TrimSpace(req.AgentType) == "":
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", "agent_type is required.")
		return
	case strings.TrimSpace(req.OwnerDID) == "":
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", "owner_did is required.")
		return
	}

	owner, err := s.db.OwnerByDID(r.Context(), req.OwnerDID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Deliberately the same refusal as a suspended owner. Distinguishing
			// "no such owner" from "that owner may not register" would turn this
			// endpoint into an oracle for enumerating who exists.
			WriteProblem(w, r, http.StatusForbidden, "UAI_OWNER_NOT_ELIGIBLE",
				"The owner named by owner_did cannot register agents.")
			return
		}
		WriteStoreError(w, r, err)
		return
	}
	if owner.Status != "ACTIVE" {
		WriteProblem(w, r, http.StatusForbidden, "UAI_OWNER_NOT_ELIGIBLE",
			"Owner "+owner.DID+" is "+owner.Status+" and cannot register new agents.")
		return
	}
	// §13.4: an owner restriction is narrow and forward-looking. It blocks NEW
	// registrations and must never cascade into disabling agents that already
	// exist, which is why it is checked here and nowhere near the action path.
	if len(owner.Restrictions) > 0 {
		WriteProblem(w, r, http.StatusForbidden, "UAI_OWNER_RESTRICTED",
			"Owner "+owner.DID+" is under a restriction that blocks new registrations.",
			WithRemediation("Existing agents of this owner are unaffected."))
		return
	}

	chOwner, err := challenge.New()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not issue a challenge.")
		return
	}
	// A second, independent draw. Deriving one challenge from the other would
	// let a party holding one key predict the half it does not control.
	chAgent, err := challenge.New()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not issue a challenge.")
		return
	}

	rid, err := uaiid.NewULID()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not allocate a registration.")
		return
	}
	jurisdiction := req.PrimaryJurisdiction
	if jurisdiction == "" {
		jurisdiction = owner.Jurisdiction
	}
	reg := store.Registration{
		ID: RegistrationIDPrefix + rid.String(), LogicalName: req.LogicalName,
		Version: req.Version, AgentType: req.AgentType,
		OwnerID: owner.ID, OwnerDID: owner.DID, OrganizationID: owner.OrganizationID,
		Vendor: req.Vendor, ModelFamily: req.ModelFamily, ModelPinned: req.ModelPinned,
		Framework: req.Framework, PrimaryJurisdiction: jurisdiction,
		RequestedCapabilities: req.RequestedCapabilities, PolicyVersion: s.policyVersion,
		ChallengeOwner: chOwner, ChallengeAgent: chAgent,
		ExpiresAt: s.now().Add(ChallengeTTL),
	}
	if err := s.db.OpenRegistration(r.Context(), reg); err != nil {
		WriteStoreError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, RegistrationChallenge{
		RegistrationID: reg.ID, ChallengeOwner: chOwner, ChallengeAgent: chAgent,
		ExpiresIn: int(ChallengeTTL.Seconds()),
	})
}

// prove accepts one half of the ownership proof, and mints the identity once
// both halves agree (§8.2).
func (s *Server) prove(w http.ResponseWriter, r *http.Request) {
	rid := r.PathValue("id")
	if !strings.HasPrefix(rid, RegistrationIDPrefix) {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_MALFORMED_IDENTIFIER",
			"A proof is submitted against a registration identifier ("+RegistrationIDPrefix+"…), not a UAI-ID.",
			WithRemediation("No UAI-ID exists until both proofs verify; use the registration_id from the 202 response."))
		return
	}
	sub, ok := decode[ProofSubmission](w, r)
	if !ok {
		return
	}
	if !sub.Role.Valid() {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", `role must be "owner" or "agent".`)
		return
	}

	reg, err := s.db.RegistrationByID(r.Context(), rid)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	now := s.now()
	if reg.Minted() {
		WriteProblem(w, r, http.StatusConflict, "UAI_REGISTRATION_CLOSED",
			"Registration "+rid+" already minted an identity.")
		return
	}
	if !now.Before(reg.ExpiresAt) {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_CHALLENGE_INVALID",
			"The challenge for registration "+rid+" expired.",
			WithRemediation("Open a new registration; challenges live "+ChallengeTTL.String()+"."))
		return
	}

	// The expected challenge is chosen by role and compared in constant time.
	// The challenge is not a secret -- both halves are handed to whoever opens
	// the registration -- but a comparison that leaks position is still a free
	// gift to anyone probing, and the cost of not making it is zero.
	expected := reg.ChallengeOwner
	if sub.Role == challenge.RoleAgent {
		expected = reg.ChallengeAgent
	}
	if subtle.ConstantTimeCompare([]byte(sub.Challenge), []byte(expected)) != 1 {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_CHALLENGE_INVALID",
			"The submitted challenge is not the one issued for the "+string(sub.Role)+" half.")
		return
	}

	thumbprint, pub, ok := s.proofKey(w, r, reg, sub, now)
	if !ok {
		return
	}

	// The statement is rebuilt from server state, never echoed from the body.
	// If the payload came from the request, a caller could sign one thing and
	// have the registry record another.
	stmt := challenge.Ownership{
		Challenge: expected, RegistrationID: reg.ID, Role: sub.Role,
		AgentKeyThumbprint: thumbprint, OwnerDID: reg.OwnerDID,
	}
	if err := challenge.Verify(pub, stmt, sub.Signature); err != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_PROOF_INVALID", err.Error(),
			WithRemediation("Sign the canonical statement under the "+string(uaicrypto.DomainChallenge)+" domain."))
		return
	}

	proof := store.Proof{Thumbprint: thumbprint, At: now}
	if proof.Signature, err = json.Marshal(sub.Signature); err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not record the proof.")
		return
	}
	if sub.Role == challenge.RoleOwner {
		proof.SignerKID = sub.Signature.KID
		reg, err = s.db.RecordOwnerProof(r.Context(), rid, proof)
	} else {
		proof.PublicJWK = sub.PublicJWK
		reg, err = s.db.RecordAgentProof(r.Context(), rid, proof)
	}
	if err != nil {
		writeRegistrationError(w, r, err)
		return
	}

	if !reg.Complete() {
		awaiting := string(challenge.RoleAgent)
		if sub.Role == challenge.RoleAgent {
			awaiting = string(challenge.RoleOwner)
		}
		WriteJSON(w, http.StatusAccepted, PendingRegistration{
			RegistrationID: reg.ID, Status: "AWAITING_PROOF", Awaiting: awaiting,
			ExpiresIn: int(time.Until(reg.ExpiresAt).Seconds()),
		})
		return
	}
	s.mint(w, r, reg, now)
}

// proofKey resolves the key a proof must verify against, and the thumbprint the
// proof names.
//
// The two halves resolve differently, and that asymmetry is the whole security
// argument. The agent's key arrives in the submission because it is being
// introduced; the owner's key is read from the registry, because an owner key
// taken from the request body would let anyone claim to be any owner.
func (s *Server) proofKey(w http.ResponseWriter, r *http.Request, reg store.Registration,
	sub ProofSubmission, now time.Time) (thumbprint string, pub crypto.PublicKey, ok bool) {

	if sub.Role == challenge.RoleAgent {
		if len(sub.PublicJWK) == 0 {
			WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
				"The agent half must carry public_jwk: UAI never generates an agent's key, so it has to be introduced here.")
			return "", nil, false
		}
		jwk, err := uaicrypto.ParseJWK(sub.PublicJWK)
		if err != nil {
			WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", err.Error())
			return "", nil, false
		}
		tp, err := jwk.ThumbprintString()
		if err != nil {
			WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", err.Error())
			return "", nil, false
		}
		// A thumbprint sent alongside the key must agree with it. Silently
		// preferring one would let a submission name a key it did not carry.
		if sub.AgentKeyThumbprint != "" && sub.AgentKeyThumbprint != tp {
			WriteProblem(w, r, http.StatusBadRequest, "UAI_PROOF_MISMATCH",
				"agent_key_thumbprint does not match the submitted public_jwk.")
			return "", nil, false
		}
		key, err := jwk.Public()
		if err != nil {
			WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", err.Error())
			return "", nil, false
		}
		return tp, key, true
	}

	if sub.PublicJWK != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"The owner half must not carry public_jwk. An owner proves control of a key UAI already holds; a key supplied here would prove nothing.",
			WithRemediation("Reference the owner's registered key through signature.kid."))
		return "", nil, false
	}
	if sub.AgentKeyThumbprint == "" {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"The owner half must carry agent_key_thumbprint: an owner signature that does not name the agent key vouches for nothing.")
		return "", nil, false
	}
	key, err := s.resolver.ResolveOwner(r.Context(), store.Owner{ID: reg.OwnerID, DID: reg.OwnerDID},
		sub.Signature.KID, now)
	if err != nil {
		WritePoPError(w, r, err)
		return "", nil, false
	}
	return sub.AgentKeyThumbprint, key, true
}

// mint creates the identity once both proofs have verified (§8.2, §8.4).
func (s *Server) mint(w http.ResponseWriter, r *http.Request, reg store.Registration, now time.Time) {
	id, err := uaiid.New(uaiid.EntityAgent)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not mint an identifier.")
		return
	}

	// The registration record of §8.3: what the transparency log commits to and
	// what the chain's genesis hash is taken over.
	record := map[string]any{
		"uai_id": id.String(), "did": id.DID(), "logical_name": reg.LogicalName,
		"version": reg.Version, "agent_type": reg.AgentType, "owner_did": reg.OwnerDID,
		"agent_key_thumbprint": reg.AgentKeyThumbprint,
		"primary_jurisdiction": reg.PrimaryJurisdiction,
		"policy_version":       reg.PolicyVersion, "status": "REGISTERED",
		"registered_at": now.UTC().Format(time.RFC3339),
	}
	canonical, err := uaicrypto.Canonicalize(record)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not canonicalize the record.")
		return
	}
	genesis, err := uaicrypto.Digest(uaicrypto.DomainRegistration, canonical)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", err.Error())
		return
	}
	// Salted, because this commitment is what goes on a ledger other parties can
	// read. An unsalted hash of a small, guessable record is not a commitment,
	// it is an index (project rule 5).
	salt, err := uaicrypto.Salt()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", err.Error())
		return
	}
	commitment, err := uaicrypto.Commit(salt, canonical)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", err.Error())
		return
	}

	alg := string(uaicrypto.AlgEdDSA)
	if jwk, err := uaicrypto.ParseJWK(reg.AgentPublicJWK); err == nil && jwk.Kty == "EC" {
		if jwk.Crv == "P-384" {
			alg = string(uaicrypto.AlgES384)
		} else {
			alg = string(uaicrypto.AlgES256)
		}
	}

	agent := store.Agent{
		ID: "agt-" + id.ULID().String(), UAIID: id.String(), DID: id.DID(),
		OwnerID: reg.OwnerID, OrganizationID: reg.OrganizationID,
		LogicalName: reg.LogicalName, Version: reg.Version, AgentType: reg.AgentType,
		Vendor: reg.Vendor, ModelFamily: reg.ModelFamily, ModelPinned: reg.ModelPinned,
		Framework: reg.Framework, PrimaryJurisdiction: reg.PrimaryJurisdiction,
		// §8.4: registration yields REGISTERED, never VERIFIED. Promotion needs
		// the credential chain to validate, and ACTIVE additionally needs a
		// runtime binding. Collapsing the three would make the distinction a
		// relying party reads off /verify meaningless.
		AssuranceLevel: "UAI-AL0", Status: "REGISTERED",
		IdentityCommitment: uaicrypto.FormatDigest(commitment), IdentityCommitmentSalt: salt,
		PolicyVersion: reg.PolicyVersion, GenesisEventHash: uaicrypto.FormatDigest(genesis),
	}
	key := store.KeyRecord{
		ID: "key-" + id.ULID().String(), KeyID: "key-1", Alg: alg,
		PublicJWK: reg.AgentPublicJWK, Protection: "SOFTWARE", ValidFrom: now,
	}
	if err := s.db.MintAgent(r.Context(), reg.ID, agent, key, now); err != nil {
		writeRegistrationError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, RegisteredAgent{
		UAIID: agent.UAIID, DID: agent.DID, LogicalName: agent.LogicalName,
		Status: agent.Status, AssuranceLevel: agent.AssuranceLevel,
		IdentityCommitment: agent.IdentityCommitment, PolicyVersion: agent.PolicyVersion,
		GenesisEventHash: agent.GenesisEventHash,
	})
}

// writeRegistrationError maps the registration sentinels to §8.5.
func writeRegistrationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrProofMismatch):
		WriteProblem(w, r, http.StatusBadRequest, "UAI_PROOF_MISMATCH", err.Error(),
			WithRemediation("Both halves must name the same agent key and the same owner."))
	case errors.Is(err, store.ErrRegistrationExpired):
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_CHALLENGE_INVALID", err.Error())
	case errors.Is(err, store.ErrAlreadyProved):
		WriteProblem(w, r, http.StatusConflict, "UAI_PROOF_FINAL", err.Error(),
			WithRemediation("A submitted proof cannot be replaced; open a new registration."))
	case errors.Is(err, store.ErrRegistrationClosed):
		WriteProblem(w, r, http.StatusConflict, "UAI_REGISTRATION_CLOSED", err.Error())
	default:
		WriteStoreError(w, r, err)
	}
}
