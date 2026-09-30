package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/credential"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// Credential validity windows from §6.4.
const (
	// IdentityCredentialTTL is 12 months. Identity credentials expire so that a
	// verifier is periodically forced to re-check rather than trusting a
	// document issued years ago and never looked at since.
	IdentityCredentialTTL = 365 * 24 * time.Hour
)

// issueRegistrationCredentials builds the two credentials §8.2 issues with an
// identity: what the agent is, and who answers for it.
//
// The ownership credential embeds the two registration signatures verbatim.
// That is what makes §6.4.1's promise real: a relying party validates ownership
// from the document alone. Our own signature on it attests only that UAI saw the
// exchange and minted this identifier -- the ownership claim itself does not
// rest on trusting us.
func (s *Server) issueRegistrationCredentials(reg store.Registration, agent store.Agent,
	assuranceLevel string, id uaiid.ID, orgDID string, at time.Time) ([]store.Credential, error) {

	if s.issuer == nil {
		return nil, fmt.Errorf("api: no credential issuer key configured")
	}
	identityUntil := at.Add(IdentityCredentialTTL)

	identity, err := credential.New(credential.TypeIdentity, credentialURN(), s.issuerDID,
		credential.IdentitySubject{
			ID: agent.DID, Name: agent.LogicalName, Version: agent.Version,
			AgentType: agent.AgentType, Vendor: agent.Vendor, ModelFamily: agent.ModelFamily,
			ModelPinned: agent.ModelPinned, Framework: agent.Framework,
			PrimaryJurisdiction: agent.PrimaryJurisdiction, AssuranceLevel: assuranceLevel,
			AgentKeyThumbprint: reg.AgentKeyThumbprint,
		}, at, &identityUntil)
	if err != nil {
		return nil, err
	}

	ownerSig, agentSig, err := proofSignatures(reg)
	if err != nil {
		return nil, err
	}
	// No validUntil: ownership holds "until unbound" (§6.4). Putting an expiry
	// on it would mean an agent silently loses its owner on a date nobody chose.
	ownership, err := credential.New(credential.TypeOwnership, credentialURN(), s.issuerDID,
		credential.OwnershipSubject{
			ID: agent.DID, OwnerDID: reg.OwnerDID, OrgDID: orgDID, EffectiveFrom: at,
			BindingProof: credential.BindingProof{
				RegistrationID: reg.ID, AgentKeyThumbprint: reg.AgentKeyThumbprint,
				AgentPublicKeyJwk: reg.AgentPublicJWK, OwnerKeyID: reg.OwnerProofKID,
				OwnerProof: credential.ProofHalf{Challenge: reg.ChallengeOwner, Signature: ownerSig},
				AgentProof: credential.ProofHalf{Challenge: reg.ChallengeAgent, Signature: agentSig},
			},
		}, at, nil)
	if err != nil {
		return nil, err
	}

	out := make([]store.Credential, 0, 2)
	for _, c := range []credential.Credential{identity, ownership} {
		signed, err := credential.Issue(s.issuer, c, at)
		if err != nil {
			return nil, err
		}
		hash, err := signed.Hash()
		if err != nil {
			return nil, err
		}
		doc, err := json.Marshal(signed)
		if err != nil {
			return nil, err
		}
		row := store.Credential{
			ID:   "cred-" + id.ULID().String() + "-" + signed.Type[1],
			Type: signed.Type[1], SubjectDID: agent.DID, IssuerDID: s.issuerDID,
			AgentID: agent.ID, OwnerID: agent.OwnerID, OrganizationID: agent.OrganizationID,
			CredentialHash: hash, Document: doc, ValidFrom: signed.ValidFrom,
			ValidUntil: signed.ValidUntil,
		}
		out = append(out, row)
	}
	return out, nil
}

// proofSignatures recovers the two registration signatures as stored.
func proofSignatures(reg store.Registration) (owner, agent uaicrypto.Signature, err error) {
	if err = json.Unmarshal(reg.OwnerProofSig, &owner); err != nil {
		return owner, agent, fmt.Errorf("api: owner proof: %w", err)
	}
	if err = json.Unmarshal(reg.AgentProofSig, &agent); err != nil {
		return owner, agent, fmt.Errorf("api: agent proof: %w", err)
	}
	return owner, agent, nil
}

func credentialURN() string {
	id, err := uaiid.NewULID()
	if err != nil {
		return ""
	}
	return "urn:uai:credential:" + id.String()
}

// AgentCredentials is the response of GET /v1/agents/{id}/credentials.
type AgentCredentials struct {
	Credentials []json.RawMessage `json:"credentials"`
}

// getCredentials returns an agent's credential set.
//
// The stored documents are returned verbatim. Re-serializing them here would
// produce different bytes than the issuer signed, and every proof would fail
// for reasons that look like a key problem.
func (s *Server) getCredentials(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUAIID(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	agent, err := s.db.AgentByUAIID(r.Context(), id.String())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	rows, err := s.db.CredentialsForAgent(r.Context(), agent.ID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	out := AgentCredentials{Credentials: make([]json.RawMessage, 0, len(rows))}
	for _, row := range rows {
		out.Credentials = append(out.Credentials, row.Document)
	}
	WriteJSON(w, http.StatusOK, out)
}
