package uai

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// Verification is the answer of the public verify endpoint.
//
// Verified is false for an identifier UAI has never seen, and that is not an
// accusation. The Note field carries the sentence that says so, and callers
// that render this should render it: "we have no record" and "we have a bad
// record" are different statements, and collapsing them defames whoever is
// simply not registered.
type Verification struct {
	Identity            string `json:"identity"`
	DID                 string `json:"did,omitempty"`
	Verified            bool   `json:"verified"`
	Status              string `json:"status"`
	AssuranceLevel      string `json:"assurance_level,omitempty"`
	Quarantined         bool   `json:"quarantined"`
	Revoked             bool   `json:"revoked"`
	PrimaryJurisdiction string `json:"primary_jurisdiction,omitempty"`
	PolicyVersion       string `json:"policy_version,omitempty"`
	AsOf                string `json:"as_of"`
	Note                string `json:"note,omitempty"`
}

// Verify checks any UAI-ID. It needs no signature and no account: §17 requires
// verification to survive being linked from a public page.
func (c *Client) Verify(ctx context.Context, uaiID string) (Verification, error) {
	var v Verification
	err := c.get(ctx, "/v1/verify/"+uaiID, &v)
	return v, err
}

// IdentityCard is the passport-style summary of an identity.
type IdentityCard struct {
	UAIID               string `json:"uai_id"`
	DID                 string `json:"did"`
	LogicalName         string `json:"logical_name"`
	Version             string `json:"version"`
	AgentType           string `json:"agent_type"`
	Status              string `json:"status"`
	AssuranceLevel      string `json:"assurance_level"`
	PrimaryJurisdiction string `json:"primary_jurisdiction"`
	PolicyVersion       string `json:"policy_version"`
	RegisteredAt        string `json:"registered_at"`
	Vendor              string `json:"vendor,omitempty"`
	ModelFamily         string `json:"model_family,omitempty"`
	ModelPinned         bool   `json:"model_pinned,omitempty"`
	RevokedAt           string `json:"revoked_at,omitempty"`
}

// Status returns this client's own identity card.
func (c *Client) Status(ctx context.Context) (IdentityCard, error) {
	return c.Agent(ctx, c.uaiID)
}

// Agent returns any agent's identity card.
func (c *Client) Agent(ctx context.Context, uaiID string) (IdentityCard, error) {
	var card IdentityCard
	err := c.get(ctx, "/v1/agents/"+uaiID, &card)
	return card, err
}

// ChainEvent is one entry of an agent's event chain.
type ChainEvent struct {
	EventID           string `json:"event_id"`
	Sequence          int64  `json:"sequence"`
	ActionType        string `json:"action_type"`
	Outcome           string `json:"outcome"`
	PreviousEventHash string `json:"previous_event_hash"`
	EventHash         string `json:"event_hash"`
	AssertedAt        string `json:"asserted_at"`
}

// Events returns an agent's chain, newest last.
func (c *Client) Events(ctx context.Context, uaiID string, limit int) ([]ChainEvent, Head, error) {
	var resp struct {
		Events []ChainEvent `json:"events"`
		Head   Head         `json:"head"`
	}
	path := "/v1/agents/" + uaiID + "/events"
	if limit > 0 {
		path += "?limit=" + itoa(limit)
	}
	if err := c.get(ctx, path, &resp); err != nil {
		return nil, Head{}, err
	}
	return resp.Events, resp.Head, nil
}

// Credentials returns the credentials issued to an agent.
//
// They are returned whole, with their proofs, because §6.4.1 requires a relying
// party to validate one from the document alone. A method that returned a
// summary would quietly reintroduce the dependency on asking us.
func (c *Client) Credentials(ctx context.Context, uaiID string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.get(ctx, "/v1/agents/"+uaiID+"/credentials", &raw)
	return raw, err
}

// CapabilityRequest is the receipt for a capability an agent asked for.
//
// Granted is present and always false on creation. It is in the struct rather
// than absent from it so that a caller reading this type sees the answer to the
// question they are about to ask.
type CapabilityRequest struct {
	RequestID   string    `json:"request_id"`
	Capability  string    `json:"capability"`
	State       string    `json:"state"`
	Granted     bool      `json:"granted"`
	RequestedAt time.Time `json:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Note        string    `json:"note"`
}

// RequestCapability asks the owner for a capability the agent does not hold.
//
// It returns a pending request. Nothing in this SDK, this API or the database
// turns one into a grant: approval is an act by the owner, out of band, and
// there is no argument here that shortens that path (§22.9, T-11/T-13).
func (c *Client) RequestCapability(ctx context.Context, capability, justification, purpose string) (CapabilityRequest, error) {
	var out CapabilityRequest
	err := c.post(ctx, "/v1/capability-requests", uaicrypto.DomainCapabilityRequest,
		map[string]any{
			"capability": capability, "justification": justification, "purpose": purpose,
		}, &out)
	return out, err
}

// SuspicionReport is the HarmSuspicion of
// spec/schemas/harm-suspicion.schema.json.
//
// The field names are the schema's, not ones chosen here: a third party
// implementing against the committed schema and a caller using this SDK must
// produce the same document, or the two are not the same protocol.
type SuspicionReport struct {
	SuspicionID string `json:"suspicion_id"`
	ReportedAt  string `json:"reported_at"`
	Reporter    struct {
		DID            string `json:"did"`
		Type           string `json:"type"`
		CredentialHash string `json:"credential_hash,omitempty"`
	} `json:"reporter"`
	Subject struct {
		AgentDID string `json:"agent_did"`
		OwnerDID string `json:"owner_did"`
	} `json:"subject"`
	RelatedEvents  []string       `json:"related_events,omitempty"`
	HarmCategories []HarmCategory `json:"harm_categories"`
	Guardrail      struct {
		Rule          string `json:"rule,omitempty"`
		PolicyVersion string `json:"policy_version,omitempty"`
		BundleHash    string `json:"bundle_hash,omitempty"`
	} `json:"guardrail,omitempty"`
	EvidenceCommitments   []string            `json:"evidence_commitments,omitempty"`
	Confidence            float64             `json:"confidence"`
	AffectedJurisdictions []string            `json:"affected_jurisdictions,omitempty"`
	Signature             uaicrypto.Signature `json:"signature"`
}

// HarmCategory is one category and its severity (0-4).
//
// There is deliberately no field for a finding. §14 is explicit that a
// suspicion is a claim warranting examination, never guilt, and a struct with
// nowhere to record a verdict is that rule where it cannot be argued with.
type HarmCategory struct {
	Category string `json:"category"`
	Severity int    `json:"severity"`
}

// SuspicionFiled is the acknowledgement.
type SuspicionFiled struct {
	SuspicionID       string `json:"suspicion_id"`
	Subject           string `json:"subject"`
	State             string `json:"state"`
	DistinctReporters int    `json:"distinct_reporters"`
	Note              string `json:"note"`
}

// ReportHarm files a signed suspicion about another identity.
//
// The report carries its own signature, separate from the one on the HTTP call,
// because the row outlives the request: an accusation that cannot be
// re-attributed months later is an accusation nobody has to answer for (§14.1).
func (c *Client) ReportHarm(ctx context.Context, r SuspicionReport) (SuspicionFiled, error) {
	if r.Reporter.DID == "" {
		r.Reporter.DID = c.agentDID
	}
	if r.Reporter.Type == "" {
		r.Reporter.Type = "AUTOMATED_GUARDRAIL"
	}
	if r.SuspicionID == "" {
		id, err := uaiid.NewULID()
		if err != nil {
			return SuspicionFiled{}, err
		}
		r.SuspicionID = id.String()
	}
	if r.ReportedAt == "" {
		r.ReportedAt = c.now().UTC().Format(time.RFC3339)
	}
	// The signature covers the report with the signature member removed (§10.4).
	payload, err := uaicrypto.CanonicalizeWithout(r, "signature")
	if err != nil {
		return SuspicionFiled{}, err
	}
	sig, err := c.signer.Sign(uaicrypto.DomainSuspicion, payload)
	if err != nil {
		return SuspicionFiled{}, err
	}
	r.Signature = sig
	var out SuspicionFiled
	err = c.post(ctx, "/v1/suspicions", uaicrypto.DomainSuspicion, r, &out)
	return out, err
}

// Quarantines lists the quarantine orders in force.
func (c *Client) Quarantines(ctx context.Context) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.get(ctx, "/v1/quarantines", &raw)
	return raw, err
}

// Case returns one harm case.
func (c *Client) Case(ctx context.Context, id string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.get(ctx, "/v1/cases/"+id, &raw)
	return raw, err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// PassportCheck is the answer of the §11.6 checklist.
//
// Allowed false with Code UAI_PASSPORT_REQUIRED means the agent has no
// passport, which is different from having one that refuses. Both deny the
// action; only the second says anything about the agent.
type PassportCheck struct {
	Subject         string   `json:"subject"`
	Capability      string   `json:"capability"`
	Targets         []string `json:"targets"`
	Effect          string   `json:"effect"`
	Allowed         bool     `json:"allowed"`
	Code            string   `json:"code,omitempty"`
	Reason          string   `json:"reason"`
	PassportID      string   `json:"passport_id,omitempty"`
	StateAtDecision string   `json:"state_at_decision,omitempty"`
	CredentialHash  string   `json:"credential_hash,omitempty"`
	PolicyVersion   string   `json:"policy_version,omitempty"`
	AsOf            string   `json:"as_of"`
	Note            string   `json:"note"`
}

// CheckPassport runs the §11.6 checklist for an agent, a capability and a set
// of target jurisdictions.
//
// A GET, and it needs no signature: the party who needs the answer is the one
// being dealt with, not the agent, and the check changes nothing.
func (c *Client) CheckPassport(ctx context.Context, subject, capability string, targets []string, risk string) (PassportCheck, error) {
	q := url.Values{}
	q.Set("subject", subject)
	q.Set("capability", capability)
	q.Set("targets", strings.Join(targets, ","))
	if risk != "" {
		q.Set("risk_class", risk)
	}
	var out PassportCheck
	err := c.get(ctx, "/v1/passports/check?"+q.Encode(), &out)
	return out, err
}

// PassportRequest asks for a passport over a set of jurisdictions.
type PassportRequest struct {
	AllowedJurisdictions    []string `json:"allowed_jurisdictions"`
	RestrictedJurisdictions []string `json:"restricted_jurisdictions,omitempty"`
	Capabilities            []struct {
		Capability   string `json:"capability"`
		MinAssurance string `json:"minAssurance,omitempty"`
	} `json:"capabilities"`
	Justification string `json:"justification"`
}

// RequestPassport asks for jurisdictional scope.
//
// It cannot widen what the agent may do: every capability named must already be
// granted, and the gateway refuses the request otherwise. A passport says where.
func (c *Client) RequestPassport(ctx context.Context, req PassportRequest) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.post(ctx, "/v1/passports/request", uaicrypto.DomainPassport, req, &raw)
	return raw, err
}

// RegistrationDraft is what an owner submits to open a registration.
type RegistrationDraft struct {
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

// RegistrationChallenges are the two challenges a registration waits on.
//
// Two, not one, and they must be answered by different keys naming the same
// subject. That is the whole of §8.2: a single challenge would prove only that
// one party was present, and the identity would then rest on whoever answered
// first.
type RegistrationChallenges struct {
	RegistrationID string `json:"registration_id"`
	ChallengeOwner string `json:"challenge_owner"`
	ChallengeAgent string `json:"challenge_agent"`
	ExpiresIn      int    `json:"expires_in"`
}

// OpenRegistration starts a registration and returns the two challenges.
//
// It mints nothing. An unanswered registration produces no identifier, no DID
// and no record a verifier can see, which is why this is the one write path in
// UAI that is not behind proof of possession: establishing the agent's key is
// what it does.
func (c *Client) OpenRegistration(ctx context.Context, draft RegistrationDraft) (RegistrationChallenges, error) {
	var out RegistrationChallenges
	err := c.postPublic(ctx, "/v1/agents", draft, &out)
	return out, err
}
