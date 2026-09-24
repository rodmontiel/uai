// Package passport implements the UAI Passport and the §11.6 check a PDP runs
// before permitting a cross-border action.
//
// The passport is separate from the identity credential on purpose (§11.1):
// "who this agent is" and "where this agent may act" have different lifetimes,
// different scopes and different revocation paths, and suspending the second
// must never invalidate the first or its history.
//
// This package has no dependencies and no I/O. Everything the check needs is an
// argument, including the number of actions already taken in the last hour, so
// that the decision is a pure function of stated inputs. A verifier auditing a
// past decision can replay it exactly; a check that reached for a clock or a
// database of its own could not be replayed at all.
package passport

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// State is a passport's lifecycle state (§11.4).
type State string

// Passport states.
const (
	StateRequested   State = "REQUESTED"
	StateValid       State = "VALID"
	StateDenied      State = "DENIED"
	StateExpired     State = "EXPIRED"
	StateSuspended   State = "SUSPENDED"
	StateQuarantined State = "QUARANTINED"
	StateRevoked     State = "REVOKED"
)

// Effect is the outcome of a check.
type Effect string

// Check effects. They are the policy effects of §12, so a passport check and a
// policy decision speak one vocabulary: a caller that has to translate between
// two effect scales will eventually translate one of them wrongly.
const (
	EffectAllow           Effect = "ALLOW"
	EffectAllowMonitoring Effect = "ALLOW_WITH_MONITORING"
	EffectRequireApproval Effect = "REQUIRE_HUMAN_APPROVAL"
	EffectDeny            Effect = "DENY"
)

// AuthorizedCapability is one capability a passport authorizes.
type AuthorizedCapability struct {
	Capability   string      `json:"capability"`
	MinAssurance string      `json:"minAssurance,omitempty"`
	Constraints  Constraints `json:"constraints,omitempty"`
}

// Constraints narrow a capability inside the passport.
type Constraints struct {
	// MaxActionsPerHour is a rate ceiling. Zero means no ceiling.
	MaxActionsPerHour int `json:"max_actions_per_hour,omitempty"`
	// RequiresHumanApprovalAbove is a risk class: an action at or above it
	// needs a human, whatever else the passport permits.
	RequiresHumanApprovalAbove string `json:"requires_human_approval_above,omitempty"`
}

// Passport is the credentialSubject of an AgentPassportCredential (§11.3).
type Passport struct {
	ID                      string                 `json:"id"`
	Agent                   string                 `json:"agent"`
	Owner                   string                 `json:"owner"`
	AllowedJurisdictions    []string               `json:"allowedJurisdictions"`
	RestrictedJurisdictions []string               `json:"restrictedJurisdictions"`
	AuthorizedCapabilities  []AuthorizedCapability `json:"authorizedCapabilities"`
	AssuranceLevel          string                 `json:"assuranceLevel"`
	PolicyVersion           string                 `json:"policyVersion"`
	PolicyBundleHash        string                 `json:"policyBundleHash"`
	State                   State                  `json:"state"`
	ValidFrom               time.Time              `json:"validFrom"`
	ValidUntil              time.Time              `json:"validUntil"`
	CredentialHash          string                 `json:"credentialHash,omitempty"`
}

// Request is the action being checked.
type Request struct {
	Capability string
	// Targets are the jurisdictions the action reaches. Under-declaring is the
	// failure mode with real-world consequences (§11.2), so an empty target set
	// on a cross-border action is treated as unanswerable, not as harmless.
	Targets []string
	// RiskClass of the action: INFORMATIONAL, LOW, MODERATE, HIGH, CRITICAL.
	RiskClass string
	// AgentAssurance is the agent's current assurance level.
	AgentAssurance string
	// SignatureValid reports whether the credential's proof verified. It is an
	// argument because verifying a Data Integrity proof needs the issuer's key,
	// which is I/O; passing the result in keeps this package replayable.
	SignatureValid bool
	// IssuerTrusted reports whether the issuer is in the caller's trust set.
	IssuerTrusted bool
	// ActionsLastHour is how many actions under this capability the agent has
	// already taken in the trailing hour.
	ActionsLastHour int
}

// Result is the outcome of a check.
//
// Code is a UAI_* error code when the effect is DENY, so a refusal names itself
// in the vocabulary the API already uses and a caller never has to map a
// sentence back to a reason.
type Result struct {
	Effect Effect
	Code   string
	Reason string
	// StatusAtDecision is the passport state the decision was made against. It
	// is recorded in the attestation (§10.2) so the state survives the
	// passport's later expiry or revocation.
	StatusAtDecision State
	CredentialHash   string
}

// Allowed reports whether the action may proceed.
func (r Result) Allowed() bool {
	return r.Effect == EffectAllow || r.Effect == EffectAllowMonitoring
}

// ErrNoPassport is returned by Check when no passport was supplied.
var ErrNoPassport = errors.New("passport: no passport presented for a cross-border action")

// assuranceRank orders the assurance levels. An unknown level ranks below the
// lowest known one rather than being treated as an error: the fail-closed
// reading of "I do not recognise this level" is "it satisfies no minimum".
var assuranceRank = map[string]int{
	"UAI-AL0": 0, "UAI-AL1": 1, "UAI-AL2": 2, "UAI-AL3": 3, "UAI-AL4": 4,
}

// riskRank orders the risk classes.
var riskRank = map[string]int{
	"INFORMATIONAL": 0, "LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4,
}

// Check runs the §11.6 checklist.
//
// It is fail-closed without exception: every path that cannot establish a fact
// denies. §11.6 states the reason and it is worth repeating where the code
// lives — an accountability system that degrades into permissiveness under load
// is worse than none, because it manufactures a false record of compliance.
//
// One deliberate difference from the order printed in §11.6: an explicitly
// restricted jurisdiction is reported before a merely unlisted one. The effect
// is identical (both deny), but §11.3 says the restricted fact is the one an
// auditor cares about, and reporting the weaker reason when the stronger one
// applies would hide it. The spec text was updated to match.
func Check(p *Passport, req Request, now time.Time) Result {
	if p == nil {
		return Result{Effect: EffectDeny, Code: "UAI_PASSPORT_REQUIRED",
			Reason: "this action crosses a jurisdictional boundary and no passport was presented"}
	}
	base := Result{StatusAtDecision: p.State, CredentialHash: p.CredentialHash}
	deny := func(code, reason string) Result {
		base.Effect, base.Code, base.Reason = EffectDeny, code, reason
		return base
	}

	if !req.SignatureValid || !req.IssuerTrusted {
		// One code for both, because the caller must act identically: an
		// unverifiable passport and one from an untrusted issuer are equally
		// unusable, and distinguishing them here would invite a caller to
		// accept the "less bad" one.
		return deny("UAI_PASSPORT_INVALID",
			"the passport proof did not verify against a trusted issuer")
	}
	if p.State == StateRevoked {
		return deny("UAI_PASSPORT_SUSPENDED", "the passport was revoked")
	}
	if now.Before(p.ValidFrom) || !now.Before(p.ValidUntil) {
		return deny("UAI_PASSPORT_EXPIRED", fmt.Sprintf(
			"the passport is valid from %s to %s", p.ValidFrom.UTC().Format(time.RFC3339),
			p.ValidUntil.UTC().Format(time.RFC3339)))
	}
	if p.State != StateValid {
		return deny("UAI_PASSPORT_SUSPENDED",
			"the passport is "+string(p.State)+", so it authorizes nothing right now")
	}
	if len(req.Targets) == 0 {
		return deny("UAI_JURISDICTION_NOT_ALLOWED",
			"the action declares no target jurisdiction, so no passport scope can be checked against it")
	}

	restricted := set(p.RestrictedJurisdictions)
	allowed := set(p.AllowedJurisdictions)
	var offending []string
	for _, t := range req.Targets {
		if restricted[normalize(t)] {
			offending = append(offending, normalize(t))
		}
	}
	if len(offending) > 0 {
		sort.Strings(offending)
		return deny("UAI_JURISDICTION_RESTRICTED",
			"explicitly restricted for "+strings.Join(offending, ", "))
	}
	for _, t := range req.Targets {
		if !allowed[normalize(t)] {
			offending = append(offending, normalize(t))
		}
	}
	if len(offending) > 0 {
		sort.Strings(offending)
		return deny("UAI_JURISDICTION_NOT_ALLOWED",
			"not authorized for "+strings.Join(offending, ", "))
	}

	authorized, found := capability(p, req.Capability)
	if !found {
		return deny("UAI_CAPABILITY_NOT_IN_PASSPORT",
			"the passport does not authorize "+req.Capability)
	}
	if authorized.MinAssurance != "" && assuranceRank[req.AgentAssurance] < assuranceRank[authorized.MinAssurance] {
		return deny("UAI_ASSURANCE_INSUFFICIENT", fmt.Sprintf(
			"%s requires %s and the agent is %s", req.Capability, authorized.MinAssurance, req.AgentAssurance))
	}

	// Step 9. These raise the bar to a human; they never lower it. Nothing
	// below can turn a denial above into an allow.
	if c := authorized.Constraints; c.MaxActionsPerHour > 0 && req.ActionsLastHour >= c.MaxActionsPerHour {
		base.Effect, base.Code = EffectRequireApproval, "UAI_RATE_CEILING_REACHED"
		base.Reason = fmt.Sprintf("%d actions already taken this hour, ceiling is %d",
			req.ActionsLastHour, c.MaxActionsPerHour)
		return base
	}
	if above := authorized.Constraints.RequiresHumanApprovalAbove; above != "" {
		if rank, known := riskRank[strings.ToUpper(req.RiskClass)]; !known ||
			rank >= riskRank[strings.ToUpper(above)] {
			base.Effect, base.Code = EffectRequireApproval, "UAI_HUMAN_APPROVAL_REQUIRED"
			base.Reason = "the passport requires a human above " + above + " risk"
			return base
		}
	}

	// A cross-border action that clears every check is still monitored. §11.6
	// ends at "ALLOW / ALLOW_WITH_MONITORING" and this is the branch that
	// chooses: crossing a boundary is the condition the passport exists to make
	// legible, so it is recorded as observed rather than as unremarkable.
	base.Effect, base.Reason = EffectAllowMonitoring, "within passport scope"
	return base
}

func capability(p *Passport, name string) (AuthorizedCapability, bool) {
	for _, c := range p.AuthorizedCapabilities {
		if c.Capability == name {
			return c, true
		}
	}
	return AuthorizedCapability{}, false
}

func set(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[normalize(i)] = true
	}
	return m
}

// normalize upper-cases an ISO 3166-1 alpha-2 code. "de" and "DE" are the same
// jurisdiction, and a check that treated them as different would deny an action
// the passport authorizes -- or, with the lists the other way round, permit one
// it does not.
func normalize(code string) string { return strings.ToUpper(strings.TrimSpace(code)) }

// Validate reports whether a passport is internally coherent.
func (p *Passport) Validate() error {
	if p.Agent == "" || p.Owner == "" {
		return errors.New("passport: subject and owner are required")
	}
	if p.PolicyVersion == "" || p.PolicyBundleHash == "" {
		return errors.New("passport: a passport must name the policy version that authorized it")
	}
	if !p.ValidFrom.Before(p.ValidUntil) {
		return errors.New("passport: validFrom must precede validUntil")
	}
	restricted := set(p.RestrictedJurisdictions)
	for _, a := range p.AllowedJurisdictions {
		if restricted[normalize(a)] {
			// The database refuses this too. It is checked here as well so that
			// a passport built in memory cannot be checked against before it
			// would have been rejected on the way to storage: an ambiguous
			// passport is resolved differently by different verifiers.
			return fmt.Errorf("passport: %s is both allowed and restricted", normalize(a))
		}
	}
	return nil
}
