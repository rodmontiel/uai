package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	uai "github.com/rodmontiel/uai/sdk/go"
)

// Tool is one MCP tool.
//
// Grants is declared on every tool and is false on every tool. It is not
// decoration: the test that keeps §22.9 honest reads this field, so adding a
// tool that grants means writing "Grants: true" and watching the build fail.
// A rule that is only in prose is a rule that survives exactly until someone
// adds a feature in a hurry.
type Tool struct {
	Name        string
	Title       string
	Description string
	Schema      map[string]any
	Grants      bool
	// ReadOnly marks a tool with no side effects, so a framework can decide
	// what to allow without asking a human each time.
	ReadOnly bool
	Handle   func(ctx context.Context, c *uai.Client, args json.RawMessage) (any, error)
}

// object builds a JSON Schema object.
func object(required []string, props map[string]any) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{
		"type": "object", "properties": props, "required": required,
		// A model that invents a parameter is a model that misunderstood the
		// tool, and silently dropping it would hide that.
		"additionalProperties": false,
	}
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func strs(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

// tools is the eight-tool surface of §22.9.
func tools() []Tool {
	return []Tool{
		{
			Name: "uai_verify_identity", Title: "Verify a UAI identity",
			Description: "Check any UAI-ID. Returns the verification status and what it means. " +
				"A 'not verified' answer for an unknown identifier means UAI has no record of it, " +
				"which is NOT an assertion that the agent is malicious.",
			ReadOnly: true,
			Schema: object([]string{"uai_id"}, map[string]any{
				"uai_id": str("The UAI-ID to verify, e.g. uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"),
			}),
			Handle: func(ctx context.Context, c *uai.Client, args json.RawMessage) (any, error) {
				var in struct {
					UAIID string `json:"uai_id"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return nil, err
				}
				return c.Verify(ctx, in.UAIID)
			},
		},
		{
			Name: "uai_get_status", Title: "Status of the calling agent",
			Description: "Return the identity card of the agent this server signs as: status, " +
				"assurance level, jurisdiction and the policy version it was registered under.",
			ReadOnly: true,
			Schema:   object(nil, map[string]any{}),
			Handle: func(ctx context.Context, c *uai.Client, _ json.RawMessage) (any, error) {
				return c.Status(ctx)
			},
		},
		{
			Name: "uai_check_policy", Title: "Evaluate a policy decision without acting",
			Description: "Ask the guardrail whether an action would be permitted, WITHOUT performing " +
				"it. Returns a signed decision record naming the policy version and bundle hash. " +
				"A DENY here is a refusal, not a suggestion.",
			ReadOnly: true,
			Schema: object([]string{"capability", "purpose"}, map[string]any{
				"capability": str("The capability the action needs, e.g. cloud.securitygroup.update"),
				"purpose":    str("Why the action is being taken, in the agent's own words"),
				"resource":   str("The resource the action touches, if any"),
				"origin":     str("ISO 3166-1 alpha-2 jurisdiction the agent acts from"),
				"targets":    strs("ISO 3166-1 alpha-2 jurisdictions the action reaches"),
				"basis":      str("Why that jurisdiction was concluded: owner_jurisdiction, execution_region, subject_jurisdiction, resource_location, data_location, infrastructure_owner or declared_consequence"),
			}),
			Handle: func(ctx context.Context, c *uai.Client, args json.RawMessage) (any, error) {
				in, err := decodeIntent(args)
				if err != nil {
					return nil, err
				}
				return c.Evaluate(ctx, in)
			},
		},
		{
			Name: "uai_attest_action", Title: "Attest an action that was performed",
			Description: "Record a signed attestation that this agent performed an action, and append " +
				"it to its event chain. Evaluates policy first and refuses to attest an action the " +
				"guardrail would not have permitted. Outcome may be SUCCESS, FAILURE or PARTIAL — " +
				"attest failures too: a record that contains only successes is an advertisement.",
			Schema: object([]string{"capability", "purpose", "outcome"}, map[string]any{
				"capability":     str("The capability the action used"),
				"purpose":        str("Why the action was taken"),
				"resource":       str("The resource the action touched, if any"),
				"outcome":        map[string]any{"type": "string", "enum": []string{"SUCCESS", "FAILURE", "PARTIAL"}, "description": "How the action ended"},
				"origin":         str("ISO 3166-1 alpha-2 jurisdiction the agent acted from"),
				"targets":        strs("ISO 3166-1 alpha-2 jurisdictions the action reached"),
				"basis":          str("Why that jurisdiction was concluded"),
				"risk_class":     str("INFORMATIONAL, LOW, MODERATE, HIGH or CRITICAL"),
				"input_summary":  str("A short description of the input. It is COMMITTED locally with a random salt; the text never leaves this process."),
				"output_summary": str("A short description of the result. Committed the same way."),
			}),
			Handle: func(ctx context.Context, c *uai.Client, args json.RawMessage) (any, error) {
				return attestTool(ctx, c, args)
			},
		},
		{
			Name: "uai_request_capability", Title: "Request a capability from the owner",
			Description: "Create a PENDING request for a capability this agent does not hold. " +
				"This does NOT grant anything and cannot be made to: approval is an act by the " +
				"human owner, out of band, and no tool on this server can perform it. Expect to " +
				"continue without the capability.",
			Schema: object([]string{"capability", "justification"}, map[string]any{
				"capability":    str("The capability being requested"),
				"justification": str("What it is for, in terms the owner can decide on"),
				"purpose":       str("The immediate purpose, if there is one"),
			}),
			Handle: func(ctx context.Context, c *uai.Client, args json.RawMessage) (any, error) {
				var in struct {
					Capability    string `json:"capability"`
					Justification string `json:"justification"`
					Purpose       string `json:"purpose"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return nil, err
				}
				return c.RequestCapability(ctx, in.Capability, in.Justification, in.Purpose)
			},
		},
		{
			Name: "uai_verify_passport", Title: "Check passport scope for a jurisdiction set",
			Description: "Run the passport checklist for an agent, a capability and a set of target " +
				"jurisdictions. Answers whether the passport covers them. A passport in scope does " +
				"not authorize an action; the guardrail still evaluates it.",
			ReadOnly: true,
			Schema: object([]string{"capability", "targets"}, map[string]any{
				"subject":    str("The UAI-ID to check. Defaults to the calling agent."),
				"capability": str("The capability the action needs"),
				"targets":    strs("ISO 3166-1 alpha-2 jurisdictions the action reaches"),
				"risk_class": str("INFORMATIONAL, LOW, MODERATE, HIGH or CRITICAL"),
			}),
			Handle: func(ctx context.Context, c *uai.Client, args json.RawMessage) (any, error) {
				var in struct {
					Subject    string   `json:"subject"`
					Capability string   `json:"capability"`
					Targets    []string `json:"targets"`
					RiskClass  string   `json:"risk_class"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return nil, err
				}
				if in.Subject == "" {
					in.Subject = c.UAIID()
				}
				return c.CheckPassport(ctx, in.Subject, in.Capability, in.Targets, in.RiskClass)
			},
		},
		{
			Name: "uai_report_incident", Title: "File a harm suspicion",
			Description: "Report that another identity may have caused harm. The report is signed by " +
				"this agent and is attributable to it: filing one is a consequential act and there " +
				"is no anonymous path. It opens an investigation; it decides nothing.",
			Schema: object([]string{"subject_agent_did", "subject_owner_did", "harm_categories", "confidence"},
				map[string]any{
					"subject_agent_did": str("DID of the agent the report is about"),
					"subject_owner_did": str("DID of the owner that answers for it"),
					"harm_categories": map[string]any{
						"type": "array", "items": map[string]any{"type": "object"},
						"description": "Objects with 'category' and a 'severity' of 0 to 4. There is no field for a finding: a suspicion is a claim warranting examination, never guilt.",
					},
					"confidence":             map[string]any{"type": "number", "minimum": 0, "maximum": 1, "description": "How confident the reporter is, 0 to 1"},
					"related_events":         strs("Event ids this report is about"),
					"guardrail_rule":         str("The rule that fired, if a guardrail produced this"),
					"affected_jurisdictions": strs("ISO 3166-1 alpha-2 codes of affected jurisdictions"),
				}),
			Handle: func(ctx context.Context, c *uai.Client, args json.RawMessage) (any, error) {
				var in struct {
					SubjectAgentDID string             `json:"subject_agent_did"`
					SubjectOwnerDID string             `json:"subject_owner_did"`
					HarmCategories  []uai.HarmCategory `json:"harm_categories"`
					Confidence      float64            `json:"confidence"`
					RelatedEvents   []string           `json:"related_events"`
					GuardrailRule   string             `json:"guardrail_rule"`
					Affected        []string           `json:"affected_jurisdictions"`
				}
				if err := json.Unmarshal(args, &in); err != nil {
					return nil, err
				}
				var report uai.SuspicionReport
				report.Subject.AgentDID = in.SubjectAgentDID
				report.Subject.OwnerDID = in.SubjectOwnerDID
				report.HarmCategories = in.HarmCategories
				report.Confidence = in.Confidence
				report.RelatedEvents = in.RelatedEvents
				report.Guardrail.Rule = in.GuardrailRule
				report.AffectedJurisdictions = in.Affected
				return c.ReportHarm(ctx, report)
			},
		},
		{
			Name: "uai_register", Title: "Start a registration",
			Description: "Open a registration for a NEW agent and return the two challenges it " +
				"waits on. It mints nothing: the identity exists only once the owner's key and " +
				"the new agent's own key have both signed, naming the same subject. This server " +
				"holds neither of those keys, so it cannot finish what it starts here.",
			Schema: object([]string{"logical_name", "agent_type", "owner_did"}, map[string]any{
				"logical_name":         str("The agent's name, e.g. DeliveryOptimizer"),
				"version":              str("The agent's version"),
				"agent_type":           str("What kind of agent it is, e.g. AUTONOMOUS_TASK"),
				"owner_did":            str("DID of the owner that will answer for it"),
				"org_did":              str("DID of the owning organization, if any"),
				"vendor":               str("Vendor of the underlying model or framework"),
				"model_family":         str("Model family, if the agent is model-backed"),
				"framework":            str("Agent framework"),
				"primary_jurisdiction": str("ISO 3166-1 alpha-2 code of the agent's primary jurisdiction"),
			}),
			Handle: func(ctx context.Context, c *uai.Client, args json.RawMessage) (any, error) {
				var draft uai.RegistrationDraft
				if err := json.Unmarshal(args, &draft); err != nil {
					return nil, err
				}
				challenges, err := c.OpenRegistration(ctx, draft)
				if err != nil {
					return nil, err
				}
				return map[string]any{
					"registration_id": challenges.RegistrationID,
					"challenge_owner": challenges.ChallengeOwner,
					"challenge_agent": challenges.ChallengeAgent,
					"expires_in":      challenges.ExpiresIn,
					"identity_exists": false,
					"next_steps": []string{
						"The NEW agent generates its own key pair. UAI never generates it, and " +
							"neither does this server: whoever can generate your key can impersonate you.",
						"The owner signs challenge_owner with the owner key, out of band, and POSTs " +
							"it to /v1/agents/{registration_id}/prove with role=owner and the new " +
							"agent's key thumbprint.",
						"The new agent signs challenge_agent with the key from step 1 and POSTs it " +
							"with role=agent and its public JWK.",
						"Both halves must name the same subject. The UAI-ID is minted only then.",
					},
					"note": "No identifier, DID or verifiable record exists yet. An unanswered " +
						"registration expires and leaves nothing behind.",
				}, nil
			},
		},
	}
}

// decodeIntent turns tool arguments into an SDK intent.
func decodeIntent(args json.RawMessage) (uai.Intent, error) {
	var in struct {
		Capability    string   `json:"capability"`
		Purpose       string   `json:"purpose"`
		Resource      string   `json:"resource"`
		RiskClass     string   `json:"risk_class"`
		Origin        string   `json:"origin"`
		Targets       []string `json:"targets"`
		Basis         string   `json:"basis"`
		InputSummary  string   `json:"input_summary"`
		OutputSummary string   `json:"output_summary"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return uai.Intent{}, err
	}
	if in.Capability == "" || in.Purpose == "" {
		return uai.Intent{}, errors.New("capability and purpose are required")
	}
	intent := uai.Intent{
		Capability: in.Capability, Purpose: in.Purpose, Resource: in.Resource,
		RiskClass: in.RiskClass,
		Jurisdiction: uai.Jurisdiction{
			Origin: in.Origin, Targets: in.Targets, Basis: in.Basis,
			// Under-declaring jurisdiction is the failure mode with real-world
			// consequences (§11.2), so any declared target that is not the
			// origin makes this cross-border rather than requiring the caller
			// to say so separately -- and to remember to.
			CrossBorder: crossBorder(in.Origin, in.Targets),
		},
	}
	if in.InputSummary != "" {
		intent.Input = in.InputSummary
	}
	return intent, nil
}

func crossBorder(origin string, targets []string) bool {
	for _, t := range targets {
		if t != "" && t != origin {
			return true
		}
	}
	return false
}

// attestTool evaluates policy, then attests, refusing to record an action the
// guardrail would not have permitted.
//
// The order matters and it is the whole reason this tool is not a thin wrapper
// over POST /v1/actions/attest: attesting first and evaluating later would
// produce a chain entry claiming a policy basis the policy never gave.
func attestTool(ctx context.Context, c *uai.Client, args json.RawMessage) (any, error) {
	intent, err := decodeIntent(args)
	if err != nil {
		return nil, err
	}
	var in struct {
		Outcome       string `json:"outcome"`
		OutputSummary string `json:"output_summary"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, err
	}
	if in.Outcome == "" {
		return nil, errors.New("outcome is required: SUCCESS, FAILURE or PARTIAL")
	}

	var result any
	if in.OutputSummary != "" {
		result = in.OutputSummary
	}
	// Act is used rather than a bare attest so the same rules apply as anywhere
	// else in the SDK: policy first, and a refusal is recorded as
	// ABORTED_BY_POLICY rather than silently dropped.
	rec, actErr := c.Act(ctx, intent, func(context.Context) (any, error) {
		if in.Outcome == "SUCCESS" {
			return result, nil
		}
		// The work already happened outside this process and the caller is
		// telling us how it ended. Returning an error here is what makes the
		// attestation say FAILURE.
		return result, fmt.Errorf("the agent reported %s", in.Outcome)
	})

	out := map[string]any{
		"decision":     rec.Decision.Decision,
		"policy":       rec.Decision.Policy,
		"outcome":      rec.Outcome,
		"event_id":     rec.EventID,
		"event_hash":   rec.EventHash,
		"sequence":     rec.Sequence,
		"transparency": rec.Transparency,
	}
	if rec.Receipt != nil {
		out["receipt"] = rec.Receipt
	}
	// The salts are returned to the caller because UAI does not have them and
	// never will. A commitment whose salt was discarded can never be opened by
	// anyone, which is the same as not having recorded anything.
	if rec.InputSalt != nil {
		out["input_salt_hex"] = hex(rec.InputSalt)
		out["salt_note"] = "Keep these salts. They are the only way to open the commitments later, " +
			"and UAI does not have them."
	}
	if rec.OutputSalt != nil {
		out["output_salt_hex"] = hex(rec.OutputSalt)
	}
	if rec.AttestError != nil {
		out["attestation_error"] = rec.AttestError.Error()
		out["warning"] = "The action was NOT recorded. Nothing verifiable exists for it."
	}
	var denied *uai.Denied
	if errors.As(actErr, &denied) {
		out["refused"] = true
		out["reason"] = denied.Decision.Reason
	}
	return out, nil
}

const hexDigits = "0123456789abcdef"

func hex(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0f])
	}
	return string(out)
}
