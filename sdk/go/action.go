package uai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rodmontiel/uai/pkg/attest"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Jurisdiction is the jurisdictional context of an action.
type Jurisdiction struct {
	Origin      string   `json:"origin"`
	Targets     []string `json:"targets,omitempty"`
	CrossBorder bool     `json:"cross_border"`
	Basis       string   `json:"basis,omitempty"`
}

// Intent is what the agent is about to do, stated before it does it.
//
// Input is committed locally and never transmitted. What reaches UAI is
// SHA-256("UAI-v1:commitment" || 0x00 || salt || jcs(input)) and nothing else;
// the salt is returned to the caller in the Record.
type Intent struct {
	Capability     string
	Purpose        string
	Type           string
	Resource       string
	RiskClass      string
	Jurisdiction   Jurisdiction
	Input          any
	Passport       map[string]any
	HarmAssessment []map[string]any
	// RuntimeIdentity is the SPIFFE ID of the workload, when one is bound.
	RuntimeIdentity string
}

func (i Intent) actionType() string {
	if i.Type != "" {
		return i.Type
	}
	return i.Capability
}

// Decision is a signed policy decision record (§12.3.1).
type Decision struct {
	DecisionID string `json:"decision_id"`
	AgentDID   string `json:"agent_did"`
	Policy     struct {
		Version    string `json:"version"`
		BundleHash string `json:"bundle_hash"`
	} `json:"policy"`
	Decision      string              `json:"decision"`
	Reason        string              `json:"reason"`
	RulesFired    []string            `json:"rules_fired"`
	Conditions    map[string]any      `json:"conditions,omitempty"`
	Degraded      bool                `json:"degraded"`
	StalenessSecs int                 `json:"bundle_staleness_seconds"`
	EvaluatedAt   time.Time           `json:"evaluated_at"`
	Signature     uaicrypto.Signature `json:"signature"`
}

// Allows reports whether the decision permits the action to run.
//
// Only two effects do. REQUIRE_HUMAN_APPROVAL is not one of them: it is a
// refusal until a human acts, and treating it as a conditional yes is how a
// human-in-the-loop requirement quietly becomes a log line.
func (d Decision) Allows() bool {
	return d.Decision == "ALLOW" || d.Decision == "ALLOW_WITH_MONITORING"
}

// Denied is returned by Act when policy refused the action. The work was not
// run, and the refusal itself was attested.
type Denied struct {
	Decision Decision
}

func (e *Denied) Error() string {
	return fmt.Sprintf("uai: policy refused %s: %s (%s, decision %s)",
		e.Decision.Decision, e.Decision.Reason, e.Decision.Policy.Version, e.Decision.DecisionID)
}

// Record is everything that happened around one action.
type Record struct {
	Decision Decision
	// Outcome is what was attested: SUCCESS, FAILURE, PARTIAL or
	// ABORTED_BY_POLICY.
	Outcome string
	EventID string
	// EventHash and Sequence are this action's position in the chain. Both are
	// zero when the attestation could not be submitted.
	EventHash string
	Sequence  int64
	// Transparency is LOGGED, UNLOGGED or LOG_UNAVAILABLE. UNLOGGED is not an
	// error: §10.5 is explicit that a log outage must not force unattested
	// execution, so the value says what evidence exists rather than pretending.
	Transparency string
	Receipt      json.RawMessage
	// InputSalt and OutputSalt open the commitments. Keep them: UAI does not
	// have them and never will, so a commitment whose salt was discarded can
	// never be opened by anyone, which is the same as having recorded nothing.
	InputSalt  []byte
	OutputSalt []byte
	// AttestError is set when the action ran but could not be recorded. The
	// work is done and the evidence is missing, and a caller that ignores this
	// field is running unattested without knowing it.
	AttestError error
	// Result is what the work returned.
	Result any
}

// Act runs one action under UAI: evaluate, execute, attest.
//
// The contract, in order:
//
//  1. The PDP is consulted BEFORE fn runs. A refusal means fn is never called.
//  2. Whatever happens to fn — a value, an error, or a panic — an attestation
//     is submitted on the way out, with SUCCESS, FAILURE or ABORTED_BY_POLICY.
//  3. A panic is re-raised after the attestation is submitted, so the agent's
//     own error handling is unchanged by having been observed.
//
// The returned error is fn's error, or *Denied when policy refused. The Record
// is non-nil in both cases: the failure is the part most worth having recorded,
// and returning nothing alongside an error would throw it away.
func (c *Client) Act(ctx context.Context, in Intent,
	fn func(context.Context) (any, error)) (*Record, error) {

	if in.Capability == "" || in.Purpose == "" {
		return nil, errors.New("uai: an action needs a capability and a purpose")
	}
	rec := &Record{}

	decision, err := c.Evaluate(ctx, in)
	if err != nil {
		// The PDP was unreachable or refused to answer. Fail closed: §12.4 is
		// explicit that "we could not ask" must never read as "no objection",
		// and a client that ran the work anyway would be the place where that
		// distinction is lost.
		return rec, fmt.Errorf("uai: policy could not be evaluated, so the action was not run: %w", err)
	}
	rec.Decision = decision

	if !decision.Allows() {
		rec.Outcome = string(attest.OutcomeAbortedByPolicy)
		c.attestInto(ctx, rec, in, nil)
		return rec, &Denied{Decision: decision}
	}

	// From here the work runs, and something is attested no matter how it ends.
	var (
		out      any
		workErr  error
		panicked any
	)
	func() {
		defer func() {
			if p := recover(); p != nil {
				panicked = p
			}
		}()
		out, workErr = fn(ctx)
	}()

	switch {
	case panicked != nil:
		rec.Outcome = string(attest.OutcomeFailure)
	case workErr != nil:
		rec.Outcome = string(attest.OutcomeFailure)
	default:
		rec.Outcome = string(attest.OutcomeSuccess)
		rec.Result = out
	}
	c.attestInto(ctx, rec, in, out)

	if panicked != nil {
		// Re-raised only after the attestation call has returned. An SDK that
		// swallowed the panic would change the agent's behaviour; one that
		// re-raised first would lose the record of the failure.
		panic(panicked)
	}
	return rec, workErr
}

// Evaluate asks the PDP whether an action may proceed, without running it.
func (c *Client) Evaluate(ctx context.Context, in Intent) (Decision, error) {
	body := map[string]any{
		"action": map[string]any{
			"capability": in.Capability, "purpose": in.Purpose, "resource": in.Resource,
		},
		"jurisdiction": map[string]any{
			"origin": in.Jurisdiction.Origin, "targets": orEmpty(in.Jurisdiction.Targets),
			"cross_border": in.Jurisdiction.CrossBorder, "basis": in.Jurisdiction.Basis,
		},
	}
	if len(in.HarmAssessment) > 0 {
		body["harm_assessment"] = in.HarmAssessment
	}
	if in.Passport != nil {
		body["passport"] = in.Passport
	}
	var d Decision
	if err := c.post(ctx, "/v1/policy/evaluate", uaicrypto.DomainDecision, body, &d); err != nil {
		return Decision{}, err
	}
	return d, nil
}

// attestInto builds, signs and submits the attestation, recording the outcome
// on rec. It never returns an error: the action already happened, and the
// caller's error is fn's error. A failure to record is reported in
// rec.AttestError instead of masking what the work did.
func (c *Client) attestInto(ctx context.Context, rec *Record, in Intent, out any) {
	inputCommitment, inputSalt, err := commit(in.Input)
	if err != nil {
		rec.AttestError = err
		return
	}
	outputCommitment, outputSalt, err := commit(out)
	if err != nil {
		rec.AttestError = err
		return
	}
	rec.InputSalt, rec.OutputSalt = inputSalt, outputSalt

	submit := func() error {
		head, err := c.Head(ctx)
		if err != nil {
			return err
		}
		a := attest.Attestation{
			UAIVersion: attest.Version,
			EventID:    "evt-" + Nonce(),
			AgentDID:   c.agentDID, OwnerDID: c.ownerDID,
			RuntimeIdentity: in.RuntimeIdentity,
			Timestamp:       attest.NewTimestamp(c.now()), Nonce: Nonce(),
			Action: attest.Action{
				Type: in.actionType(), Resource: in.Resource,
				Capability: in.Capability, RiskClass: in.RiskClass,
			},
			Purpose: in.Purpose,
			Jurisdiction: attest.Jurisdiction{
				Origin: in.Jurisdiction.Origin, Targets: orEmpty(in.Jurisdiction.Targets),
				CrossBorder: in.Jurisdiction.CrossBorder, Basis: in.Jurisdiction.Basis,
			},
			Policy: attest.Policy{
				Version: rec.Decision.Policy.Version, BundleHash: rec.Decision.Policy.BundleHash,
				DecisionID: rec.Decision.DecisionID, Decision: rec.Decision.Decision,
				RulesFired: rec.Decision.RulesFired,
			},
			InputCommitment:   inputCommitment,
			OutputCommitment:  outputCommitment,
			Outcome:           attest.Outcome(rec.Outcome),
			PreviousEventHash: head.Hash,
			Sequence:          head.Sequence + 1,
		}
		signed, err := attest.Sign(c.signer, a)
		if err != nil {
			return err
		}
		var resp struct {
			EventID      string          `json:"event_id"`
			EventHash    string          `json:"event_hash"`
			Sequence     int64           `json:"sequence"`
			Transparency string          `json:"transparency"`
			Receipt      json.RawMessage `json:"receipt"`
		}
		if err := c.post(ctx, "/v1/actions/attest", uaicrypto.DomainAttestation, signed, &resp); err != nil {
			return err
		}
		c.head = Head{Hash: resp.EventHash, Sequence: resp.Sequence}
		rec.EventID, rec.EventHash, rec.Sequence = resp.EventID, resp.EventHash, resp.Sequence
		rec.Transparency, rec.Receipt = resp.Transparency, resp.Receipt
		return nil
	}

	err = submit()
	// One retry, and only for a chain conflict. The refusal carries the real
	// head, so the retry is not a guess: another writer appended between the
	// read and the write, which is ordinary concurrency rather than an error to
	// surface. Any other refusal is reported as-is; retrying a policy refusal
	// would be the SDK arguing with the guardrail.
	if IsCode(err, "UAI_CHAIN_CONFLICT") {
		err = submit()
	}
	rec.AttestError = err
}

// Head returns the tip of this agent's event chain, fetching it once and then
// tracking it from attestation responses.
func (c *Client) Head(ctx context.Context) (Head, error) {
	if c.head.Hash != "" {
		return c.head, nil
	}
	var resp struct {
		Head Head `json:"head"`
	}
	if err := c.get(ctx, "/v1/agents/"+c.uaiID+"/events?limit=1", &resp); err != nil {
		return Head{}, err
	}
	c.head = resp.Head
	return c.head, nil
}

// commit produces a salted commitment to v, or ("", nil, nil) when there is
// nothing to commit to.
//
// A fresh salt per commitment, never a per-agent or per-session one: commitments
// are published, and two commitments under one salt let anyone who opens the
// first test guesses against the second.
func commit(v any) (string, []byte, error) {
	if v == nil {
		return "", nil, nil
	}
	salt, err := uaicrypto.Salt()
	if err != nil {
		return "", nil, err
	}
	sum, err := uaicrypto.CommitObject(salt, v)
	if err != nil {
		return "", nil, fmt.Errorf("uai: commit: %w", err)
	}
	return uaicrypto.FormatDigest(sum), salt, nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
