// Package pdp is the Policy Decision Point: it evaluates a request against a
// verified GASC bundle and produces a decision record.
//
// It lives in internal/ and not pkg/ for a reason worth stating. Evaluating
// Rego costs 33 third-party modules, and pkg/ is the verification path a
// relying party runs (project rule 3). A relying party does NOT need to re-run
// Rego: it needs to check that a decision record names a policy version and a
// bundle hash and carries a valid signature, and that the bundle with that hash
// was approved by the governance process. Both of those live in pkg/policy with
// no dependencies at all.
//
// So the heavy evaluator sits on the side that makes fresh decisions, and the
// dependency-free checks sit on the side that audits them afterwards.
package pdp

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"github.com/rodmontiel/uai/pkg/policy"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Query is the single entry point into the bundle. One entry point means a
// decision cannot come from a rule the aggregator never considered.
const Query = "data.gasc.decision"

// Effects a bundle may return.
const (
	EffectAllow           = "ALLOW"
	EffectAllowMonitoring = "ALLOW_WITH_MONITORING"
	EffectRequireApproval = "REQUIRE_HUMAN_APPROVAL"
	EffectDeny            = "DENY"
	EffectQuarantine      = "QUARANTINE"
)

var knownEffects = map[string]bool{
	EffectAllow: true, EffectAllowMonitoring: true, EffectRequireApproval: true,
	EffectDeny: true, EffectQuarantine: true,
}

// Bundle is a loaded, verified policy bundle ready to evaluate.
type Bundle struct {
	Manifest  policy.Manifest
	query     rego.PreparedEvalQuery
	harmQuery rego.PreparedEvalQuery
	// threshold and minCountries come from the bundle, so a quorum changes when
	// someone signs rather than when someone deploys.
	threshold    string
	minCountries int
	loadedAt     time.Time
}

// Version is the "GASC-2027.4" form recorded on every decision.
func (b *Bundle) Version() string { return b.Manifest.Version() }

// Hash is the bundle hash recorded on every decision.
func (b *Bundle) Hash() string { return b.Manifest.BundleHash }

// LoadedAt is when this bundle was last refreshed, used to report staleness.
func (b *Bundle) LoadedAt() time.Time { return b.loadedAt }

// Decision is what the bundle returned.
type Decision struct {
	Effect     string         `json:"effect"`
	Reason     string         `json:"reason"`
	RulesFired []string       `json:"rules_fired"`
	Conditions map[string]any `json:"conditions,omitempty"`
}

// Load reads a bundle from a filesystem, verifies it, and compiles it.
//
// Verification comes first and is not optional. Compiling rules before checking
// who approved them would mean a PDP that happily enforces whatever policy was
// last written to disk, which is the failure the signatures exist to prevent.
// `at` is the moment effectiveness is judged against, which is not the same as
// the moment the bundle was loaded: staging a release means verifying a bundle
// that is not yet in force. Staleness is measured from the real load time, so a
// bundle staged for next quarter does not report a negative age.
func Load(ctx context.Context, fsys fs.FS, authority policy.Authority, at time.Time) (*Bundle, error) {
	files, err := readAll(fsys)
	if err != nil {
		return nil, err
	}
	raw, ok := files["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("pdp: bundle has no manifest.json")
	}
	manifest, err := policy.ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	if err := policy.Verify(manifest, files, authority); err != nil {
		return nil, err
	}
	if err := manifest.EffectiveAt(at); err != nil {
		return nil, err
	}

	modules := map[string]string{}
	data := map[string]any{}
	for name, content := range files {
		switch {
		case strings.HasPrefix(name, "policy/") && strings.HasSuffix(name, ".rego"):
			modules[name] = string(content)
		case strings.HasPrefix(name, "data/") && strings.HasSuffix(name, ".json"):
			var doc map[string]any
			if err := json.Unmarshal(content, &doc); err != nil {
				return nil, fmt.Errorf("pdp: %s: %w", name, err)
			}
			// data/taxonomy.json mounts at data.taxonomy, which is how the
			// rego refers to it.
			data[strings.TrimSuffix(path.Base(name), ".json")] = doc
		}
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("pdp: bundle carries no rego modules")
	}

	store := inmem.NewFromObject(data)
	compile := func(query string) (rego.PreparedEvalQuery, error) {
		opts := []func(*rego.Rego){rego.Query(query), rego.Store(store)}
		for name, src := range modules {
			opts = append(opts, rego.Module(name, src))
		}
		return rego.New(opts...).PrepareForEval(ctx)
	}
	prepared, err := compile(Query)
	if err != nil {
		return nil, fmt.Errorf("pdp: compile bundle %s: %w", manifest.Version(), err)
	}
	// A second prepared query for the harm rules alone.
	//
	// The harm monitor asks a different question from the action PDP: "does
	// this reported harm warrant a quarantine", not "may this action proceed".
	// Running it through the full aggregator would mix in capability and
	// jurisdiction findings about an action nobody is proposing, and the
	// strictest-wins rule would then hide the harm answer behind them.
	harm, err := compile(HarmQuery)
	if err != nil {
		return nil, fmt.Errorf("pdp: compile harm rules of %s: %w", manifest.Version(), err)
	}
	// The governance parameters come from the bundle, never from code: §16
	// says the threshold is policy, and a quorum compiled into a service is a
	// quorum that changes when someone deploys rather than when someone signs.
	gov, err := compile(GovernanceQuery)
	if err != nil {
		return nil, fmt.Errorf("pdp: compile governance rules of %s: %w", manifest.Version(), err)
	}
	b := &Bundle{Manifest: manifest, query: prepared, harmQuery: harm, loadedAt: time.Now()}
	if err := b.loadGovernance(ctx, gov); err != nil {
		return nil, err
	}
	return b, nil
}

// HarmQuery asks only the harm taxonomy rules.
const HarmQuery = "data.gasc.harm.findings"

// GovernanceQuery asks for the governance parameters.
const GovernanceQuery = "data.gasc.governance"

// loadGovernance reads the threshold and country minimum out of the bundle.
func (b *Bundle) loadGovernance(ctx context.Context, q rego.PreparedEvalQuery) error {
	results, err := q.Eval(ctx)
	if err != nil || len(results) == 0 || len(results[0].Expressions) == 0 {
		return fmt.Errorf("pdp: bundle %s states no governance parameters: %w",
			b.Manifest.Version(), err)
	}
	doc, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return fmt.Errorf("pdp: bundle %s governance parameters are not an object",
			b.Manifest.Version())
	}
	threshold, _ := doc["threshold"].(string)
	countries, _ := doc["min_countries"].(json.Number)
	if threshold == "" {
		return fmt.Errorf("pdp: bundle %s states no revocation threshold", b.Manifest.Version())
	}
	b.threshold = threshold
	if n, err := countries.Int64(); err == nil {
		b.minCountries = int(n)
	}
	return nil
}

// Threshold is the revocation threshold this bundle sets, as "M-of-N".
func (b *Bundle) Threshold() string { return b.threshold }

// MinCountries is the jurisdictional spread a revocation needs.
func (b *Bundle) MinCountries() int { return b.minCountries }

// HarmEffect returns the strictest effect the harm taxonomy assigns to a set of
// reported categories, or "" when none of them crosses its threshold.
//
// The thresholds live in the signed bundle, so "is this bad enough to quarantine
// an agent" is answered by policy that five parties approved, not by a constant
// in a service.
func (b *Bundle) HarmEffect(ctx context.Context, assessment []map[string]any) (string, string, error) {
	if b.harmQuery.Modules() == nil && len(assessment) == 0 {
		return "", "", nil
	}
	results, err := b.harmQuery.Eval(ctx, rego.EvalInput(map[string]any{
		"harm_assessment": assessment,
	}))
	if err != nil {
		return "DENY", "harm_evaluation_failed", fmt.Errorf("pdp: harm: %w", err)
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return "", "", nil
	}
	raw, ok := results[0].Expressions[0].Value.([]any)
	if !ok {
		return "", "", nil
	}
	// Two different questions share one vocabulary, and they order it
	// differently.
	//
	// The action PDP asks "may this proceed", and there DENY is strictest: the
	// action does not happen. The harm monitor asks "what response does this
	// warrant", and there QUARANTINE is stronger than DENY — denying one action
	// is narrower than restricting the agent that attempted it.
	//
	// Ranking them on one scale is how a SAFETY_SYSTEM_BYPASS finding gets
	// buried under an UNAUTHORIZED_ACCESS DENY from the same report, which is
	// exactly backwards: the category the policy singles out as the highest
	// signal it can observe would be the one that stops mattering as soon as
	// anything else is also wrong.
	rank := map[string]int{
		"ALLOW": 0, "ALLOW_WITH_MONITORING": 1, "REQUIRE_HUMAN_APPROVAL": 2, "DENY": 3,
	}
	worst, reason := "", ""
	for _, item := range raw {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		effect, _ := finding["effect"].(string)
		// A response category, not a point on the permissiveness scale: any
		// finding that calls for quarantine decides the answer, whatever else
		// the report also says.
		if effect == "QUARANTINE" {
			reason, _ = finding["reason"].(string)
			return "QUARANTINE", reason, nil
		}
		if worst == "" || rank[effect] > rank[worst] {
			worst = effect
			reason, _ = finding["reason"].(string)
		}
	}
	return worst, reason, nil
}

// Evaluate runs one request against the bundle.
//
// Any failure is a DENY, never an error the caller might be tempted to ignore.
// A PDP that returns "I could not decide" invites the calling code to treat it
// as "no objection", and every guardrail that has ever failed open has failed
// open exactly there.
func (b *Bundle) Evaluate(ctx context.Context, input any) (Decision, error) {
	results, err := b.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return denied("evaluation_failed"), fmt.Errorf("pdp: evaluate: %w", err)
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return denied("no_result"), fmt.Errorf("pdp: bundle %s returned no decision", b.Version())
	}
	raw, err := json.Marshal(results[0].Expressions[0].Value)
	if err != nil {
		return denied("undecodable_result"), fmt.Errorf("pdp: decode decision: %w", err)
	}
	var d Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return denied("undecodable_result"), fmt.Errorf("pdp: decode decision: %w", err)
	}
	if !knownEffects[d.Effect] {
		// A bundle returning an effect this build does not know is a bundle
		// this build cannot enforce. Denying is the only honest answer.
		return denied("unknown_effect"), fmt.Errorf("pdp: bundle %s returned effect %q", b.Version(), d.Effect)
	}
	sort.Strings(d.RulesFired)
	return d, nil
}

func denied(reason string) Decision {
	return Decision{Effect: EffectDeny, Reason: reason, RulesFired: []string{}}
}

// readAll loads every file in the bundle.
func readAll(fsys fs.FS) (policy.Files, error) {
	files := policy.Files{}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		files[name] = content
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("pdp: read bundle: %w", err)
	}
	return files, nil
}

// Staleness is how long ago the bundle was refreshed, recorded on every
// decision so that "we were running on a cached bundle" is a fact in the record
// rather than a footnote in an ops channel (§12.4).
//
// Never negative. A clock that moved backwards is a reason to report zero age,
// not to write a negative number into an audit record where every reader would
// have to guess what it meant.
func (b *Bundle) Staleness(now time.Time) time.Duration {
	if d := now.Sub(b.loadedAt); d > 0 {
		return d
	}
	return 0
}

// LoadAuthorityFile reads the public approval set.
//
// In production this set comes from UAIPolicyRegistry on-chain (§12.6); a file
// is the development stand-in. Either way the PDP must know WHO may approve
// policy before it will load any, because a bundle verified against an
// attacker-supplied authority set is a bundle verified against nothing.
func LoadAuthorityFile(path string) (policy.Authority, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pdp: authority: %w", err)
	}
	var doc struct {
		Keys map[string]uaicrypto.JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("pdp: authority: %w", err)
	}
	out := policy.Authority{}
	for kid, jwk := range doc.Keys {
		pub, err := jwk.Public()
		if err != nil {
			return nil, fmt.Errorf("pdp: authority key %s: %w", kid, err)
		}
		out[kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pdp: authority set is empty")
	}
	return out, nil
}
