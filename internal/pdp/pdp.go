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
	Manifest policy.Manifest
	query    rego.PreparedEvalQuery
	loadedAt time.Time
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

	opts := []func(*rego.Rego){rego.Query(Query), rego.Store(inmem.NewFromObject(data))}
	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}
	prepared, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("pdp: compile bundle %s: %w", manifest.Version(), err)
	}
	return &Bundle{Manifest: manifest, query: prepared, loadedAt: time.Now()}, nil
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
