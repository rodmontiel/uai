// Package openapi checks the UAI OpenAPI definition against the protocol
// specification.
//
// It verifies three things a hand-written API document silently gets wrong:
// every endpoint the specification promises is present, every $ref resolves,
// and every state-changing operation actually requires an idempotency key.
// A definition that references a schema file that does not exist is worse than
// no definition, because tooling generates clients from it.
package openapi

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rodmontiel/uai/internal/testvectors"
)

// CaseResult is one check.
type CaseResult struct {
	Name   string
	OK     bool
	Detail string
}

// Result is the outcome of checking the definition.
type Result struct {
	File      string
	Version   string
	Paths     int
	Cases     []CaseResult
	LoadError error
}

// Failures returns the checks that did not pass.
func (r Result) Failures() []CaseResult {
	var out []CaseResult
	for _, c := range r.Cases {
		if !c.OK {
			out = append(out, c)
		}
	}
	return out
}

// OK reports whether the definition passed every check.
func (r Result) OK() bool { return r.LoadError == nil && len(r.Failures()) == 0 }

// File returns the absolute path of the OpenAPI definition.
func File() string {
	return filepath.Join(testvectors.Root(), "spec", "openapi", "uai-v1.yaml")
}

// requiredPaths are the endpoints docs/protocol/15-api.md section 22.2 commits
// to. Removing one from the definition without removing it from the
// specification is a divergence this check exists to catch.
var requiredPaths = []string{
	"/agents",
	"/agents/{id}",
	"/agents/{id}/credentials",
	"/agents/{id}/bind",
	"/agents/{id}/unbind",
	"/agents/{id}/rebind",
	"/passports/request",
	"/passports/{id}",
	"/policy/evaluate",
	"/actions/attest",
	"/actions/{eventId}",
	"/suspicions",
	"/cases/{id}",
	"/quarantines",
	// Against a proposal, not a case: a case may carry more than one proposal,
	// and a vote addressed to the case would be ambiguous the first time it does.
	"/governance/proposals/{id}/vote",
	"/governance/proposals/{id}",
	"/revocations/{decisionId}",
	"/revocations/{decisionId}/execute",
	"/verify/{uaiId}",
	// What an independent verifier needs (§5.1). Listed as required because a
	// build that served everything else and not these would be a build nobody
	// could audit without trusting it.
	"/agents/{id}/did.json",
	"/log/checkpoint",
	"/trust-anchors",
}

// idempotencyExempt lists the state-changing operations that deliberately do
// NOT take an idempotency key, per docs/protocol/15-api.md section 22.6.
//
// Policy evaluation is the only one. Each evaluation is genuinely a new
// request: the SDK calls it before every action, and two evaluations of the
// same intent at different moments can legitimately reach different decisions
// because the policy bundle, the passport state or the agent's status may have
// changed in between. Collapsing them under an idempotency key would return a
// stale decision, which is worse than an extra record.
var idempotencyExempt = map[string]bool{
	"post /policy/evaluate": true,
}

// unauthenticatedPaths are public by design: verification must survive being
// linked from a public page.
var unauthenticatedPaths = map[string]bool{
	"/verify/{uaiId}": true,
	"/log/checkpoint": true,
	"/log/proof":      true,
}

func pass(name string) CaseResult { return CaseResult{Name: name, OK: true} }

func fail(name, format string, args ...any) CaseResult {
	return CaseResult{Name: name, OK: false, Detail: fmt.Sprintf(format, args...)}
}

// Check parses and validates the definition.
func Check() Result {
	r := Result{File: "spec/openapi/uai-v1.yaml"}
	raw, err := os.ReadFile(File())
	if err != nil {
		r.LoadError = err
		return r
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		r.LoadError = fmt.Errorf("parse: %w", err)
		return r
	}

	version, _ := doc["openapi"].(string)
	r.Version = version
	if strings.HasPrefix(version, "3.1") {
		r.Cases = append(r.Cases, pass("declares OpenAPI 3.1"))
	} else {
		r.Cases = append(r.Cases, fail("declares OpenAPI 3.1", "openapi = %q", version))
	}

	paths, _ := doc["paths"].(map[string]any)
	r.Paths = len(paths)
	if len(paths) == 0 {
		r.Cases = append(r.Cases, fail("defines paths", "no paths declared"))
		return r
	}

	// Every endpoint the specification commits to must exist.
	var missing []string
	for _, p := range requiredPaths {
		if _, ok := paths[p]; !ok {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		r.Cases = append(r.Cases, pass(fmt.Sprintf("all %d specified endpoints present", len(requiredPaths))))
	} else {
		sort.Strings(missing)
		r.Cases = append(r.Cases, fail("all specified endpoints present",
			"missing from the definition: %s", strings.Join(missing, ", ")))
	}

	// Every $ref must resolve, locally or to a schema file that exists.
	var unresolved []string
	walkRefs(doc, func(ref string) {
		if !resolves(ref, doc) {
			unresolved = append(unresolved, ref)
		}
	})
	if len(unresolved) == 0 {
		r.Cases = append(r.Cases, pass("every $ref resolves"))
	} else {
		sort.Strings(unresolved)
		r.Cases = append(r.Cases, fail("every $ref resolves", "unresolved: %s", strings.Join(dedupe(unresolved), ", ")))
	}

	// Every state-changing operation requires an idempotency key. Registration,
	// binding, attestation and voting are all expensive and all retried.
	var noIdem []string
	for path, item := range paths {
		ops, _ := item.(map[string]any)
		for method, op := range ops {
			if method != "post" && method != "put" && method != "patch" {
				continue
			}
			if idempotencyExempt[method+" "+path] {
				continue
			}
			if !hasIdempotencyKey(op) {
				noIdem = append(noIdem, method+" "+path)
			}
		}
	}
	if len(noIdem) == 0 {
		r.Cases = append(r.Cases, pass(fmt.Sprintf(
			"state-changing operations require an idempotency key (%d documented exemption(s))", len(idempotencyExempt))))
	} else {
		sort.Strings(noIdem)
		r.Cases = append(r.Cases, fail("state-changing operations require an idempotency key",
			"missing on: %s", strings.Join(noIdem, ", ")))
	}

	// The public verification surface must be explicitly unauthenticated.
	var notPublic []string
	for path := range unauthenticatedPaths {
		item, ok := paths[path].(map[string]any)
		if !ok {
			continue
		}
		get, ok := item["get"].(map[string]any)
		if !ok {
			continue
		}
		sec, present := get["security"]
		if !present {
			notPublic = append(notPublic, path)
			continue
		}
		if list, ok := sec.([]any); !ok || len(list) != 0 {
			notPublic = append(notPublic, path)
		}
	}
	if len(notPublic) == 0 {
		r.Cases = append(r.Cases, pass("public verification endpoints are unauthenticated"))
	} else {
		sort.Strings(notPublic)
		r.Cases = append(r.Cases, fail("public verification endpoints are unauthenticated",
			"still require auth: %s", strings.Join(notPublic, ", ")))
	}

	return r
}

func hasIdempotencyKey(op any) bool {
	m, ok := op.(map[string]any)
	if !ok {
		return false
	}
	params, _ := m["parameters"].([]any)
	for _, p := range params {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if ref, ok := pm["$ref"].(string); ok && strings.HasSuffix(ref, "/IdempotencyKey") {
			return true
		}
		if name, ok := pm["name"].(string); ok && name == "Idempotency-Key" {
			return true
		}
	}
	return false
}

// walkRefs visits every $ref value in the document.
func walkRefs(node any, visit func(string)) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "$ref" {
				if s, ok := v.(string); ok {
					visit(s)
					continue
				}
			}
			walkRefs(v, visit)
		}
	case []any:
		for _, v := range n {
			walkRefs(v, visit)
		}
	}
}

// resolves reports whether a $ref points at something that exists.
func resolves(ref string, doc map[string]any) bool {
	if strings.HasPrefix(ref, "#/") {
		cur := any(doc)
		for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			m, ok := cur.(map[string]any)
			if !ok {
				return false
			}
			cur, ok = m[seg]
			if !ok {
				return false
			}
		}
		return true
	}
	// A relative file reference, e.g. ../schemas/action-attestation.schema.json
	path, _, _ := strings.Cut(ref, "#")
	full := filepath.Join(filepath.Dir(File()), filepath.FromSlash(path))
	_, err := os.Stat(full)
	return err == nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
