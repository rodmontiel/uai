// Package schemas compiles the UAI JSON Schemas and validates the committed
// examples against them.
//
// Both directions are checked. Valid examples MUST pass, and invalid examples
// MUST fail: a schema that never rejects anything validates nothing, and the
// invalid examples are where the protocol's constraints are actually pinned —
// a vote without user verification, a quarantine without an expiry, a suspicion
// that records a verdict.
//
// This package depends on a JSON Schema library. That is acceptable here
// because it is tooling: pkg/ stays dependency-free because it sits on the
// verification path (threat T-07).
package schemas

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rodmontiel/uai/internal/testvectors"
)

// BaseURI is the namespace every UAI schema declares in its $id.
const BaseURI = "https://uai.world/schemas/v0.1/"

// CaseResult is the outcome of validating one example.
type CaseResult struct {
	Name   string
	OK     bool
	Detail string
}

// Result is the outcome for one schema.
type Result struct {
	Schema    string
	File      string
	Title     string
	Cases     []CaseResult
	LoadError error
}

// Failures returns the cases that did not pass.
func (r Result) Failures() []CaseResult {
	var out []CaseResult
	for _, c := range r.Cases {
		if !c.OK {
			out = append(out, c)
		}
	}
	return out
}

// OK reports whether the schema and all of its examples behaved as required.
func (r Result) OK() bool { return r.LoadError == nil && len(r.Failures()) == 0 }

// Dir returns the absolute path of spec/schemas.
func Dir() string { return filepath.Join(testvectors.Root(), "spec", "schemas") }

// Validate compiles every schema and checks every committed example.
func Validate() []Result {
	dir := Dir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []Result{{Schema: "spec/schemas", LoadError: err}}
	}

	compiler := jsonschema.NewCompiler()
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".schema.json") {
			continue
		}
		doc, err := loadJSON(filepath.Join(dir, e.Name()))
		if err != nil {
			return []Result{{Schema: e.Name(), LoadError: err}}
		}
		// Register under the $id the schema declares, so that relative $refs
		// such as "common.schema.json#/$defs/sha256Digest" resolve without any
		// network access.
		if err := compiler.AddResource(BaseURI+e.Name(), doc); err != nil {
			return []Result{{Schema: e.Name(), LoadError: err}}
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var results []Result
	for _, name := range names {
		stem := strings.TrimSuffix(name, ".schema.json")
		r := Result{Schema: stem, File: "spec/schemas/" + name}

		sch, err := compiler.Compile(BaseURI + name)
		if err != nil {
			r.LoadError = fmt.Errorf("compile: %w", err)
			results = append(results, r)
			continue
		}
		r.Title = sch.Title

		exDir := filepath.Join(dir, "examples", stem)
		if _, err := os.Stat(exDir); os.IsNotExist(err) {
			// common.schema.json holds only $defs and has no instances.
			if stem != "common" {
				r.Cases = append(r.Cases, CaseResult{
					Name: "examples present", OK: false,
					Detail: "no examples committed: a schema with no examples is untested",
				})
			}
			results = append(results, r)
			continue
		}

		reasons := loadReasons(filepath.Join(exDir, "reasons.json"))
		r.Cases = append(r.Cases, checkDir(sch, filepath.Join(exDir, "valid"), true, nil)...)
		r.Cases = append(r.Cases, checkDir(sch, filepath.Join(exDir, "invalid"), false, reasons)...)
		results = append(results, r)
	}
	return results
}

func checkDir(sch *jsonschema.Schema, dir string, mustPass bool, reasons map[string]string) []CaseResult {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []CaseResult
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		stem := strings.TrimSuffix(e.Name(), ".json")
		label := stem
		if mustPass {
			label = "valid/" + stem
		} else {
			label = "invalid/" + stem
		}
		doc, err := loadJSON(filepath.Join(dir, e.Name()))
		if err != nil {
			out = append(out, CaseResult{Name: label, OK: false, Detail: err.Error()})
			continue
		}
		verr := sch.Validate(doc)
		switch {
		case mustPass && verr != nil:
			out = append(out, CaseResult{Name: label, OK: false,
				Detail: "example should validate but does not: " + firstLine(verr.Error())})
		case !mustPass && verr == nil:
			detail := "example should be REJECTED but validated"
			if why, ok := reasons[stem]; ok {
				detail += ": " + why
			}
			out = append(out, CaseResult{Name: label, OK: false, Detail: detail})
		default:
			out = append(out, CaseResult{Name: label, OK: true})
		}
	}
	return out
}

func loadJSON(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return doc, nil
}

func loadReasons(path string) map[string]string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
