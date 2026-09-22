// Command uai-conformance runs the normative UAI test vectors against this
// implementation and reports the result.
//
// It exists so that conformance can be checked without a Go test runner, and
// so that an implementation in another language has a reference for what a
// conformance run must cover. Exit status is 0 only when every case passes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rodmontiel/uai/internal/conformance"
	"github.com/rodmontiel/uai/internal/openapi"
	"github.com/rodmontiel/uai/internal/schemas"
	"github.com/rodmontiel/uai/internal/testvectors"
)

func main() {
	asJSON := flag.Bool("json", false, "emit machine-readable JSON")
	verbose := flag.Bool("v", false, "list every case, not only failures")
	flag.Parse()

	results := conformance.All()

	if *asJSON {
		emitJSON(results)
		return
	}

	fmt.Printf("UAI conformance — vectors from %s\n\n", testvectors.Dir())
	total, passed, failedSets := 0, 0, 0
	for _, r := range results {
		if r.LoadError != nil {
			failedSets++
			fmt.Printf("  FAIL  %-28s could not load %s: %v\n", r.Set, r.File, r.LoadError)
			continue
		}
		failures := r.Failures()
		total += len(r.Cases)
		passed += len(r.Cases) - len(failures)
		status := "ok  "
		if len(failures) > 0 {
			status = "FAIL"
			failedSets++
		}
		fmt.Printf("  %s  %-28s %3d/%-3d cases\n", status, r.Set, len(r.Cases)-len(failures), len(r.Cases))
		for _, c := range failures {
			fmt.Printf("          %s\n            %s\n", c.Name, c.Detail)
		}
		if *verbose {
			for _, c := range r.Cases {
				if c.OK {
					fmt.Printf("          ok  %s\n", c.Name)
				}
			}
		}
	}

	// Schemas and the API definition are part of conformance: an implementation
	// that reproduces the crypto vectors but accepts a malformed attestation is
	// not interoperable.
	fmt.Printf("\n  -- JSON Schemas --\n")
	for _, r := range schemas.Validate() {
		if r.LoadError != nil {
			failedSets++
			fmt.Printf("  FAIL  %-28s %v\n", r.Schema, r.LoadError)
			continue
		}
		failures := r.Failures()
		total += len(r.Cases)
		passed += len(r.Cases) - len(failures)
		status := "ok  "
		if len(failures) > 0 {
			status = "FAIL"
			failedSets++
		}
		fmt.Printf("  %s  %-28s %3d/%-3d examples\n", status, r.Schema, len(r.Cases)-len(failures), len(r.Cases))
		for _, c := range failures {
			fmt.Printf("          %s\n            %s\n", c.Name, c.Detail)
		}
	}

	fmt.Printf("\n  -- OpenAPI --\n")
	oa := openapi.Check()
	if oa.LoadError != nil {
		failedSets++
		fmt.Printf("  FAIL  %-28s %v\n", "openapi", oa.LoadError)
	} else {
		failures := oa.Failures()
		total += len(oa.Cases)
		passed += len(oa.Cases) - len(failures)
		status := "ok  "
		if len(failures) > 0 {
			status = "FAIL"
			failedSets++
		}
		fmt.Printf("  %s  %-28s %3d/%-3d checks (%d paths)\n", status, "openapi "+oa.Version,
			len(oa.Cases)-len(failures), len(oa.Cases), oa.Paths)
		for _, c := range failures {
			fmt.Printf("          %s\n            %s\n", c.Name, c.Detail)
		}
	}

	fmt.Printf("\n%d/%d checks passed\n", passed, total)
	if failedSets > 0 {
		fmt.Fprintf(os.Stderr, "\n%d vector set(s) failed — this build is NOT conformant with UAI v0.1\n", failedSets)
		os.Exit(1)
	}
	fmt.Println("conformant with UAI v0.1")
}

func emitJSON(results []conformance.Result) {
	type caseOut struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail,omitempty"`
	}
	type setOut struct {
		Set       string    `json:"set"`
		File      string    `json:"file"`
		OK        bool      `json:"ok"`
		LoadError string    `json:"load_error,omitempty"`
		Cases     []caseOut `json:"cases"`
	}
	out := struct {
		UAIVersion string   `json:"uai_version"`
		OK         bool     `json:"ok"`
		Sets       []setOut `json:"sets"`
	}{UAIVersion: "0.1", OK: true}

	for _, r := range results {
		s := setOut{Set: r.Set, File: r.File, OK: r.OK()}
		if r.LoadError != nil {
			s.LoadError = r.LoadError.Error()
		}
		for _, c := range r.Cases {
			s.Cases = append(s.Cases, caseOut{Name: c.Name, OK: c.OK, Detail: c.Detail})
		}
		if !s.OK {
			out.OK = false
		}
		out.Sets = append(out.Sets, s)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "uai-conformance: %v\n", err)
		os.Exit(1)
	}
	if !out.OK {
		os.Exit(1)
	}
}
