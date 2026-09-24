// Package invariants checks that the security invariants of §20.3 are actually
// tested, and tested in more than one place.
//
// The threat model ends with a sentence that is easy to write and easy to stop
// being true: "Each invariant has a corresponding negative test in the test
// suite." When this gate was first written, that sentence was false for INV-001
// and INV-010 -- the first had no test anywhere, and the second was enforced by
// nine Solidity tests that no reader could connect to it, because nothing in
// them said so.
//
// So the claim is checked mechanically. An invariant is covered when a TEST
// file names it. §20.3 also claims each one is "enforced at more than one
// layer, so that a single compromised layer does not break it" -- and that is
// the stronger claim, because it is the one that survives a compromise. Both
// are enforced here.
package invariants_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The layers an invariant can be defended at. They are deliberately coarse:
// what matters is that two of them would have to fail together, not how the
// repository happens to be laid out.
const (
	layerDatabase    = "database"    // constraints, triggers, grants
	layerApplication = "application" // the Go services and packages
	layerContract    = "contract"    // Solidity, and the ABI surface it exposes
	layerClient      = "client"      // what a relying party runs: SDKs, browser
)

// layerOf places a test file. Returns "" for files that are not tests.
func layerOf(rel string) string {
	switch {
	// This file names every invariant in its own prose. Counting that as
	// coverage would make the gate report itself as the defence -- which is
	// precisely the substitution of text for enforcement it exists to catch.
	case rel == "test/invariants/coverage_test.go":
		return ""
	case rel == "test/invariants/invariants.sql":
		return layerDatabase
	case strings.HasPrefix(rel, "contracts/test/") && strings.HasSuffix(rel, ".t.sol"):
		return layerContract
	// The ABI gate is Go, but what it audits is the contract's published
	// surface: if it fails, a contract changed, not a service.
	case strings.HasPrefix(rel, "test/onchain/"):
		return layerContract
	case strings.HasPrefix(rel, "test/web/"), strings.HasPrefix(rel, "sdk/"):
		return layerClient
	case strings.HasSuffix(rel, "_test.go"):
		return layerApplication
	case strings.HasSuffix(rel, ".test.mjs"), strings.HasSuffix(rel, "_test.py"):
		return layerClient
	}
	return ""
}

var (
	invRE = regexp.MustCompile(`INV-0\d\d`)
	// §20.3's table rows: | **INV-001** ... |
	rowRE = regexp.MustCompile(`\|\s*\*\*(INV-0\d\d)\*\*`)
)

// repoRoot walks up until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

// declared reads the invariants out of the threat model rather than hardcoding
// them. Adding INV-011 to §20.3 makes this test fail until INV-011 has tests,
// which is the direction the enforcement has to run: the document is the claim,
// and the claim is what gets checked.
func declared(t *testing.T, root string) []string {
	t.Helper()
	path := filepath.Join(root, "docs/protocol/13-threat-model.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the threat model is the source of this list: %v", err)
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range rowRE.FindAllStringSubmatch(string(b), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	if len(out) == 0 {
		t.Fatalf("no invariant rows found in %s; §20.3's table shape changed", path)
	}
	sort.Strings(out)
	return out
}

// coverage maps each invariant to the layers whose tests name it, and to the
// files themselves so a failure can say where to look.
func coverage(t *testing.T, root string) (map[string]map[string][]string, error) {
	t.Helper()
	cov := map[string]map[string][]string{}
	skip := map[string]bool{
		".git": true, "node_modules": true, "graphify-out": true,
		"lib": true, "out": true, "cache": true, ".keys": true,
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		layer := layerOf(filepath.ToSlash(rel))
		if layer == "" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, id := range invRE.FindAllString(string(b), -1) {
			if cov[id] == nil {
				cov[id] = map[string][]string{}
			}
			files := cov[id][layer]
			if len(files) == 0 || files[len(files)-1] != rel {
				cov[id][layer] = append(files, rel)
			}
		}
		return nil
	})
	return cov, err
}

// TestEveryInvariantHasANegativeTest is §20.3's closing sentence as a gate.
func TestEveryInvariantHasANegativeTest(t *testing.T) {
	root := repoRoot(t)
	cov, err := coverage(t, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range declared(t, root) {
		if len(cov[inv]) == 0 {
			t.Errorf("%s is declared in §20.3 and no test names it.\n"+
				"An invariant nobody asserts is a paragraph, not a control.\n"+
				"Write the negative test -- the one that asserts the forbidden\n"+
				"operation FAILS -- and put %q in its name or its comment.", inv, inv)
		}
	}
}

// TestEveryInvariantIsDefendedTwice is the stronger claim: "enforced at more
// than one layer, so that a single compromised layer does not break it".
//
// One layer is not a defence in depth argument, it is a single point of
// failure with a test. Where a second layer genuinely cannot exist, the
// exemption is recorded below with its reason -- visible, countable, and
// requiring an edit to this file rather than silence.
func TestEveryInvariantIsDefendedTwice(t *testing.T) {
	// Exemptions. Each one is a place where §20.3's own table names a single
	// enforcement point, so a second test would be theatre.
	exempt := map[string]string{}

	root := repoRoot(t)
	cov, err := coverage(t, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range declared(t, root) {
		layers := make([]string, 0, len(cov[inv]))
		for l := range cov[inv] {
			layers = append(layers, l)
		}
		sort.Strings(layers)
		if len(layers) >= 2 {
			continue
		}
		if why, ok := exempt[inv]; ok {
			t.Logf("%s is tested at one layer only: %s", inv, why)
			continue
		}
		t.Errorf("%s is tested at %d layer(s): %v\n"+
			"§20.3 says every invariant is enforced at more than one layer.\n"+
			"Either add the test that proves the second layer refuses it too,\n"+
			"or record an exemption in this file saying why there is only one.",
			inv, len(layers), layers)
	}
}

// TestCoverageIsReported prints the matrix. It never fails: its job is to make
// the shape of the defence readable in CI output, next to the two tests above
// that do fail.
func TestCoverageIsReported(t *testing.T) {
	root := repoRoot(t)
	cov, err := coverage(t, root)
	if err != nil {
		t.Fatal(err)
	}
	all := []string{layerDatabase, layerApplication, layerContract, layerClient}
	t.Logf("%-9s %-10s %-12s %-10s %s", "invariant", all[0], all[1], all[2], all[3])
	for _, inv := range declared(t, root) {
		cells := make([]string, len(all))
		for i, l := range all {
			if n := len(cov[inv][l]); n > 0 {
				cells[i] = strings.Repeat("*", min(n, 3))
			} else {
				cells[i] = "-"
			}
		}
		t.Logf("%-9s %-10s %-12s %-10s %s", inv, cells[0], cells[1], cells[2], cells[3])
	}
}
