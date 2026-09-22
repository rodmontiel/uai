package deps_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// TestPkgHasNoExternalDependencies enforces the rule that pkg/ imports nothing
// outside the Go standard library.
//
// pkg/ sits on the verification path: it is what a relying party runs to decide
// whether an attestation is genuine. Every dependency there is supply-chain
// attack surface (threat T-07), and an auditor should be able to read the whole
// verification core without following a dependency tree.
//
// Tooling under tools/ and internal/ may depend on third-party libraries. This
// test deliberately does not constrain them.
func TestPkgHasNoExternalDependencies(t *testing.T) {
	// The pattern is module-qualified, not "./pkg/...": a test runs with its
	// own package directory as the working directory, so a relative pattern
	// would resolve to test/deps/pkg and silently match nothing.
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not available: %v", err)
	}
	cmd := exec.Command("go", "list", "-deps", "github.com/rodmontiel/uai/pkg/...")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		// A failure here must not degrade to a skip. A guard test that quietly
		// passes when it could not run is worse than no guard at all.
		t.Fatalf("go list failed: %v\n%s", err, stderr.String())
	}
	if len(strings.Fields(string(out))) == 0 {
		t.Fatal("go list returned no packages: the guard did not actually inspect pkg/")
	}

	const modulePrefix = "github.com/rodmontiel/uai/"
	var offenders []string
	for _, dep := range strings.Fields(string(out)) {
		switch {
		case strings.HasPrefix(dep, modulePrefix):
			continue // our own packages
		case !strings.Contains(strings.SplitN(dep, "/", 2)[0], "."):
			continue // no dot in the first segment means standard library
		default:
			offenders = append(offenders, dep)
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("pkg/ must not depend on anything outside the standard library.\n"+
			"Found: %s\n"+
			"If a dependency is genuinely required here, it needs an explicit decision record: "+
			"this code is what a relying party runs to verify evidence.",
			strings.Join(offenders, ", "))
	}
}
