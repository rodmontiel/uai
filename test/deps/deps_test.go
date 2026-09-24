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

// TestTheSDKsAndMCPHaveNoExternalDependencies is ADR-0004 as a build gate.
//
// sdk/go and mcp/ run inside the agent's process and hold, or can reach, its
// signing key. A compromised transitive dependency of a web framework
// exfiltrates data; a compromised transitive dependency here SIGNS, and what it
// signs is indistinguishable from what the agent meant to sign, forever.
//
// The Python and TypeScript SDKs are held to the same rule by their own tests
// and manifests: sdk/typescript/test/types.test.mjs asserts an empty dependency
// set and that nothing outside node: builtins is imported.
func TestTheSDKsAndMCPHaveNoExternalDependencies(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not available: %v", err)
	}
	for _, pattern := range []string{
		"github.com/rodmontiel/uai/sdk/...",
		"github.com/rodmontiel/uai/mcp/...",
	} {
		t.Run(pattern, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", pattern)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list failed: %v\n%s", err, stderr.String())
			}
			deps := strings.Fields(string(out))
			if len(deps) == 0 {
				t.Fatal("go list returned no packages: the guard did not actually inspect anything")
			}
			const modulePrefix = "github.com/rodmontiel/uai/"
			var offenders []string
			for _, dep := range deps {
				switch {
				case strings.HasPrefix(dep, modulePrefix):
					continue
				case !strings.Contains(strings.SplitN(dep, "/", 2)[0], "."):
					continue // standard library
				default:
					offenders = append(offenders, dep)
				}
			}
			if len(offenders) > 0 {
				t.Fatalf("%s must not depend on anything outside the standard library.\n"+
					"Found: %s\n"+
					"This code holds the agent's signing key. A dependency here is a dependency "+
					"that could sign on the agent's behalf (ADR-0004).",
					pattern, strings.Join(offenders, ", "))
			}
		})
	}
}
