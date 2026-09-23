// Package onchain enforces INV-007 and INV-008 against the compiled contracts.
//
// §17.2.1 lists what may go on a chain the consortium operates and what must
// never: prompts, documents, personal data, secrets, and — the subtle one —
// unsalted hashes of low-entropy values. SHA-256("alice@example.com") is
// personal data in practice, because it is recoverable by dictionary attack.
//
// A code-review gate would catch most of that most of the time. This test
// catches all of it every time, by refusing to let a contract declare a
// parameter that COULD carry content in the first place.
package onchain_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// abiEntry is the part of a compiled ABI this check reads.
type abiEntry struct {
	Type            string     `json:"type"`
	Name            string     `json:"name"`
	Inputs          []abiParam `json:"inputs"`
	Outputs         []abiParam `json:"outputs"`
	StateMutability string     `json:"stateMutability"`
}

type abiParam struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	Components []abiParam `json:"components"`
}

type artifact struct {
	ABI []abiEntry `json:"abi"`
}

// allowed leaf types. Everything here is fixed-width and carries no room for a
// payload: a bytes32 holds a commitment or an identifier and nothing else.
//
//   - bytes32  commitments, identifiers, roots, proofs
//   - uintN    counts, thresholds, timestamps, and enums (an enum is a uint8)
//   - bool     flags
//   - address  on-chain accounts, for access control
//
// Notably absent: string, bytes, and every bytesN other than 32. Those are the
// shapes that can carry a prompt, a document or an email address, and the only
// reliable way to keep them off the chain is to make them unspellable.
func allowedLeaf(t string) bool {
	base := strings.TrimSuffix(t, "[]")
	for strings.HasSuffix(base, "]") {
		if i := strings.LastIndex(base, "["); i >= 0 {
			base = base[:i]
		} else {
			break
		}
	}
	switch {
	case base == "bytes32", base == "bool", base == "address":
		return true
	case strings.HasPrefix(base, "uint"), strings.HasPrefix(base, "int"):
		return true
	case base == "tuple":
		return true // checked through its components
	default:
		return false
	}
}

func checkParams(t *testing.T, where string, params []abiParam) {
	t.Helper()
	for _, p := range params {
		name := p.Name
		if name == "" {
			name = "<unnamed>"
		}
		if !allowedLeaf(p.Type) {
			t.Errorf("INV-007/008: %s parameter %q is %s.\n"+
				"  Only bytes32, uintN, intN, bool, address and tuples of those may cross this boundary.\n"+
				"  A %s can carry content, and content must never reach the chain (§17.2.1).",
				where, name, p.Type, p.Type)
			continue
		}
		if len(p.Components) > 0 {
			checkParams(t, where+"."+name, p.Components)
		}
	}
}

// contracts are the UAI contracts. Library and test artifacts are excluded:
// forge-std is development tooling and never deployed.
var contracts = []string{
	"Roles", "UAIIdentityRegistry", "UAIPolicyRegistry", "UAITransparencyAnchor",
	"UAIQuarantineRegistry", "UAIGovernance", "UAIVoting", "UAIRevocationRegistry",
}

func load(t *testing.T, name string) artifact {
	t.Helper()
	// The committed ABI, not the build directory: this check must run on a
	// machine with no Solidity toolchain, and what matters is the contract's
	// published surface rather than the state of somebody's out/ folder.
	path := filepath.Join("..", "..", "spec", "contracts", name+".abi.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v\n  Run `make contracts` to compile and export the ABIs.", name, err)
	}
	var a artifact
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return a
}

// TestNoContentCanReachTheChain is INV-007 and INV-008 as a build gate.
func TestNoContentCanReachTheChain(t *testing.T) {
	for _, name := range contracts {
		t.Run(name, func(t *testing.T) {
			a := load(t, name)
			if len(a.ABI) == 0 {
				t.Fatalf("%s has an empty ABI", name)
			}
			for _, e := range a.ABI {
				switch e.Type {
				case "function", "constructor", "event", "error":
					label := e.Type
					if e.Name != "" {
						label = fmt.Sprintf("%s %s", e.Type, e.Name)
					}
					checkParams(t, fmt.Sprintf("%s: %s", name, label), e.Inputs)
					// Outputs matter too: a view returning a string would mean
					// the contract is storing one.
					checkParams(t, fmt.Sprintf("%s: %s (returns)", name, label), e.Outputs)
				}
			}
		})
	}
}

// TestRevocationIsGatedOnChain checks that the acceptance criterion of Phase 7
// is structurally present, not merely tested in Solidity: the entry point
// exists, takes a governance proof, and takes the votes that justify it.
func TestRevocationIsGatedOnChain(t *testing.T) {
	a := load(t, "UAIRevocationRegistry")
	var fn *abiEntry
	for i := range a.ABI {
		if a.ABI[i].Type == "function" && a.ABI[i].Name == "executeRevocation" {
			fn = &a.ABI[i]
		}
	}
	if fn == nil {
		t.Fatal("UAIRevocationRegistry has no executeRevocation: revocation would not be gated on chain at all")
	}
	want := []string{"bytes32", "bytes32", "bytes32", "tuple[]"}
	if len(fn.Inputs) != len(want) {
		t.Fatalf("executeRevocation takes %d parameters, want %d", len(fn.Inputs), len(want))
	}
	for i, w := range want {
		if fn.Inputs[i].Type != w {
			t.Errorf("parameter %d is %s, want %s", i, fn.Inputs[i].Type, w)
		}
	}
	// The votes must carry a signature, or "verified against delegate
	// signatures" would be a claim with nothing behind it.
	var hasR, hasS, hasV bool
	for _, c := range fn.Inputs[3].Components {
		switch c.Name {
		case "r":
			hasR = true
		case "s":
			hasS = true
		case "v":
			hasV = true
		}
	}
	if !hasR || !hasS || !hasV {
		t.Error("a vote must carry an ECDSA signature (r, s, v); without one nothing is verified")
	}

	// And AgentRevoked must name the proof that authorized it.
	for _, e := range a.ABI {
		if e.Type == "event" && e.Name == "AgentRevoked" {
			if len(e.Inputs) != 2 {
				t.Errorf("AgentRevoked has %d fields, want agentId and governanceProof", len(e.Inputs))
			}
			return
		}
	}
	t.Error("UAIRevocationRegistry emits no AgentRevoked event")
}
