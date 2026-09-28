// The practical example is a document of commands, and a command that stopped
// existing reads exactly like one that still works.
//
// A reader following it cannot tell a renamed Make target from a typo of their
// own, and will assume the fault is theirs. So every command the document tells
// someone to run is checked here against the repository: the tool exists, the
// target exists, the script exists, and every flag is one the tool actually
// defines.
//
// What this does NOT check is that the commands produce the output shown. That
// needs a running stack, and lives in `make walkthrough`.
package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const example = "../../docs/Ejemplo_Practico_es.md"

var (
	// Commands inside fenced blocks, at the start of a line or after a pipe.
	goRunRE  = regexp.MustCompile(`go (?:run|build -o \S+) (\./[\w./-]+)`)
	makeRE   = regexp.MustCompile(`(?m)^\s*(?:@|&& )?make ([a-z][a-z0-9-]*)`)
	scriptRE = regexp.MustCompile(`\./(tools/[\w.-]+\.sh)`)
	docLinkRE = regexp.MustCompile(`\]\((?:\./)?([A-Za-z0-9_.-]+\.md)\)`)
	// A flag as written in the document: `-name` or `-name value`.
	flagRE = regexp.MustCompile(`(?:^|\s)-([a-z][a-z0-9-]*)`)
)

func exampleText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(example)
	if err != nil {
		t.Fatalf("the practical example must exist: %v", err)
	}
	return string(b)
}

// TestEveryToolTheExampleNamesExists guards against a document that points at a
// command nobody can run any more.
func TestEveryToolTheExampleNamesExists(t *testing.T) {
	for _, m := range goRunRE.FindAllStringSubmatch(exampleText(t), -1) {
		pkg := strings.TrimPrefix(m[1], "./")
		if _, err := os.Stat(filepath.Join("../..", pkg)); err != nil {
			t.Errorf("the example runs `go ... %s`, and that package is not in this repo", m[1])
		}
	}
}

// TestEveryMakeTargetTheExampleNamesExists: a renamed target is invisible to a
// reader, who reads "make: *** No rule to make target" as their own mistake.
func TestEveryMakeTargetTheExampleNamesExists(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range makeRE.FindAllStringSubmatch(exampleText(t), -1) {
		target := m[1]
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(target) + `:`).Match(makefile) {
			t.Errorf("the example runs `make %s`, and the Makefile has no such target", target)
		}
	}
}

// TestEveryScriptTheExampleNamesIsExecutable. A script that lost its bit fails
// with "Permission denied", which names nothing.
func TestEveryScriptTheExampleNamesIsExecutable(t *testing.T) {
	for _, m := range scriptRE.FindAllStringSubmatch(exampleText(t), -1) {
		path := filepath.Join("../..", m[1])
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("the example runs `./%s`, which is not in this repo", m[1])
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Errorf("./%s is not executable, so the example's command fails with "+
				"\"Permission denied\"", m[1])
		}
	}
}

// TestEveryFlagTheExampleUsesIsDefined is the check that catches the quiet
// failure: a flag removed from a tool makes Go's flag package print usage and
// exit 2, with no hint that the flag it rejected is the one the document
// supplied.
func TestEveryFlagTheExampleUsesIsDefined(t *testing.T) {
	// Which tool each command line belongs to, and the source that defines it.
	sources := map[string][]string{
		"uai-register": {"tools/uai-register/main.go"},
		"uai-grant":    {"tools/uai-grant/main.go"},
		"uai-verify":   {"tools/uai-verify/main.go"},
		"uai-keygen":   {"tools/uai-keygen/main.go"},
		"uai-mcp":      {"mcp/main.go"},
	}
	defined := map[string]map[string]bool{}
	for tool, paths := range sources {
		defined[tool] = map[string]bool{}
		for _, p := range paths {
			body, err := os.ReadFile(filepath.Join("../..", p))
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			for _, m := range regexp.MustCompile(
				`(?:flag|fs)\.(?:String|Bool|Int|Duration)\("([a-z][a-z0-9-]*)"`,
			).FindAllStringSubmatch(string(body), -1) {
				defined[tool][m[1]] = true
			}
		}
	}

	// Continuation lines first. Almost every command in the document is written
	// across several lines with a trailing backslash, so a check that looked at
	// one line at a time examined the invocation and never its flags -- and
	// passed while the document told people to pass a flag that does not exist.
	for _, line := range joinContinuations(exampleText(t)) {
		trimmed := strings.TrimSpace(line)
		// Only lines that invoke one of these tools, and not prose about them.
		var tool string
		for name := range sources {
			if strings.Contains(trimmed, "./tools/"+name) || strings.Contains(trimmed, "/"+name+" -") {
				tool = name
				break
			}
		}
		if tool == "" {
			continue
		}
		for _, m := range flagRE.FindAllStringSubmatch(trimmed, -1) {
			flag := m[1]
			// A word after a hyphen inside a value, not a flag.
			if strings.Contains(trimmed, "'"+"-"+flag) {
				continue
			}
			if !defined[tool][flag] {
				t.Errorf("the example passes -%s to %s, which does not define that flag.\n"+
					"  line: %s", flag, tool, trimmed)
			}
		}
	}
}

// TestTheExampleLinksToDocumentsThatExist.
func TestTheExampleLinksToDocumentsThatExist(t *testing.T) {
	for _, m := range docLinkRE.FindAllStringSubmatch(exampleText(t), -1) {
		if _, err := os.Stat(filepath.Join("../../docs", m[1])); err != nil {
			t.Errorf("the example links to %s, which is not in docs/", m[1])
		}
	}
}

// TestTheExampleDoesNotPromiseAKillSwitch. The one claim this project must
// never make, in the one document a newcomer reads end to end.
func TestTheExampleDoesNotPromiseAKillSwitch(t *testing.T) {
	body := strings.ToLower(exampleText(t))
	for _, phrase := range []string{"kill switch", "apaga el agente", "detiene al agente",
		"lo desconecta", "deja de funcionar el agente"} {
		if strings.Contains(body, phrase) {
			t.Errorf("the example contains %q. Revocation is participants declining to honour "+
				"a credential; nothing here stops a process.", phrase)
		}
	}
	if !strings.Contains(body, "revocar no apaga nada") {
		t.Error("the example must say plainly that revocation stops nothing")
	}
}

// joinContinuations folds shell line continuations into one line each.
func joinContinuations(src string) []string {
	var out []string
	var pending strings.Builder
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			pending.WriteString(strings.TrimSuffix(trimmed, "\\"))
			pending.WriteString(" ")
			continue
		}
		if pending.Len() > 0 {
			pending.WriteString(trimmed)
			out = append(out, pending.String())
			pending.Reset()
			continue
		}
		out = append(out, trimmed)
	}
	if pending.Len() > 0 {
		out = append(out, pending.String())
	}
	return out
}
