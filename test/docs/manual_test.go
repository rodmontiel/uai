// The two manuals have to stay the same document in two languages.
//
// A translation drifts in one direction: the language somebody is editing gets
// the new section, and the other one quietly becomes a description of an older
// system. Nothing about that failure is visible to a reader, because each file
// reads perfectly well on its own -- which is exactly why it needs a gate
// rather than a convention.
//
// What is checked is structure, not prose: the same heading hierarchy, the same
// number of code blocks, and the same commands. A translator is free with the
// words and not with what the document claims the software does.
package docs_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const (
	english = "../../docs/MANUAL.md"
	spanish = "../../docs/MANUAL.es.md"
)

var (
	headingRE = regexp.MustCompile(`(?m)^(#{1,6}) `)
	fenceRE   = regexp.MustCompile("(?m)^```")
	// Commands a reader is told to run. If one manual says `./deploy.sh up` and
	// the other still says `make run-gateway`, one of them is wrong.
	commandRE = regexp.MustCompile(`(?m)^(\./deploy\.sh [a-z]+|make [a-z-]+|go build [^\n]*|curl -s [^\n]+)`)
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("both manuals must exist: %v", err)
	}
	return string(b)
}

// TestTheManualsHaveTheSameShape compares heading depth, section for section.
func TestTheManualsHaveTheSameShape(t *testing.T) {
	en, es := read(t, english), read(t, spanish)

	depths := func(src string) []string {
		var out []string
		for _, m := range headingRE.FindAllStringSubmatch(src, -1) {
			out = append(out, m[1])
		}
		return out
	}
	a, b := depths(en), depths(es)
	if len(a) != len(b) {
		t.Fatalf("MANUAL.md has %d headings and MANUAL.es.md has %d.\n"+
			"One of them gained or lost a section the other does not have.", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("heading %d is %q in English and %q in Spanish: the section nesting diverged",
				i+1, a[i], b[i])
		}
	}
}

// TestTheManualsShowTheSameCommands is the part that actually misleads a reader.
//
// Prose can differ; instructions cannot. A manual that tells a Spanish reader to
// run a target that was renamed six months ago is worse than no manual, because
// it fails in a way that looks like the software is broken.
func TestTheManualsShowTheSameCommands(t *testing.T) {
	commands := func(src string) map[string]int {
		out := map[string]int{}
		for _, m := range commandRE.FindAllString(src, -1) {
			out[strings.TrimSpace(m)]++
		}
		return out
	}
	en, es := commands(read(t, english)), commands(read(t, spanish))
	if len(en) == 0 {
		t.Fatal("no commands parsed; this check stopped checking anything")
	}
	for cmd, n := range en {
		if es[cmd] != n {
			t.Errorf("%q appears %d time(s) in MANUAL.md and %d in MANUAL.es.md", cmd, n, es[cmd])
		}
	}
	for cmd, n := range es {
		if en[cmd] != n {
			t.Errorf("%q appears %d time(s) in MANUAL.es.md and %d in MANUAL.md", cmd, n, en[cmd])
		}
	}
}

// TestTheManualsHaveTheSameNumberOfExamples: a code block is a claim about what
// the software prints. Losing one in translation loses the evidence.
func TestTheManualsHaveTheSameNumberOfExamples(t *testing.T) {
	en := len(fenceRE.FindAllString(read(t, english), -1))
	es := len(fenceRE.FindAllString(read(t, spanish), -1))
	if en != es {
		t.Errorf("MANUAL.md has %d code fences and MANUAL.es.md has %d", en, es)
	}
	if en%2 != 0 {
		t.Errorf("MANUAL.md has an odd number of code fences (%d): one is unclosed", en)
	}
}

// TestEachManualPointsAtTheOther, so a reader who lands on one finds the other.
func TestEachManualPointsAtTheOther(t *testing.T) {
	if !strings.Contains(read(t, english), "MANUAL.es.md") {
		t.Error("MANUAL.md does not link to the Spanish version")
	}
	if !strings.Contains(read(t, spanish), "MANUAL.md") {
		t.Error("MANUAL.es.md does not link to the English version")
	}
}
