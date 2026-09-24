// Package threatmodel checks §20 against the repository.
//
// A threat register is a document that describes controls, and documents drift
// in one direction: toward describing what someone intended. Writing this gate
// found six controls listed in §20.1 that do not exist -- rate limits, did:web
// domain-control proof, owner notification on registration, SBOM and artifact
// signing, counter-attestation, and cross-instance fork observation -- each of
// which a reader of the Controls column would have taken for present.
//
// So §20.4 states a status and names an artifact for every threat, and this
// checks that the artifacts are real. It cannot check that a control WORKS;
// that is what the tests it points at are for. What it can check is that the
// document has not quietly become fiction.
package threatmodel_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const doc = "../../docs/protocol/13-threat-model.md"

var (
	registerRE = regexp.MustCompile(`(?m)^\| (T-\d\d) \| \*\*`)
	// §20.4 rows: | T-01 | PARTIAL | `path`, `path` | prose |
	validRE  = regexp.MustCompile(`(?m)^\| (T-\d\d) \| ([A-Z]+) \| (.*?) \| (.*?) \|\s*$`)
	tickedRE = regexp.MustCompile("`([^`]+)`")
	// §20.5 rows name the threats a missing control affects.
	threatRefRE = regexp.MustCompile(`T-\d\d`)
	pathishRE   = regexp.MustCompile(`(/|\.(go|sql|py|json|mjs|sol|md|yaml))$|/`)
)

var statuses = map[string]bool{
	"ENFORCED": true, "PARTIAL": true, "ACCEPTED": true, "PLANNED": true,
}

func read(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sections splits the document at its "## 20.N " headings.
func sections(src string) map[string]string {
	out := map[string]string{}
	re := regexp.MustCompile(`(?m)^## (20\.\d) `)
	idx := re.FindAllStringSubmatchIndex(src, -1)
	for i, m := range idx {
		end := len(src)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		out[src[m[2]:m[3]]] = src[m[0]:end]
	}
	return out
}

type row struct {
	status   string
	evidence string
	shows    string
}

func validation(t *testing.T, src string) map[string]row {
	t.Helper()
	sec, ok := sections(src)["20.4"]
	if !ok {
		t.Fatal("§20.4 is missing; the validation table is the point of this gate")
	}
	out := map[string]row{}
	for _, m := range validRE.FindAllStringSubmatch(sec, -1) {
		out[m[1]] = row{status: m[2], evidence: m[3], shows: m[4]}
	}
	return out
}

// TestEveryThreatIsValidated: §20.1 and §20.4 must name the same threats.
func TestEveryThreatIsValidated(t *testing.T) {
	src := read(t)
	rows := validation(t, src)

	declared := map[string]bool{}
	for _, m := range registerRE.FindAllStringSubmatch(src, -1) {
		declared[m[1]] = true
	}
	if len(declared) == 0 {
		t.Fatal("no threats parsed from §20.1; the register's table shape changed")
	}
	for id := range declared {
		if _, ok := rows[id]; !ok {
			t.Errorf("%s is in the register and not in §20.4.\n"+
				"Every threat has to say whether its controls exist. If none of them do,\n"+
				"the honest row is PLANNED with no evidence -- not an absent row.", id)
		}
	}
	for id := range rows {
		if !declared[id] {
			t.Errorf("%s is validated in §20.4 and not declared in §20.1", id)
		}
	}
	t.Logf("%d threats, %d validated", len(declared), len(rows))
}

// TestEveryStatusIsFromTheVocabulary keeps the column from becoming prose.
func TestEveryStatusIsFromTheVocabulary(t *testing.T) {
	for id, r := range validation(t, read(t)) {
		if !statuses[r.status] {
			t.Errorf("%s has status %q, which is not one of ENFORCED/PARTIAL/ACCEPTED/PLANNED",
				id, r.status)
		}
	}
}

// TestEveryEvidencePathExists is the check that does the work.
//
// Backticked tokens that look like paths must resolve. A token in parentheses
// after a path is a symbol -- a test name, an error, a column -- and must appear
// inside the file before it, which is what catches a renamed test still being
// cited as evidence.
func TestEveryEvidencePathExists(t *testing.T) {
	root := "../.."
	checked := 0
	for id, r := range validation(t, read(t)) {
		var lastPath string
		for _, m := range tickedRE.FindAllStringSubmatch(r.evidence, -1) {
			tok := m[1]
			if !pathishRE.MatchString(tok) {
				// A symbol. It has to live in the file it was cited beside.
				if lastPath == "" {
					t.Errorf("%s cites %q with no file before it", id, tok)
					continue
				}
				b, err := os.ReadFile(filepath.Join(root, lastPath))
				if err != nil {
					continue // reported by the path check below
				}
				if !strings.Contains(string(b), tok) {
					t.Errorf("%s cites %q in %s, and %s does not contain it.\n"+
						"Evidence that names something no longer there is worse than none.",
						id, tok, lastPath, lastPath)
				}
				continue
			}
			lastPath = tok
			checked++
			if _, err := os.Stat(filepath.Join(root, tok)); err != nil {
				t.Errorf("%s cites %s as evidence and it does not exist: %v", id, tok, err)
			}
		}
		if r.status == "ENFORCED" && lastPath == "" {
			t.Errorf("%s is ENFORCED and names no evidence.\n"+
				"ENFORCED means a test asserts it; name the test.", id)
		}
		if r.status == "PLANNED" && strings.Contains(r.shows, " enforces ") {
			t.Errorf("%s is PLANNED and its description claims enforcement", id)
		}
	}
	if checked == 0 {
		t.Fatal("no evidence paths parsed; this gate stopped checking anything")
	}
	t.Logf("%d evidence paths checked", checked)
}

// TestAcceptedRisksAgree: a risk §20.2 accepts must be ACCEPTED in §20.4.
//
// The two sections say the same thing in different places, which is exactly
// where a document contradicts itself without anyone noticing.
func TestAcceptedRisksAgree(t *testing.T) {
	src := read(t)
	rows := validation(t, src)
	sec, ok := sections(src)["20.2"]
	if !ok {
		t.Fatal("§20.2 is missing")
	}
	accepted := map[string]bool{}
	for _, id := range threatRefRE.FindAllString(sec, -1) {
		accepted[id] = true
	}
	if len(accepted) == 0 {
		t.Fatal("§20.2 names no threats; the accepted-risk list stopped being machine-readable")
	}
	for id := range accepted {
		if r, ok := rows[id]; ok && r.status != "ACCEPTED" {
			t.Errorf("%s is listed as an accepted risk in §20.2 and is %s in §20.4.\n"+
				"Either it is accepted or it is controlled; the register cannot say both.",
				id, r.status)
		}
	}
	ids := make([]string, 0, len(accepted))
	for id := range accepted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	t.Logf("accepted risks: %v", ids)
}

// TestMissingControlsPointAtUnfinishedThreats: §20.5 exists so the gaps are
// readable in one place. A control listed there against a threat that §20.4
// calls ENFORCED means one of the two is wrong.
func TestMissingControlsPointAtUnfinishedThreats(t *testing.T) {
	src := read(t)
	rows := validation(t, src)
	sec, ok := sections(src)["20.5"]
	if !ok {
		t.Fatal("§20.5 is missing; the gaps have to be listed somewhere a reader will find them")
	}
	found := 0
	for _, line := range strings.Split(sec, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.Contains(line, "---") ||
			strings.Contains(line, "Missing control") {
			continue
		}
		for _, id := range threatRefRE.FindAllString(line, -1) {
			found++
			r, ok := rows[id]
			if !ok {
				t.Errorf("§20.5 names %s, which §20.4 does not validate", id)
				continue
			}
			if r.status == "ENFORCED" {
				t.Errorf("§20.5 says a control for %s is missing, and §20.4 calls %s ENFORCED",
					id, id)
			}
		}
	}
	if found == 0 {
		t.Fatal("§20.5 names no threats; it stopped connecting gaps to the register")
	}
	t.Logf("%d gap-to-threat references checked", found)
}
