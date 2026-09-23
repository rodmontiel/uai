// Package frontend checks the properties ADR-0003 claims for web/.
//
// Each of these is a promise made in a document, which is exactly the kind of
// promise this project keeps catching itself making and not keeping.
package frontend_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func webRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "web"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "index.html")); err != nil {
		t.Fatalf("no frontend at %s: %v", root, err)
	}
	return root
}

func served(t *testing.T) map[string]string {
	t.Helper()
	root := webRoot(t)
	files := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		files[rel] = string(body)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 8 {
		t.Fatalf("only %d files under web/; the surfaces are missing", len(files))
	}
	return files
}

// TestTheFrontendHasNoDependencies is ADR-0003 §2.1. Without this the "what you
// audit is what runs" property quietly stops being true the first time somebody
// adds a package.json.
func TestTheFrontendHasNoDependencies(t *testing.T) {
	root := webRoot(t)
	for _, forbidden := range []string{
		"package.json", "package-lock.json", "node_modules", "yarn.lock", "pnpm-lock.yaml",
	} {
		if _, err := os.Stat(filepath.Join(root, forbidden)); err == nil {
			t.Errorf("web/%s exists: the frontend is meant to have no build step and no "+
				"runtime dependencies (docs/adr/0003-a-frontend-with-no-dependencies.md)", forbidden)
		}
	}
	for name, body := range served(t) {
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".html") {
			continue
		}
		// A remote script is a dependency with none of the review a package
		// would get, on the page whose job is to tell a visitor what to trust.
		for _, remote := range []string{"https://", "http://", "//cdn.", "unpkg", "jsdelivr"} {
			if strings.Contains(body, "src=\""+remote) || strings.Contains(body, "from '"+remote) ||
				strings.Contains(body, "import('"+remote) {
				t.Errorf("%s loads something from %s", name, remote)
			}
		}
	}
}

// TestNothingClaimsAKillSwitch is project rule 2, enforced on the surface that
// the public actually reads.
//
// A UI sentence is the most likely place for this promise to creep back in,
// because it is the shortest way to describe revocation and the wrong one.
func TestNothingClaimsAKillSwitch(t *testing.T) {
	forbidden := []string{
		"kill switch", "kill-switch", "killswitch",
		"shut down the agent", "stops the agent", "stop the agent from running",
		"prevents the agent from running", "disables the agent",
	}
	for name, body := range served(t) {
		lower := strings.ToLower(body)
		for _, phrase := range forbidden {
			if strings.Contains(lower, phrase) {
				t.Errorf("web/%s says %q. Revocation means participants stop honouring the "+
					"credential; no protocol can stop code from running, and claiming otherwise "+
					"is the one thing this product must never say (project rule 2).", name, phrase)
			}
		}
	}
}

// TestTheHonestFramingIsPresent: the negative test above only catches the wrong
// sentence. This one checks the right one is actually there to be read.
func TestTheHonestFramingIsPresent(t *testing.T) {
	files := served(t)
	ui, ok := files[filepath.Join("app", "ui.js")]
	if !ok {
		t.Fatal("web/app/ui.js is missing")
	}
	if !strings.Contains(ui, "not a switch that stops software from running") {
		t.Error("the shared revocation note no longer states the limit plainly")
	}
	home, ok := files["index.html"]
	if !ok || home == "" {
		t.Fatal("web/index.html is missing")
	}
	homeJS := files[filepath.Join("app", "home.js")]
	for _, must := range []string{"cannot", "withheld", "coerced"} {
		if !strings.Contains(strings.ToLower(homeJS), must) {
			t.Errorf("the home page no longer states what this system cannot prove (%q)", must)
		}
	}
}

// TestSurfacesExist is the Phase 8 criterion in the simplest possible form: the
// five surfaces are present and each loads its own module.
func TestSurfacesExist(t *testing.T) {
	files := served(t)
	for page, module := range map[string]string{
		"index.html":      "/app/home.js",
		"verify.html":     "/app/verify-page.js",
		"agent.html":      "/app/agent.js",
		"explorer.html":   "/app/explorer.js",
		"quarantine.html": "/app/quarantine.js",
		"governance.html": "/app/governance.js",
	} {
		body, ok := files[page]
		if !ok {
			t.Errorf("web/%s is missing", page)
			continue
		}
		if !strings.Contains(body, module) {
			t.Errorf("web/%s does not load %s", page, module)
		}
		if !strings.Contains(body, `type="module"`) {
			t.Errorf("web/%s does not load its script as a module", page)
		}
	}
}

// TestNoInlineScript: the CSP forbids it, so an inline handler would be a page
// that silently does not work rather than a page that is merely impure.
func TestNoInlineScript(t *testing.T) {
	for name, body := range served(t) {
		if !strings.HasSuffix(name, ".html") {
			continue
		}
		lower := strings.ToLower(body)
		if strings.Contains(lower, "<script>") || strings.Contains(lower, "onclick=") ||
			strings.Contains(lower, "onload=") {
			t.Errorf("web/%s carries inline script, which the Content-Security-Policy blocks", name)
		}
	}
}
