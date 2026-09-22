package conformance

import "testing"

// Check reports every failing case in a result to t. It lives beside the
// runner so that the package tests and the CLI report identical verdicts from
// identical logic.
func Check(t *testing.T, results []Result) {
	t.Helper()
	for _, r := range results {
		r := r
		t.Run(r.Set, func(t *testing.T) {
			if r.LoadError != nil {
				t.Fatalf("vector set %s failed to load: %v", r.File, r.LoadError)
			}
			for _, c := range r.Cases {
				if !c.OK {
					t.Errorf("%s: %s", c.Name, c.Detail)
				}
			}
		})
	}
}
