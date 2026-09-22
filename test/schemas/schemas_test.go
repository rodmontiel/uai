package schemas_test

import (
	"testing"

	"github.com/rodmontiel/uai/internal/schemas"
)

// TestSchemas compiles every UAI JSON Schema and checks the committed
// examples in both directions: the valid ones must validate, and the invalid
// ones must be rejected. The second direction is the one that matters — it is
// where the protocol's constraints are actually pinned.
func TestSchemas(t *testing.T) {
	results := schemas.Validate()
	if len(results) == 0 {
		t.Fatal("no schemas found in spec/schemas")
	}
	for _, r := range results {
		r := r
		t.Run(r.Schema, func(t *testing.T) {
			if r.LoadError != nil {
				t.Fatalf("%s: %v", r.File, r.LoadError)
			}
			if len(r.Cases) == 0 && r.Schema != "common" {
				t.Fatalf("%s has no examples", r.File)
			}
			for _, c := range r.Cases {
				if !c.OK {
					t.Errorf("%s: %s", c.Name, c.Detail)
				}
			}
		})
	}
}
