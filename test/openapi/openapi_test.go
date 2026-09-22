package openapi_test

import (
	"testing"

	"github.com/rodmontiel/uai/internal/openapi"
)

// TestOpenAPI checks that the API definition matches the protocol
// specification: every promised endpoint exists, every $ref resolves, every
// state-changing operation requires an idempotency key, and the public
// verification surface is genuinely unauthenticated.
func TestOpenAPI(t *testing.T) {
	r := openapi.Check()
	if r.LoadError != nil {
		t.Fatalf("%s: %v", r.File, r.LoadError)
	}
	for _, c := range r.Cases {
		if !c.OK {
			t.Errorf("%s: %s", c.Name, c.Detail)
		}
	}
	t.Logf("%s: OpenAPI %s, %d paths, %d checks", r.File, r.Version, r.Paths, len(r.Cases))
}
