package uaiid_test

import (
	"testing"

	"github.com/rodmontiel/uai/internal/conformance"
)

// TestVectors checks the committed identifier parsing and canonicalization
// vectors, including every input that MUST be rejected.
func TestVectors(t *testing.T) {
	conformance.Check(t, conformance.IdentifierSets())
}
