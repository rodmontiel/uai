package pop_test

import (
	"testing"

	"github.com/rodmontiel/uai/internal/conformance"
)

// TestVectors checks the committed RFC 9421 vectors, including the exact
// signature base string. Two implementations that agree on the cryptography but
// disagree on a newline cannot verify each other, and the disagreement stays
// invisible until it matters.
func TestVectors(t *testing.T) {
	conformance.Check(t, conformance.PoPSets())
}
