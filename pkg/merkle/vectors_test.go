package merkle_test

import (
	"testing"

	"github.com/rodmontiel/uai/internal/conformance"
)

// TestVectors checks the committed RFC 6962 hashing and proof vectors. Proofs
// are verified from the committed bytes rather than from freshly generated
// ones, so passing demonstrates interoperability and not self-agreement.
func TestVectors(t *testing.T) {
	conformance.Check(t, conformance.MerkleSets())
}
