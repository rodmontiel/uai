package uaicrypto_test

import (
	"testing"

	"github.com/rodmontiel/uai/internal/conformance"
)

// TestVectors asserts that this implementation reproduces the COMMITTED
// vectors in spec/test-vectors. The expectations are never regenerated here:
// a test that writes its own expected values proves only that the code agrees
// with itself, which is exactly the gap published vectors exist to close.
func TestVectors(t *testing.T) {
	conformance.Check(t, conformance.CryptoSets())
}
