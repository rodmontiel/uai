package merkle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// entries mirrors the RFC 6962 section 2.1.3 worked example.
func entries(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("entry-%04d", i))
	}
	return out
}

func build(n int) *Tree {
	t := New()
	for _, e := range entries(n) {
		t.Append(e)
	}
	return t
}

func TestEmptyRootIsSHA256OfEmptyString(t *testing.T) {
	// RFC 6962: MTH({}) = SHA-256().
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := hex.EncodeToString(EmptyRoot()); got != want {
		t.Fatalf("empty root = %s, want %s", got, want)
	}
	if got := hex.EncodeToString(New().Root()); got != want {
		t.Fatalf("empty tree root = %s, want %s", got, want)
	}
}

func TestLeafAndNodePrefixesDiffer(t *testing.T) {
	// Second-preimage resistance: an interior node hash must never be
	// producible as a leaf hash, which is exactly what the 0x00/0x01 prefixes
	// buy. Without them, NodeHash(a,b) == LeafHash(a||b).
	a, b := LeafHash([]byte("a")), LeafHash([]byte("b"))
	node := NodeHash(a, b)
	leafOfConcat := LeafHash(append(append([]byte{}, a...), b...))
	if bytes.Equal(node, leafOfConcat) {
		t.Fatal("interior node hash collides with a leaf hash: domain prefixes are missing")
	}
}

func TestSingleLeafRootIsItsLeafHash(t *testing.T) {
	tree := build(1)
	if !bytes.Equal(tree.Root(), LeafHash([]byte("entry-0000"))) {
		t.Fatal("MTH of a one-leaf tree must be the leaf hash itself")
	}
}

func TestInclusionProofsVerifyForEverySize(t *testing.T) {
	for size := uint64(1); size <= 64; size++ {
		tree := build(int(size))
		root := tree.Root()
		for i := uint64(0); i < size; i++ {
			proof, err := tree.InclusionProof(i, size)
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, i, err)
			}
			leaf, err := tree.LeafHashAt(i)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(i, size, leaf, root, proof); err != nil {
				t.Fatalf("size %d index %d: %v", size, i, err)
			}
		}
	}
}

func TestInclusionProofRejectsTampering(t *testing.T) {
	tree := build(17)
	root := tree.Root()
	leaf, _ := tree.LeafHashAt(5)
	proof, err := tree.InclusionProof(5, 17)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong leaf", func(t *testing.T) {
		if err := VerifyInclusion(5, 17, LeafHash([]byte("forged")), root, proof); err == nil {
			t.Fatal("a forged leaf verified")
		}
	})
	t.Run("wrong index", func(t *testing.T) {
		if err := VerifyInclusion(6, 17, leaf, root, proof); err == nil {
			t.Fatal("a proof verified at the wrong index")
		}
	})
	t.Run("mutated path", func(t *testing.T) {
		bad := make([][]byte, len(proof))
		copy(bad, proof)
		mutated := append([]byte{}, bad[0]...)
		mutated[0] ^= 0xFF
		bad[0] = mutated
		if err := VerifyInclusion(5, 17, leaf, root, bad); err == nil {
			t.Fatal("a mutated audit path verified")
		}
	})
	t.Run("truncated path", func(t *testing.T) {
		if err := VerifyInclusion(5, 17, leaf, root, proof[:len(proof)-1]); err == nil {
			t.Fatal("a truncated proof verified")
		}
	})
	t.Run("index out of range", func(t *testing.T) {
		if _, err := tree.InclusionProof(17, 17); err == nil {
			t.Fatal("an out-of-range index produced a proof")
		}
	})
}

func TestConsistencyProofsVerifyForEveryPair(t *testing.T) {
	const max = 40
	tree := build(max)
	for second := uint64(1); second <= max; second++ {
		secondRoot, err := tree.RootAtSize(second)
		if err != nil {
			t.Fatal(err)
		}
		for first := uint64(0); first <= second; first++ {
			firstRoot, err := tree.RootAtSize(first)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := tree.ConsistencyProof(first, second)
			if err != nil {
				t.Fatalf("proof(%d,%d): %v", first, second, err)
			}
			if err := VerifyConsistency(first, second, firstRoot, secondRoot, proof); err != nil {
				t.Fatalf("verify(%d,%d): %v", first, second, err)
			}
		}
	}
}

func TestConsistencyProofDetectsRewrittenHistory(t *testing.T) {
	// The property the transparency log exists for: a log that silently
	// rewrites an old entry cannot produce a valid consistency proof.
	honest := build(8)
	oldRoot, err := honest.RootAtSize(5)
	if err != nil {
		t.Fatal(err)
	}

	tampered := New()
	for i, e := range entries(8) {
		if i == 2 {
			e = []byte("entry-0002-REWRITTEN")
		}
		tampered.Append(e)
	}
	proof, err := tampered.ConsistencyProof(5, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(5, 8, oldRoot, tampered.Root(), proof); err == nil {
		t.Fatal("a rewritten log produced a valid consistency proof")
	}
}

func TestConsistencyProofDetectsDeletedEntry(t *testing.T) {
	honest := build(9)
	oldRoot, err := honest.RootAtSize(9)
	if err != nil {
		t.Fatal(err)
	}
	shortened := build(8) // an entry removed from the end
	proof, err := shortened.ConsistencyProof(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(9, 8, oldRoot, shortened.Root(), proof); err == nil {
		t.Fatal("a shrinking log verified as consistent")
	}
}

func TestConsistencyEdgeCases(t *testing.T) {
	tree := build(6)
	root := tree.Root()

	t.Run("empty first snapshot", func(t *testing.T) {
		proof, err := tree.ConsistencyProof(0, 6)
		if err != nil {
			t.Fatal(err)
		}
		if len(proof) != 0 {
			t.Fatalf("proof for an empty snapshot should be empty, got %d hashes", len(proof))
		}
		if err := VerifyConsistency(0, 6, EmptyRoot(), root, proof); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("equal snapshots", func(t *testing.T) {
		if err := VerifyConsistency(6, 6, root, root, nil); err != nil {
			t.Fatal(err)
		}
		if err := VerifyConsistency(6, 6, root, LeafHash([]byte("x")), nil); err == nil {
			t.Fatal("equal sizes with different roots verified")
		}
	})
	t.Run("reversed sizes", func(t *testing.T) {
		if _, err := tree.ConsistencyProof(6, 3); err == nil {
			t.Fatal("a proof was produced for reversed sizes")
		}
	})
	t.Run("extra hashes rejected", func(t *testing.T) {
		proof, err := tree.ConsistencyProof(3, 6)
		if err != nil {
			t.Fatal(err)
		}
		first, _ := tree.RootAtSize(3)
		padded := append(append([][]byte{}, proof...), LeafHash([]byte("junk")))
		if err := VerifyConsistency(3, 6, first, root, padded); err == nil {
			t.Fatal("a proof with unused hashes verified")
		}
	})
}

func TestAppendingDoesNotChangeEarlierRoots(t *testing.T) {
	// Append-only means a checkpoint stays valid forever.
	tree := New()
	var roots [][]byte
	for i, e := range entries(20) {
		tree.Append(e)
		roots = append(roots, tree.Root())
		for size := 1; size <= i+1; size++ {
			got, err := tree.RootAtSize(uint64(size))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, roots[size-1]) {
				t.Fatalf("root at size %d changed after %d appends", size, i+1)
			}
		}
	}
}

func TestSplitPoint(t *testing.T) {
	cases := map[uint64]uint64{2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8, 16: 8, 17: 16}
	for n, want := range cases {
		if got := splitPoint(n); got != want {
			t.Errorf("splitPoint(%d) = %d, want %d", n, got, want)
		}
	}
}
