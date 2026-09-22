// Package merkle implements the RFC 6962 Merkle tree profile used by the UAI
// transparency log: inclusion proofs, consistency proofs and checkpoints.
//
// The RFC 6962 domain prefixes (0x00 for leaves, 0x01 for interior nodes) are
// not decoration: without them an interior node hash can be presented as a leaf
// hash, which breaks second-preimage resistance and therefore breaks every
// inclusion proof the log issues. UAI uses the profile unchanged so that
// existing Certificate Transparency verifiers work against a UAI log.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

// HashSize is the length of a SHA-256 digest in bytes.
const HashSize = sha256.Size

var (
	// ErrIndexOutOfRange is returned when a leaf index is not inside the tree.
	ErrIndexOutOfRange = errors.New("merkle: leaf index out of range")
	// ErrProofMalformed is returned when a proof has the wrong number of hashes.
	ErrProofMalformed = errors.New("merkle: proof is malformed")
	// ErrVerificationFailed is returned when a proof does not reconstruct the root.
	ErrVerificationFailed = errors.New("merkle: proof verification failed")
	// ErrSizeOrder is returned when snapshot sizes are not ordered.
	ErrSizeOrder = errors.New("merkle: first snapshot must not exceed the second")
)

// LeafHash returns SHA-256(0x00 || data).
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// NodeHash returns SHA-256(0x01 || left || right).
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// EmptyRoot returns the root of an empty tree, SHA-256("").
func EmptyRoot() []byte {
	h := sha256.Sum256(nil)
	return h[:]
}

// Tree is an append-only in-memory Merkle tree holding the log's leaf hashes.
//
// It recomputes subtree roots on demand rather than caching them. That is
// O(n) per root and entirely adequate for the MVP's volumes; the production
// log replaces this type with a persistent tiled store behind the same
// interface, and the proof formats do not change.
type Tree struct {
	leaves [][]byte
}

// New returns an empty tree.
func New() *Tree { return &Tree{} }

// Append adds a leaf (the raw entry, not its hash) and returns its index.
func (t *Tree) Append(entry []byte) uint64 {
	t.leaves = append(t.leaves, LeafHash(entry))
	return uint64(len(t.leaves) - 1)
}

// AppendLeafHash adds an already-hashed leaf and returns its index.
func (t *Tree) AppendLeafHash(leafHash []byte) uint64 {
	cp := make([]byte, len(leafHash))
	copy(cp, leafHash)
	t.leaves = append(t.leaves, cp)
	return uint64(len(t.leaves) - 1)
}

// Size returns the number of leaves.
func (t *Tree) Size() uint64 { return uint64(len(t.leaves)) }

// LeafHashAt returns the hash of the leaf at index i.
func (t *Tree) LeafHashAt(i uint64) ([]byte, error) {
	if i >= t.Size() {
		return nil, fmt.Errorf("%w: %d not in [0,%d)", ErrIndexOutOfRange, i, t.Size())
	}
	return t.leaves[i], nil
}

// Root returns the Merkle tree hash of the whole tree.
func (t *Tree) Root() []byte { return t.rootAt(0, t.Size()) }

// RootAtSize returns the root the tree had when it held n leaves, which is what
// a checkpoint for that size committed to.
func (t *Tree) RootAtSize(n uint64) ([]byte, error) {
	if n > t.Size() {
		return nil, fmt.Errorf("%w: %d exceeds current size %d", ErrIndexOutOfRange, n, t.Size())
	}
	return t.rootAt(0, n), nil
}

// rootAt computes MTH(D[lo:hi]) per RFC 6962 section 2.1.
func (t *Tree) rootAt(lo, hi uint64) []byte {
	switch n := hi - lo; {
	case n == 0:
		return EmptyRoot()
	case n == 1:
		return t.leaves[lo]
	default:
		k := splitPoint(n)
		return NodeHash(t.rootAt(lo, lo+k), t.rootAt(lo+k, hi))
	}
}

// splitPoint returns the largest power of two strictly smaller than n.
func splitPoint(n uint64) uint64 {
	if n < 2 {
		return 0
	}
	return uint64(1) << (bits.Len64(n-1) - 1)
}

// InclusionProof returns the audit path for the leaf at index, in the tree of
// the given size.
func (t *Tree) InclusionProof(index, size uint64) ([][]byte, error) {
	if size > t.Size() {
		return nil, fmt.Errorf("%w: size %d exceeds tree size %d", ErrIndexOutOfRange, size, t.Size())
	}
	if index >= size {
		return nil, fmt.Errorf("%w: index %d not in [0,%d)", ErrIndexOutOfRange, index, size)
	}
	return t.path(index, 0, size), nil
}

// path implements PATH(m, D[n]) from RFC 6962 section 2.1.1.
func (t *Tree) path(m, lo, hi uint64) [][]byte {
	n := hi - lo
	if n == 1 {
		return nil
	}
	k := splitPoint(n)
	if m < k {
		return append(t.path(m, lo, lo+k), t.rootAt(lo+k, hi))
	}
	return append(t.path(m-k, lo+k, hi), t.rootAt(lo, lo+k))
}

// ConsistencyProof proves that the tree of size first is a prefix of the tree
// of size second: the property that makes "append-only" verifiable rather than
// merely asserted.
func (t *Tree) ConsistencyProof(first, second uint64) ([][]byte, error) {
	if first > second {
		return nil, fmt.Errorf("%w: %d > %d", ErrSizeOrder, first, second)
	}
	if second > t.Size() {
		return nil, fmt.Errorf("%w: size %d exceeds tree size %d", ErrIndexOutOfRange, second, t.Size())
	}
	if first == 0 || first == second {
		return nil, nil
	}
	return t.subproof(first, 0, second, true), nil
}

// subproof implements SUBPROOF(m, D[n], b) from RFC 6962 section 2.1.2.
func (t *Tree) subproof(m, lo, hi uint64, complete bool) [][]byte {
	n := hi - lo
	if m == n {
		if complete {
			return nil
		}
		return [][]byte{t.rootAt(lo, hi)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(t.subproof(m, lo, lo+k, complete), t.rootAt(lo+k, hi))
	}
	return append(t.subproof(m-k, lo+k, hi, false), t.rootAt(lo, lo+k))
}

// VerifyInclusion checks an audit path against a root. A verifier that has a
// witnessed checkpoint and this function needs nothing from the log operator.
func VerifyInclusion(index, size uint64, leafHash, root []byte, proof [][]byte) error {
	computed, err := RootFromInclusionProof(index, size, leafHash, proof)
	if err != nil {
		return err
	}
	if !bytes.Equal(computed, root) {
		return fmt.Errorf("%w: computed root %x does not match %x", ErrVerificationFailed, computed, root)
	}
	return nil
}

// RootFromInclusionProof recomputes the tree root implied by an audit path.
func RootFromInclusionProof(index, size uint64, leafHash []byte, proof [][]byte) ([]byte, error) {
	if index >= size {
		return nil, fmt.Errorf("%w: index %d not in [0,%d)", ErrIndexOutOfRange, index, size)
	}
	if len(leafHash) != HashSize {
		return nil, fmt.Errorf("%w: leaf hash is %d bytes, want %d", ErrProofMalformed, len(leafHash), HashSize)
	}
	inner, border := decomposeInclusionProof(index, size)
	if len(proof) != inner+border {
		return nil, fmt.Errorf("%w: got %d hashes, want %d", ErrProofMalformed, len(proof), inner+border)
	}
	res := chainInner(leafHash, proof[:inner], index)
	res = chainBorderRight(res, proof[inner:])
	return res, nil
}

// decomposeInclusionProof splits an audit path into the part that mixes with
// the leaf's own subtree and the part that folds in the tree's right border.
func decomposeInclusionProof(index, size uint64) (inner, border int) {
	inner = bits.Len64(index ^ (size - 1))
	border = bits.OnesCount64(index >> uint(inner))
	return inner, border
}

func chainInner(seed []byte, proof [][]byte, index uint64) []byte {
	for i, h := range proof {
		if (index>>uint(i))&1 == 0 {
			seed = NodeHash(seed, h)
		} else {
			seed = NodeHash(h, seed)
		}
	}
	return seed
}

func chainBorderRight(seed []byte, proof [][]byte) []byte {
	for _, h := range proof {
		seed = NodeHash(h, seed)
	}
	return seed
}

// VerifyConsistency checks that the tree of size first with root firstRoot is a
// prefix of the tree of size second with root secondRoot.
func VerifyConsistency(first, second uint64, firstRoot, secondRoot []byte, proof [][]byte) error {
	if first > second {
		return fmt.Errorf("%w: %d > %d", ErrSizeOrder, first, second)
	}
	if first == second {
		if len(proof) != 0 {
			return fmt.Errorf("%w: proof must be empty for equal sizes", ErrProofMalformed)
		}
		if !bytes.Equal(firstRoot, secondRoot) {
			return fmt.Errorf("%w: equal sizes with different roots", ErrVerificationFailed)
		}
		return nil
	}
	if first == 0 {
		// Every tree is consistent with the empty tree.
		if len(proof) != 0 {
			return fmt.Errorf("%w: proof must be empty for an empty first snapshot", ErrProofMalformed)
		}
		return nil
	}
	if len(proof) == 0 {
		return fmt.Errorf("%w: empty proof", ErrProofMalformed)
	}

	// Descend to the node where the two snapshots diverge.
	node, lastNode := first-1, second-1
	for node%2 == 1 {
		node /= 2
		lastNode /= 2
	}

	var firstHash, secondHash []byte
	if node > 0 {
		firstHash, secondHash = proof[0], proof[0]
		proof = proof[1:]
	} else {
		// The first snapshot is a perfect subtree, so its root is implicit.
		firstHash, secondHash = firstRoot, firstRoot
	}

	for node > 0 {
		if node%2 == 1 {
			if len(proof) == 0 {
				return fmt.Errorf("%w: proof exhausted", ErrProofMalformed)
			}
			firstHash = NodeHash(proof[0], firstHash)
			secondHash = NodeHash(proof[0], secondHash)
			proof = proof[1:]
		} else if node < lastNode {
			if len(proof) == 0 {
				return fmt.Errorf("%w: proof exhausted", ErrProofMalformed)
			}
			secondHash = NodeHash(secondHash, proof[0])
			proof = proof[1:]
		}
		node /= 2
		lastNode /= 2
	}

	for lastNode > 0 {
		if len(proof) == 0 {
			return fmt.Errorf("%w: proof exhausted", ErrProofMalformed)
		}
		secondHash = NodeHash(secondHash, proof[0])
		proof = proof[1:]
		lastNode /= 2
	}

	if len(proof) != 0 {
		return fmt.Errorf("%w: %d unused hashes", ErrProofMalformed, len(proof))
	}
	if !bytes.Equal(firstHash, firstRoot) {
		return fmt.Errorf("%w: reconstructed first root does not match", ErrVerificationFailed)
	}
	if !bytes.Equal(secondHash, secondRoot) {
		return fmt.Errorf("%w: reconstructed second root does not match", ErrVerificationFailed)
	}
	return nil
}
