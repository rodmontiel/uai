// Package chain talks to an EVM JSON-RPC endpoint.
//
// It is deliberately small. UAI's contracts take only fixed-width arguments
// (INV-007/008), so ABI encoding here is padding values to 32 bytes rather than
// the general algorithm — no dynamic offsets, no tails, no strings. Pulling in
// a full Ethereum client to encode three bytes32 would put a very large
// dependency tree behind the component that writes to the ledger, and that is
// the one component whose writes are supposed to be hard to forge.
package chain

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

// ErrUnsupportedArgument is returned for anything that is not fixed-width.
//
// It exists so that a future caller cannot quietly pass a string: the same rule
// INV-007 enforces on the contracts is enforced here on the way in.
var ErrUnsupportedArgument = errors.New("chain: only fixed-width arguments can be encoded")

// Keccak256 is the hash the EVM uses. It is the pre-standard variant, not
// SHA3-256, and the two produce different digests for the same input.
func Keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// Selector is the first four bytes of the keccak hash of a function signature.
func Selector(signature string) []byte { return Keccak256([]byte(signature))[:4] }

// Word is one 32-byte ABI slot.
type Word [32]byte

// WordFromBytes32 places a 32-byte value.
func WordFromBytes32(b []byte) (Word, error) {
	var w Word
	if len(b) != 32 {
		return w, fmt.Errorf("%w: bytes32 needs 32 bytes, got %d", ErrUnsupportedArgument, len(b))
	}
	copy(w[:], b)
	return w, nil
}

// WordFromUint places an unsigned integer, right-aligned as the ABI requires.
func WordFromUint(v uint64) Word {
	var w Word
	binary.BigEndian.PutUint64(w[24:], v)
	return w
}

// WordFromAddress places a 20-byte address, right-aligned.
func WordFromAddress(addr string) (Word, error) {
	var w Word
	b, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
	if err != nil {
		return w, fmt.Errorf("chain: address %q: %w", addr, err)
	}
	if len(b) != 20 {
		return w, fmt.Errorf("%w: address needs 20 bytes, got %d", ErrUnsupportedArgument, len(b))
	}
	copy(w[12:], b)
	return w, nil
}

// Encode builds call data from a signature and fixed-width words.
func Encode(signature string, args ...Word) []byte {
	out := make([]byte, 0, 4+32*len(args))
	out = append(out, Selector(signature)...)
	for _, a := range args {
		out = append(out, a[:]...)
	}
	return out
}

// Hex renders bytes as an 0x-prefixed string.
func Hex(b []byte) string { return "0x" + hex.EncodeToString(b) }
