// Package uaiid implements UAI identifiers: ULID generation and the
// uai:<entity>:<ulid> / did:uai:<entity>:<ulid> identifier forms.
//
// The package has no external dependencies by design: identifier parsing sits
// on the verification path, and every dependency there is a supply-chain risk
// (threat T-07).
package uaiid

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// ULID is a 128-bit identifier: 48 bits of millisecond timestamp followed by
// 80 bits of cryptographic randomness. Its Crockford base32 encoding sorts
// lexicographically in creation order.
type ULID [16]byte

const (
	// encodedLen is the length of the Crockford base32 encoding of 128 bits.
	encodedLen = 26
	// alphabet is Crockford base32: no I, L, O or U, so that transcription
	// mistakes are impossible rather than merely unlikely.
	alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// maxTime is the largest timestamp representable in 48 bits.
	maxTime = uint64(1)<<48 - 1
)

var (
	// ErrInvalidLength is returned when an encoded ULID is not 26 characters.
	ErrInvalidLength = errors.New("uaiid: encoded ULID must be 26 characters")
	// ErrInvalidCharacter is returned for a character outside the Crockford alphabet.
	ErrInvalidCharacter = errors.New("uaiid: invalid character in ULID")
	// ErrOverflow is returned when an encoding decodes to more than 128 bits.
	ErrOverflow = errors.New("uaiid: ULID encoding overflows 128 bits")
	// ErrTimeRange is returned when a timestamp does not fit in 48 bits.
	ErrTimeRange = errors.New("uaiid: timestamp out of 48-bit range")
)

// decodeTable maps ASCII to its 5-bit value, or 0xFF when the character is not
// part of the alphabet. Crockford's ambiguous characters are folded: I and L
// decode as 1, O decodes as 0. Decoding is lenient so that a human-transcribed
// identifier resolves; encoding is always canonical, so each ULID has exactly
// one canonical spelling.
var decodeTable = func() [256]byte {
	var t [256]byte
	for i := range t {
		t[i] = 0xFF
	}
	for i := 0; i < len(alphabet); i++ {
		c := alphabet[i]
		t[c] = byte(i)
		if c >= 'A' && c <= 'Z' {
			t[c+('a'-'A')] = byte(i)
		}
	}
	for _, p := range []struct {
		chars string
		value byte
	}{{"IiLl", 1}, {"Oo", 0}} {
		for i := 0; i < len(p.chars); i++ {
			t[p.chars[i]] = p.value
		}
	}
	return t
}()

// NewULID returns a ULID for the current time using crypto/rand entropy.
func NewULID() (ULID, error) { return NewULIDAt(time.Now()) }

// NewULIDAt returns a ULID carrying t's millisecond timestamp.
func NewULIDAt(t time.Time) (ULID, error) {
	var u ULID
	ms := uint64(t.UnixMilli())
	if t.UnixMilli() < 0 || ms > maxTime {
		return u, ErrTimeRange
	}
	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	if _, err := rand.Read(u[6:]); err != nil {
		return u, fmt.Errorf("uaiid: entropy: %w", err)
	}
	return u, nil
}

// Time returns the ULID's embedded timestamp.
func (u ULID) Time() time.Time {
	ms := uint64(u[0])<<40 | uint64(u[1])<<32 | uint64(u[2])<<24 |
		uint64(u[3])<<16 | uint64(u[4])<<8 | uint64(u[5])
	return time.UnixMilli(int64(ms)).UTC()
}

// String returns the canonical 26-character uppercase Crockford base32 encoding.
func (u ULID) String() string {
	out := make([]byte, encodedLen)
	// 26 * 5 = 130 bits for 128 bits of value: the first character carries the
	// top 2 bits only, so a canonical ULID never starts above '7'.
	var carry uint16
	bits := 0
	idx := encodedLen
	for i := len(u) - 1; i >= 0; i-- {
		carry |= uint16(u[i]) << bits
		bits += 8
		for bits >= 5 {
			idx--
			out[idx] = alphabet[carry&0x1F]
			carry >>= 5
			bits -= 5
		}
	}
	for idx > 0 {
		idx--
		out[idx] = alphabet[carry&0x1F]
		carry >>= 5
	}
	return string(out)
}

// ParseULID decodes a Crockford base32 ULID. It accepts lowercase and the
// Crockford-equivalent characters I, L and O; it rejects anything else.
func ParseULID(s string) (ULID, error) {
	var u ULID
	if len(s) != encodedLen {
		return u, ErrInvalidLength
	}
	if decodeTable[s[0]] > 7 && decodeTable[s[0]] != 0xFF {
		return u, ErrOverflow
	}
	var carry uint16
	bits := 0
	idx := len(u)
	for i := len(s) - 1; i >= 0; i-- {
		v := decodeTable[s[i]]
		if v == 0xFF {
			return u, fmt.Errorf("%w: %q at position %d", ErrInvalidCharacter, s[i], i)
		}
		carry |= uint16(v) << bits
		bits += 5
		if bits >= 8 {
			idx--
			if idx < 0 {
				return u, ErrOverflow
			}
			u[idx] = byte(carry & 0xFF)
			carry >>= 8
			bits -= 8
		}
	}
	if idx != 0 || carry != 0 {
		return u, ErrOverflow
	}
	return u, nil
}
