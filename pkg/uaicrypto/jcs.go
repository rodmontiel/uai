// Package uaicrypto implements the UAI-CS-1 cipher suite: JCS canonicalization,
// domain-separated digests, salted commitments and signature envelopes.
//
// It deliberately depends only on the Go standard library. Every dependency on
// the verification path is supply-chain attack surface (threat T-07), and a
// third party must be able to audit this package in one sitting.
package uaicrypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
)

// ErrNotCanonicalizable is returned for values JSON cannot represent
// canonically, such as NaN and infinities.
var ErrNotCanonicalizable = errors.New("uaicrypto: value cannot be canonicalized")

// Canonicalize marshals v to JSON and returns its RFC 8785 (JCS) canonical
// form. Every hash and signature in UAI is computed over this representation,
// so that two implementations serializing the same logical object produce
// identical bytes.
func Canonicalize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("uaicrypto: marshal: %w", err)
	}
	return CanonicalizeJSON(raw)
}

// CanonicalizeJSON returns the RFC 8785 canonical form of an existing JSON
// document. Numbers are re-serialized using the ECMAScript Number::toString
// algorithm, object members are sorted by the UTF-16 code units of their names,
// and insignificant whitespace is removed.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("uaicrypto: decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("uaicrypto: trailing data after JSON value")
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeJSONString(buf, t)
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return fmt.Errorf("uaicrypto: number %q: %w", t.String(), err)
		}
		s, err := formatNumber(f)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case float64:
		s, err := formatNumber(t)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortByUTF16(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJSONString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported type %T", ErrNotCanonicalizable, v)
	}
	return nil
}

// sortByUTF16 orders strings by their UTF-16 code units, which is what RFC 8785
// requires and what differs from Go's default byte-wise ordering for characters
// outside the Basic Multilingual Plane.
func sortByUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
}

// formatNumber implements the ECMAScript Number::toString serialization that
// RFC 8785 mandates: the shortest representation that round-trips, with
// exponential notation only outside the range [1e-6, 1e21).
func formatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: %v is not representable in JSON", ErrNotCanonicalizable, f)
	}
	if f == 0 {
		// JCS serializes negative zero as "0".
		return "0", nil
	}
	abs := math.Abs(f)
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	// Go emits "1e+21" / "1e-07"; ECMAScript emits "1e+21" / "1e-7" (no
	// zero-padded exponent).
	if i := bytes.IndexByte([]byte(s), 'e'); i >= 0 {
		mantissa, exp := s[:i], s[i+1:]
		sign := ""
		if exp[0] == '+' || exp[0] == '-' {
			sign, exp = string(exp[0]), exp[1:]
		}
		for len(exp) > 1 && exp[0] == '0' {
			exp = exp[1:]
		}
		s = mantissa + "e" + sign + exp
	}
	return s, nil
}

// writeJSONString emits a JSON string using the minimal escaping required by
// RFC 8785: the two mandatory escapes, the short forms for the control
// characters that have them, \u00xx for the remaining control characters, and
// literal UTF-8 for everything else.
func writeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
