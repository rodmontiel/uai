package credential

import (
	"fmt"
	"math/big"
	"strings"
)

// The Data Integrity specification encodes proofValue as multibase. The
// ecosystem emits base58btc (the "z" prefix), so UAI emits it too: being the one
// implementation that encodes proofs differently would undercut the
// interoperability this whole credential format exists for.
//
// Decoding accepts "u" (base64url, no padding) as well, because it is equally
// valid multibase and a conformant producer may use it. Encoding never does.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Index = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i, c := range base58Alphabet {
		t[byte(c)] = int8(i)
	}
	return t
}()

// base58Encode encodes bytes as base58btc.
func base58Encode(b []byte) string {
	// Leading zero bytes are not representable positionally -- 0x00 and no byte
	// at all are the same number -- so they are carried as explicit '1's.
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, base58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// base58Decode decodes base58btc.
func base58Decode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == base58Alphabet[0] {
		zeros++
	}
	n := new(big.Int)
	radix := big.NewInt(58)
	for i := zeros; i < len(s); i++ {
		v := base58Index[s[i]]
		if v < 0 {
			return nil, fmt.Errorf("credential: %q is not base58btc", s)
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(v)))
	}
	return append(make([]byte, zeros), n.Bytes()...), nil
}

// encodeProofValue renders a signature as multibase base58btc.
func encodeProofValue(sig []byte) string { return "z" + base58Encode(sig) }

// decodeProofValue parses a multibase proofValue.
func decodeProofValue(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("credential: empty proofValue")
	}
	switch s[0] {
	case 'z':
		return base58Decode(s[1:])
	case 'u':
		return decodeBase64URL(s[1:])
	default:
		return nil, fmt.Errorf("credential: unsupported multibase prefix %q; UAI emits base58btc (z)", s[:1])
	}
}

func decodeBase64URL(s string) ([]byte, error) {
	if strings.ContainsAny(s, "=+/") {
		return nil, fmt.Errorf("credential: multibase u is base64url without padding")
	}
	return b64urlDecode(s)
}
