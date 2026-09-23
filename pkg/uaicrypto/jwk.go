package uaicrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK is the subset of RFC 7517 that UAI-CS-1 uses: public keys only, and only
// the curves in the cipher suite.
//
// Private key members are absent by construction rather than by convention. A
// struct that cannot hold "d" cannot accidentally serialize it into a DID
// Document, a credential or a log entry.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	// Kid is optional and is deliberately NOT part of the thumbprint: RFC 7638
	// computes over the required members only, so renaming a key never changes
	// the identity of the key material.
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// ErrUnsupportedKey is returned for key types outside UAI-CS-1.
var ErrUnsupportedKey = fmt.Errorf("uaicrypto: unsupported key type")

// JWKFromPublic converts a public key into its JWK representation.
func JWKFromPublic(pub crypto.PublicKey) (JWK, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", X: b64(k)}, nil
	case *ecdsa.PublicKey:
		crv, size, err := curveParams(k.Curve)
		if err != nil {
			return JWK{}, err
		}
		// Coordinates are fixed-width, left-padded. A short big-endian integer
		// would encode the same point as different bytes, and therefore as a
		// different thumbprint — which would let one key masquerade as two.
		return JWK{Kty: "EC", Crv: crv, X: b64(pad(k.X, size)), Y: b64(pad(k.Y, size))}, nil
	default:
		return JWK{}, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
}

// Public converts a JWK into a crypto.PublicKey, rejecting anything that is not
// a well-formed point on a supported curve.
func (j JWK) Public() (crypto.PublicKey, error) {
	switch {
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		x, err := unb64(j.X, "x")
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("uaicrypto: ed25519 key is %d bytes, want %d", len(x), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(x), nil
	case j.Kty == "EC":
		curve, size, err := curveByName(j.Crv)
		if err != nil {
			return nil, err
		}
		xb, err := unb64(j.X, "x")
		if err != nil {
			return nil, err
		}
		yb, err := unb64(j.Y, "y")
		if err != nil {
			return nil, err
		}
		// Reject non-canonical encodings before touching the curve: RFC 7518
		// fixes the coordinate width, and accepting a short or long encoding
		// would make two spellings of one key produce two thumbprints.
		if len(xb) != size || len(yb) != size {
			return nil, fmt.Errorf("uaicrypto: %s coordinates must be %d bytes, got %d/%d", j.Crv, size, len(xb), len(yb))
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("uaicrypto: jwk point is not on %s", j.Crv)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("%w: %q/%q", ErrUnsupportedKey, j.Kty, j.Crv)
	}
}

// Thumbprint returns the RFC 7638 JWK thumbprint: SHA-256 over a JSON object
// containing only the required members, in lexicographic order, with no
// whitespace.
//
// This is the one digest in UAI that is NOT domain-separated, and the exception
// is deliberate. RFC 7638 defines an interoperable identifier for key material;
// prefixing it with a UAI domain would produce a value that agrees with no
// other implementation on earth, which defeats the only reason to use a
// standard here. It is safe precisely because it is not a signature: nothing
// accepts a thumbprint as authorization, it only names a key.
func (j JWK) Thumbprint() ([]byte, error) {
	var canonical string
	switch {
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		canonical = fmt.Sprintf(`{"crv":%s,"kty":%s,"x":%s}`,
			quote(j.Crv), quote(j.Kty), quote(j.X))
	case j.Kty == "EC":
		canonical = fmt.Sprintf(`{"crv":%s,"kty":%s,"x":%s,"y":%s}`,
			quote(j.Crv), quote(j.Kty), quote(j.X), quote(j.Y))
	default:
		return nil, fmt.Errorf("%w: %q/%q", ErrUnsupportedKey, j.Kty, j.Crv)
	}
	// Validate before hashing: a thumbprint of a key that cannot be parsed
	// would name something unusable, and callers treat a thumbprint as proof
	// that they are talking about a real key.
	if _, err := j.Public(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(canonical))
	return sum[:], nil
}

// ThumbprintString returns the thumbprint in the "sha256:<hex>" wire form used
// everywhere else in UAI.
func (j JWK) ThumbprintString() (string, error) {
	sum, err := j.Thumbprint()
	if err != nil {
		return "", err
	}
	return FormatDigest(sum), nil
}

// ParseJWK decodes a JWK from JSON.
func ParseJWK(raw []byte) (JWK, error) {
	var j JWK
	if err := json.Unmarshal(raw, &j); err != nil {
		return JWK{}, fmt.Errorf("uaicrypto: parse jwk: %w", err)
	}
	return j, nil
}

// PublicFromJWKBytes is the common path: JSON in, verified public key out.
func PublicFromJWKBytes(raw []byte) (crypto.PublicKey, error) {
	j, err := ParseJWK(raw)
	if err != nil {
		return nil, err
	}
	return j.Public()
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s, member string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("uaicrypto: jwk member %q is empty", member)
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("uaicrypto: jwk member %q: %w", member, err)
	}
	return b, nil
}

// quote renders a JSON string. The members involved are base64url and curve
// names, so no escaping is reachable, but encoding/json is used rather than
// string concatenation so that an unexpected input cannot forge JSON structure.
func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

func pad(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func curveParams(c elliptic.Curve) (name string, size int, err error) {
	switch c {
	case elliptic.P256():
		return "P-256", 32, nil
	case elliptic.P384():
		return "P-384", 48, nil
	default:
		return "", 0, fmt.Errorf("%w: curve %s", ErrUnsupportedKey, c.Params().Name)
	}
}

func curveByName(name string) (elliptic.Curve, int, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	default:
		return nil, 0, fmt.Errorf("%w: curve %q", ErrUnsupportedKey, name)
	}
}
