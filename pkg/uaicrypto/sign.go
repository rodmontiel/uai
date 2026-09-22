package uaicrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// Algorithm identifies a signature algorithm from the UAI-CS-1 suite.
type Algorithm string

// UAI-CS-1 algorithms. EdDSA and ES256 are both mandatory to implement for
// verifiers: an Ed25519-only suite would exclude hardware-backed keys, since
// TPMs, Secure Enclave, WebAuthn and most cloud KMS sign with P-256, and
// hardware backing is the main defense against agent key theft (threat T-02).
const (
	AlgEdDSA Algorithm = "EdDSA" // Ed25519, RFC 8032
	AlgES256 Algorithm = "ES256" // ECDSA P-256 with SHA-256
	AlgES384 Algorithm = "ES384" // ECDSA P-384 with SHA-384
)

var (
	// ErrUnsupportedAlgorithm is returned for an algorithm outside UAI-CS-1.
	ErrUnsupportedAlgorithm = errors.New("uaicrypto: unsupported algorithm")
	// ErrDomainMismatch is returned when a signature's declared domain differs
	// from the context it is being verified in.
	ErrDomainMismatch = errors.New("uaicrypto: signature domain does not match verification context")
	// ErrBadSignature is returned when verification fails.
	ErrBadSignature = errors.New("uaicrypto: signature verification failed")
	// ErrKeyMismatch is returned when a key does not match the algorithm.
	ErrKeyMismatch = errors.New("uaicrypto: key type does not match algorithm")
)

// Signature is the UAI signature envelope. The same semantics are carried by
// the JSON-LD Data Integrity form and by COSE/JWS; this is the internal
// representation both encode to.
type Signature struct {
	Alg    Algorithm `json:"alg"`
	KID    string    `json:"kid"`    // DID URL of the verification method
	Domain Domain    `json:"domain"` // domain separation string
	Value  string    `json:"value"`  // base64url, no padding
}

// Bytes decodes the signature value.
func (s Signature) Bytes() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s.Value)
}

// Signer produces UAI signatures over domain-separated payloads.
type Signer interface {
	// Sign returns a signature over DOMAIN || 0x00 || canonical(payload).
	Sign(d Domain, payload []byte) (Signature, error)
	// Algorithm reports the signer's algorithm.
	Algorithm() Algorithm
	// KID returns the DID URL of the verification method.
	KID() string
	// Public returns the public key.
	Public() crypto.PublicKey
}

// ed25519Signer signs with Ed25519.
type ed25519Signer struct {
	key ed25519.PrivateKey
	kid string
}

// NewEd25519Signer wraps an Ed25519 private key.
func NewEd25519Signer(key ed25519.PrivateKey, kid string) Signer {
	return &ed25519Signer{key: key, kid: kid}
}

// GenerateEd25519Signer generates a fresh Ed25519 key. Intended for tests and
// development; production keys are generated inside a TPM, Secure Enclave, HSM
// or cloud KMS and never exist as exportable material.
func GenerateEd25519Signer(kid string) (Signer, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("uaicrypto: generate ed25519: %w", err)
	}
	return &ed25519Signer{key: priv, kid: kid}, pub, nil
}

func (s *ed25519Signer) Algorithm() Algorithm     { return AlgEdDSA }
func (s *ed25519Signer) KID() string              { return s.kid }
func (s *ed25519Signer) Public() crypto.PublicKey { return s.key.Public() }

func (s *ed25519Signer) Sign(d Domain, payload []byte) (Signature, error) {
	in, err := SigningInput(d, payload)
	if err != nil {
		return Signature{}, err
	}
	// Ed25519 hashes the full message internally, so it signs the input directly.
	sig := ed25519.Sign(s.key, in)
	return Signature{
		Alg:    AlgEdDSA,
		KID:    s.kid,
		Domain: d,
		Value:  base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// ecdsaSigner signs with ECDSA P-256 or P-384, emitting fixed-width R||S so
// that signatures are interchangeable with JOSE and WebAuthn.
type ecdsaSigner struct {
	key *ecdsa.PrivateKey
	alg Algorithm
	kid string
}

// NewECDSASigner wraps an ECDSA private key on P-256 or P-384.
func NewECDSASigner(key *ecdsa.PrivateKey, kid string) (Signer, error) {
	alg, err := algForCurve(key.Curve)
	if err != nil {
		return nil, err
	}
	return &ecdsaSigner{key: key, alg: alg, kid: kid}, nil
}

// GenerateECDSASigner generates a fresh ECDSA key for the given algorithm.
func GenerateECDSASigner(alg Algorithm, kid string) (Signer, *ecdsa.PublicKey, error) {
	curve, err := curveForAlg(alg)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("uaicrypto: generate ecdsa: %w", err)
	}
	return &ecdsaSigner{key: key, alg: alg, kid: kid}, &key.PublicKey, nil
}

func (s *ecdsaSigner) Algorithm() Algorithm     { return s.alg }
func (s *ecdsaSigner) KID() string              { return s.kid }
func (s *ecdsaSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s *ecdsaSigner) Sign(d Domain, payload []byte) (Signature, error) {
	in, err := SigningInput(d, payload)
	if err != nil {
		return Signature{}, err
	}
	digest, size, err := hashForAlg(s.alg, in)
	if err != nil {
		return Signature{}, err
	}
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest)
	if err != nil {
		return Signature{}, fmt.Errorf("uaicrypto: ecdsa sign: %w", err)
	}
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	sv.FillBytes(sig[size:])
	return Signature{
		Alg:    s.alg,
		KID:    s.kid,
		Domain: d,
		Value:  base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks sig over payload in the given domain, using pub.
//
// The domain argument is the context the caller is verifying in. A signature
// whose declared domain differs is rejected even when it is cryptographically
// valid — that check is what prevents a signature captured in one context from
// being replayed in another.
func Verify(pub crypto.PublicKey, d Domain, payload []byte, sig Signature) error {
	if sig.Domain != d {
		return fmt.Errorf("%w: signed for %q, verifying as %q", ErrDomainMismatch, sig.Domain, d)
	}
	in, err := SigningInput(d, payload)
	if err != nil {
		return err
	}
	raw, err := sig.Bytes()
	if err != nil {
		return fmt.Errorf("uaicrypto: decode signature: %w", err)
	}

	switch sig.Alg {
	case AlgEdDSA:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: want ed25519.PublicKey, got %T", ErrKeyMismatch, pub)
		}
		if len(raw) != ed25519.SignatureSize || !ed25519.Verify(key, in, raw) {
			return ErrBadSignature
		}
		return nil

	case AlgES256, AlgES384:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: want *ecdsa.PublicKey, got %T", ErrKeyMismatch, pub)
		}
		curve, err := curveForAlg(sig.Alg)
		if err != nil {
			return err
		}
		if key.Curve != curve {
			return fmt.Errorf("%w: key is on %s, algorithm %s requires %s",
				ErrKeyMismatch, key.Curve.Params().Name, sig.Alg, curve.Params().Name)
		}
		digest, size, err := hashForAlg(sig.Alg, in)
		if err != nil {
			return err
		}
		if len(raw) != 2*size {
			return fmt.Errorf("%w: signature is %d bytes, want %d", ErrBadSignature, len(raw), 2*size)
		}
		r := new(big.Int).SetBytes(raw[:size])
		s := new(big.Int).SetBytes(raw[size:])
		if !ecdsa.Verify(key, digest, r, s) {
			return ErrBadSignature
		}
		return nil

	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, sig.Alg)
	}
}

// VerifyObject canonicalizes v and verifies sig over its canonical form.
func VerifyObject(pub crypto.PublicKey, d Domain, v any, sig Signature) error {
	canonical, err := Canonicalize(v)
	if err != nil {
		return err
	}
	return Verify(pub, d, canonical, sig)
}

// SignObject canonicalizes v and signs its canonical form.
func SignObject(s Signer, d Domain, v any) (Signature, error) {
	canonical, err := Canonicalize(v)
	if err != nil {
		return Signature{}, err
	}
	return s.Sign(d, canonical)
}

func curveForAlg(alg Algorithm) (elliptic.Curve, error) {
	switch alg {
	case AlgES256:
		return elliptic.P256(), nil
	case AlgES384:
		return elliptic.P384(), nil
	default:
		return nil, fmt.Errorf("%w: %q is not an ECDSA algorithm", ErrUnsupportedAlgorithm, alg)
	}
}

func algForCurve(c elliptic.Curve) (Algorithm, error) {
	switch c {
	case elliptic.P256():
		return AlgES256, nil
	case elliptic.P384():
		return AlgES384, nil
	default:
		return "", fmt.Errorf("%w: curve %s is not in UAI-CS-1", ErrUnsupportedAlgorithm, c.Params().Name)
	}
}

// hashForAlg returns the digest and the fixed component width for an algorithm.
func hashForAlg(alg Algorithm, in []byte) ([]byte, int, error) {
	switch alg {
	case AlgES256:
		sum := sha256.Sum256(in)
		return sum[:], 32, nil
	case AlgES384:
		sum := sha512.Sum384(in)
		return sum[:], 48, nil
	default:
		return nil, 0, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}
}

// --- RFC 9421 HTTP message signatures ---------------------------------------
//
// These two functions are the ONLY place in UAI where a signature is produced
// or verified without the DOMAIN || 0x00 prefix, and the exception is
// deliberate: an RFC 9421 signature base already carries the domain inside the
// signed bytes, as the `tag` parameter of @signature-params. Prefixing it again
// would add no security property and would break interoperability with standard
// RFC 9421 verifiers.
//
// The caller MUST still check the tag against the expected domain. pkg/pop does
// that; nothing else should call these functions.

// rawSigner is unexported on purpose. Domain-less signing is available only to
// the signers defined in this package, so an external implementation of Signer
// cannot be used to bypass domain separation.
type rawSigner interface {
	signRaw(message []byte) ([]byte, error)
}

func (s *ed25519Signer) signRaw(message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

func (s *ecdsaSigner) signRaw(message []byte) ([]byte, error) {
	digest, size, err := hashForAlg(s.alg, message)
	if err != nil {
		return nil, err
	}
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest)
	if err != nil {
		return nil, fmt.Errorf("uaicrypto: ecdsa sign: %w", err)
	}
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	sv.FillBytes(out[size:])
	return out, nil
}

// HTTPSignatureAlg maps a UAI algorithm to its RFC 9421 registry name.
func HTTPSignatureAlg(alg Algorithm) (string, error) {
	switch alg {
	case AlgEdDSA:
		return "ed25519", nil
	case AlgES256:
		return "ecdsa-p256-sha256", nil
	case AlgES384:
		return "ecdsa-p384-sha384", nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}
}

// AlgorithmFromHTTP maps an RFC 9421 registry name back to a UAI algorithm.
func AlgorithmFromHTTP(name string) (Algorithm, error) {
	switch name {
	case "ed25519":
		return AlgEdDSA, nil
	case "ecdsa-p256-sha256":
		return AlgES256, nil
	case "ecdsa-p384-sha384":
		return AlgES384, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, name)
	}
}

// SignHTTPSignatureBase signs an RFC 9421 signature base. See the note above:
// the domain lives inside the base, not in a prefix.
func SignHTTPSignatureBase(s Signer, base []byte) (httpAlg string, sig []byte, err error) {
	raw, ok := s.(rawSigner)
	if !ok {
		return "", nil, errors.New("uaicrypto: signer does not support HTTP message signatures")
	}
	httpAlg, err = HTTPSignatureAlg(s.Algorithm())
	if err != nil {
		return "", nil, err
	}
	sig, err = raw.signRaw(base)
	if err != nil {
		return "", nil, err
	}
	return httpAlg, sig, nil
}

// VerifyHTTPSignatureBase verifies an RFC 9421 signature base.
func VerifyHTTPSignatureBase(pub crypto.PublicKey, httpAlg string, base, sig []byte) error {
	alg, err := AlgorithmFromHTTP(httpAlg)
	if err != nil {
		return err
	}
	switch alg {
	case AlgEdDSA:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: want ed25519.PublicKey, got %T", ErrKeyMismatch, pub)
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, base, sig) {
			return ErrBadSignature
		}
		return nil
	case AlgES256, AlgES384:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: want *ecdsa.PublicKey, got %T", ErrKeyMismatch, pub)
		}
		curve, err := curveForAlg(alg)
		if err != nil {
			return err
		}
		if key.Curve != curve {
			return fmt.Errorf("%w: key is on %s, %s requires %s",
				ErrKeyMismatch, key.Curve.Params().Name, httpAlg, curve.Params().Name)
		}
		digest, size, err := hashForAlg(alg, base)
		if err != nil {
			return err
		}
		if len(sig) != 2*size {
			return fmt.Errorf("%w: signature is %d bytes, want %d", ErrBadSignature, len(sig), 2*size)
		}
		r := new(big.Int).SetBytes(sig[:size])
		sv := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(key, digest, r, sv) {
			return ErrBadSignature
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}
}
