// Package keyfile loads and writes the issuer signing key.
//
// It lives in internal/ rather than pkg/ for one reason: pkg/uaicrypto's JWK
// type cannot represent a private key at all, which is what stops a private key
// ever being serialized into a DID Document, a credential or a log entry. Key
// material handling is a server concern, so it stays on the server side of that
// line.
package keyfile

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// privateJWK is an Ed25519 private key in JWK form (RFC 8037).
type privateJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	D   string `json:"d"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
}

// Generate creates a new Ed25519 issuer key and writes it to path.
//
// The file is created with 0600 and refuses to overwrite: silently replacing an
// issuer key would invalidate every credential ever issued under it, and the
// operator would find out from verification failures rather than from us.
func Generate(path, kid string) error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("keyfile: generate: %w", err)
	}
	doc := privateJWK{
		Kty: "OKP", Crv: "Ed25519", Kid: kid,
		D: base64.RawURLEncoding.EncodeToString(priv.Seed()),
		X: base64.RawURLEncoding.EncodeToString(pub),
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	return nil
}

// Load reads a signing key and returns a signer bound to kid.
func Load(path, kid string) (uaicrypto.Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	// A key readable by every account on the host is not a key, and this is the
	// kind of thing nobody notices until it is quoted in an incident report.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("keyfile: %s is mode %#o; it must not be readable by group or other", path, perm)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	var doc privateJWK
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("keyfile: %s: %w", path, err)
	}
	if doc.Kty != "OKP" || doc.Crv != "Ed25519" {
		return nil, fmt.Errorf("keyfile: %s holds %q/%q, want OKP/Ed25519", path, doc.Kty, doc.Crv)
	}
	seed, err := base64.RawURLEncoding.DecodeString(doc.D)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s: private member: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("keyfile: %s: seed is %d bytes, want %d", path, len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// The public member must match the private one. A file where they disagree
	// produces signatures nobody can verify, and the failure would surface as a
	// mysterious verification error instead of a startup error.
	if doc.X != "" {
		want := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
		if doc.X != want {
			return nil, fmt.Errorf("keyfile: %s: the public member does not match the private key", path)
		}
	}
	return uaicrypto.NewEd25519Signer(priv, kid), nil
}

// PublicJWK returns the public half of a key file, for publishing in an
// authority set.
func PublicJWK(path string) (uaicrypto.JWK, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return uaicrypto.JWK{}, fmt.Errorf("keyfile: %w", err)
	}
	var doc privateJWK
	if err := json.Unmarshal(body, &doc); err != nil {
		return uaicrypto.JWK{}, fmt.Errorf("keyfile: %s: %w", path, err)
	}
	// Derived from the private half rather than copied from the file: a public
	// member that disagrees with the private key would publish a key nobody
	// can verify against, and the mismatch would only surface much later.
	seed, err := base64.RawURLEncoding.DecodeString(doc.D)
	if err != nil || len(seed) != ed25519.SeedSize {
		return uaicrypto.JWK{}, fmt.Errorf("keyfile: %s: unusable private member", path)
	}
	jwk, err := uaicrypto.JWKFromPublic(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		return uaicrypto.JWK{}, err
	}
	jwk.Kid = doc.Kid
	return jwk, nil
}
