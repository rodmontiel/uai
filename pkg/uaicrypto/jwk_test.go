package uaicrypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// TestThumbprintMatchesRFC8037 checks the implementation against the worked
// example in RFC 8037 appendix A.3.
//
// An external vector is the only thing that proves interoperability. A test
// that hashes our own output and compares it to our own output would pass just
// as happily with a thumbprint no other implementation computes.
func TestThumbprintMatchesRFC8037(t *testing.T) {
	jwk := uaicrypto.JWK{
		Kty: "OKP", Crv: "Ed25519",
		X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	}
	sum, err := jwk.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	const want = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	if got := base64.RawURLEncoding.EncodeToString(sum); got != want {
		t.Errorf("thumbprint = %s, want %s (RFC 8037 A.3)", got, want)
	}
}

// TestThumbprintIgnoresOptionalMembers: RFC 7638 hashes the required members
// only, so renaming or annotating a key must not change what it identifies.
func TestThumbprintIgnoresOptionalMembers(t *testing.T) {
	base := uaicrypto.JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	annotated := base
	annotated.Kid = "key-7"
	annotated.Alg = "EdDSA"
	annotated.Use = "sig"

	a, err := base.ThumbprintString()
	if err != nil {
		t.Fatal(err)
	}
	b, err := annotated.ThumbprintString()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("optional members changed the thumbprint: %s vs %s", a, b)
	}
}

// TestThumbprintSeparatesDistinctKeys: two different keys must never share a
// thumbprint, since the registration proof uses it to name a subject.
func TestThumbprintSeparatesDistinctKeys(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		_, pub, err := uaicrypto.GenerateEd25519Signer("did:key:x#k")
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := uaicrypto.JWKFromPublic(pub)
		if err != nil {
			t.Fatal(err)
		}
		tp, err := jwk.ThumbprintString()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tp] {
			t.Fatalf("two distinct keys produced the thumbprint %s", tp)
		}
		seen[tp] = true
	}
}

// TestRoundTripPreservesKeys covers both curves of UAI-CS-1.
func TestRoundTripPreservesKeys(t *testing.T) {
	_, ed, err := uaicrypto.GenerateEd25519Signer("did:key:x#k")
	if err != nil {
		t.Fatal(err)
	}
	_, p256, err := uaicrypto.GenerateECDSASigner(uaicrypto.AlgES256, "did:key:x#k")
	if err != nil {
		t.Fatal(err)
	}
	_, p384, err := uaicrypto.GenerateECDSASigner(uaicrypto.AlgES384, "did:key:x#k")
	if err != nil {
		t.Fatal(err)
	}
	for name, pub := range map[string]any{"Ed25519": ed, "P-256": p256, "P-384": p384} {
		jwk, err := uaicrypto.JWKFromPublic(pub)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		back, err := jwk.Public()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		again, err := uaicrypto.JWKFromPublic(back)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if again != jwk {
			t.Errorf("%s did not round-trip: %+v vs %+v", name, again, jwk)
		}
	}
}

// TestCoordinatesAreFixedWidth: a short big-endian coordinate encodes the same
// point as a padded one. If both were accepted, one key would have two
// thumbprints and could be vouched for under one and used under the other.
func TestCoordinatesAreFixedWidth(t *testing.T) {
	// Find a P-256 key whose X coordinate has a leading zero byte, so the
	// unpadded encoding is genuinely shorter.
	var short *ecdsa.PublicKey
	for i := 0; i < 4000 && short == nil; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if len(k.PublicKey.X.Bytes()) < 32 {
			short = &k.PublicKey
		}
	}
	if short == nil {
		t.Skip("no short-X key found in the sample; the padding path is covered by the round-trip test")
	}
	jwk, err := uaicrypto.JWKFromPublic(short)
	if err != nil {
		t.Fatal(err)
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatal(err)
	}
	if len(x) != 32 {
		t.Fatalf("encoded X is %d bytes, want 32", len(x))
	}

	// The unpadded spelling of the same point must be refused, not silently
	// accepted as an equivalent key.
	unpadded := jwk
	unpadded.X = base64.RawURLEncoding.EncodeToString(new(big.Int).SetBytes(x).Bytes())
	if _, err := unpadded.Public(); err == nil {
		t.Error("a non-canonical coordinate width was accepted")
	}
}

// TestRejectsBadKeys refuses what must be refused.
func TestRejectsBadKeys(t *testing.T) {
	cases := map[string]uaicrypto.JWK{
		"unsupported type":  {Kty: "RSA", X: "AQAB"},
		"unsupported curve": {Kty: "EC", Crv: "secp256k1", X: "AA", Y: "AA"},
		"empty coordinate":  {Kty: "OKP", Crv: "Ed25519", X: ""},
		"bad base64":        {Kty: "OKP", Crv: "Ed25519", X: "not base64!!"},
		"wrong length":      {Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString([]byte("short"))},
		"point off curve": {Kty: "EC", Crv: "P-256",
			X: strings.Repeat("A", 43), Y: strings.Repeat("A", 43)},
	}
	for name, jwk := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := jwk.Public(); err == nil {
				t.Error("accepted a key that must be refused")
			}
			if _, err := jwk.Thumbprint(); err == nil {
				t.Error("produced a thumbprint for a key that cannot be parsed")
			}
		})
	}
}
