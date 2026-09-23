package credential

import (
	"bytes"
	"testing"
)

// TestBase58KnownVectors checks the encoder against the canonical base58btc
// vectors rather than against itself.
//
// A round-trip test passes happily with a wrong alphabet or with leading zeros
// dropped, and dropping leading zeros silently shortens a signature — which
// then fails to verify for reasons that look like a key problem.
func TestBase58KnownVectors(t *testing.T) {
	cases := []struct {
		in  []byte
		out string
	}{
		{[]byte{}, ""},
		{[]byte{0x00}, "1"},
		{[]byte{0x00, 0x00, 0x00}, "111"},
		{[]byte{0x61}, "2g"},
		{[]byte("hello world"), "StV1DL6CwTryKyV"},
		{[]byte{0x00, 0x61}, "12g"},
		{[]byte{0xff, 0xff}, "LUv"},
	}
	for _, tc := range cases {
		if got := base58Encode(tc.in); got != tc.out {
			t.Errorf("base58Encode(%x) = %q, want %q", tc.in, got, tc.out)
		}
		back, err := base58Decode(tc.out)
		if err != nil {
			t.Fatalf("base58Decode(%q): %v", tc.out, err)
		}
		if !bytes.Equal(back, tc.in) {
			t.Errorf("base58Decode(%q) = %x, want %x", tc.out, back, tc.in)
		}
	}
}

// TestLeadingZerosSurvive: an Ed25519 signature starting with 0x00 is ordinary,
// and an encoder that loses that byte produces a 63-byte signature.
func TestLeadingZerosSurvive(t *testing.T) {
	sig := make([]byte, 64)
	sig[0], sig[1] = 0x00, 0x00
	for i := 2; i < 64; i++ {
		sig[i] = byte(i)
	}
	back, err := decodeProofValue(encodeProofValue(sig))
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 64 {
		t.Fatalf("decoded %d bytes, want 64: leading zeros were lost", len(back))
	}
	if !bytes.Equal(back, sig) {
		t.Error("the signature did not survive the encoding")
	}
}

func TestRejectsBadMultibase(t *testing.T) {
	for _, s := range []string{"", "x0123", "zO0Il", "u!!!", "uYWJj="} {
		if _, err := decodeProofValue(s); err == nil {
			t.Errorf("decodeProofValue(%q) was accepted", s)
		}
	}
}

// TestAcceptsBase64URLMultibase: "u" is valid multibase and a conformant
// producer may use it, so verification must not depend on our own choice.
func TestAcceptsBase64URLMultibase(t *testing.T) {
	want := []byte{0x00, 0x01, 0xfe, 0xff}
	got, err := decodeProofValue("u" + "AAH-_w")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}
