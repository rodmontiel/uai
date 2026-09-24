package uaicrypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// --- RFC 8785 canonicalization -------------------------------------------

func TestCanonicalizeSortsKeysAndStripsWhitespace(t *testing.T) {
	in := []byte(`{ "b": 1, "a": 2, "c": { "z": true, "y": null } }`)
	got, err := CanonicalizeJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1,"c":{"y":null,"z":true}}`
	if string(got) != want {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
}

func TestCanonicalizeNumbers(t *testing.T) {
	// ECMAScript Number::toString, as required by RFC 8785 section 3.2.2.3.
	cases := map[string]string{
		`{"n":1}`:            `{"n":1}`,
		`{"n":1.0}`:          `{"n":1}`,
		`{"n":-0}`:           `{"n":0}`,
		`{"n":1e2}`:          `{"n":100}`,
		`{"n":0.000001}`:     `{"n":0.000001}`,
		`{"n":1e21}`:         `{"n":1e+21}`,
		`{"n":1e-7}`:         `{"n":1e-7}`,
		`{"n":1.5e300}`:      `{"n":1.5e+300}`,
		`{"n":333333333.33}`: `{"n":333333333.33}`,
	}
	for in, want := range cases {
		got, err := CanonicalizeJSON([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if string(got) != want {
			t.Errorf("CanonicalizeJSON(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestCanonicalizeStringEscaping(t *testing.T) {
	// Only the two mandatory escapes plus the short forms survive; other
	// control characters become \u00xx and printable characters stay literal.
	in := []byte(`{"s":"a\"b\\c\nd\u0007eé"}`)
	got, err := CanonicalizeJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"s":"a\"b\\c\nd\u0007e` + "é" + `"}`
	if string(got) != want {
		t.Fatalf("canonical = %q, want %q", got, want)
	}
}

func TestCanonicalizeIsStableAcrossEquivalentInputs(t *testing.T) {
	// Two spellings of the same logical object must produce identical bytes:
	// this is the property every signature in UAI depends on.
	a := []byte(`{"agent":"uai:agent:X","seq":5,"nested":{"b":2,"a":1}}`)
	b := []byte("{\n  \"seq\": 5.0,\n  \"nested\": {\"a\": 1, \"b\": 2},\n  \"agent\": \"uai:agent:X\"\n}")
	ca, err := CanonicalizeJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := CanonicalizeJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, cb) {
		t.Fatalf("equivalent documents canonicalized differently:\n%s\n%s", ca, cb)
	}
}

func TestCanonicalizeUTF16KeyOrdering(t *testing.T) {
	// RFC 8785 orders member names by UTF-16 code units, which differs from
	// Go's byte ordering once a name is outside the Basic Multilingual Plane.
	in := []byte(`{"😀":1,"דּ":2}`)
	got, err := CanonicalizeJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	// U+FB33 encodes as the single unit 0xFB33; U+1F600 as a surrogate pair
	// starting at 0xD83D, which therefore sorts first.
	if !strings.HasPrefix(string(got), `{"`+"\U0001F600"+`"`) {
		t.Fatalf("UTF-16 ordering not applied: %s", got)
	}
}

func TestCanonicalizeRejectsNonFinite(t *testing.T) {
	if _, err := Canonicalize(map[string]any{"n": json.Number("1e999")}); err == nil {
		t.Fatal("expected an error for a non-finite number")
	}
}

// --- domain separation ----------------------------------------------------

func TestDigestIsDomainSeparated(t *testing.T) {
	payload := []byte(`{"a":1}`)
	d1, err := Digest(DomainAttestation, payload)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Digest(DomainVote, payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(d1, d2) {
		t.Fatal("identical payloads in different domains produced the same digest")
	}
}

func TestUnknownDomainRejected(t *testing.T) {
	if _, err := Digest(Domain("UAI-v1:not-registered"), []byte("x")); err == nil {
		t.Fatal("unknown domain was accepted")
	}
}

func TestDigestWireFormat(t *testing.T) {
	sum, err := Digest(DomainAttestation, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	s := FormatDigest(sum)
	if !strings.HasPrefix(s, "sha256:") || len(s) != len("sha256:")+64 {
		t.Fatalf("wire form = %q", s)
	}
	back, err := ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, sum) {
		t.Fatal("digest did not survive the wire form round trip")
	}
	for _, bad := range []string{"deadbeef", "sha256:zz", "sha256:aa"} {
		if _, err := ParseDigest(bad); err == nil {
			t.Errorf("ParseDigest(%q) succeeded, want error", bad)
		}
	}
}

// --- commitments ----------------------------------------------------------

func TestCommitmentOpensAndHidesContent(t *testing.T) {
	salt, err := Salt()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("customer@example.com")
	c, err := Commit(salt, content)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCommitment(c, salt, content) {
		t.Fatal("commitment did not open with its own salt and content")
	}
	if VerifyCommitment(c, salt, []byte("someone@else.com")) {
		t.Fatal("commitment opened with the wrong content")
	}
	other, err := Salt()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyCommitment(c, other, content) {
		t.Fatal("commitment opened with the wrong salt")
	}
}

// TestCommitmentIsSaltedNotBareHash is INV-008 on the way IN.
//
// The contracts refuse any parameter that could carry personal data, which
// stops a string. It cannot stop SHA-256("alice@example.com") -- 32 bytes that
// look exactly like a commitment and are recoverable from a wordlist in
// seconds. §19.3's answer is the salt, and this is where that is enforced:
// the same content must commit differently every time.
func TestCommitmentIsSaltedNotBareHash(t *testing.T) {
	// Two commitments to identical low-entropy content must differ, otherwise
	// publishing the commitment on-chain would publish the content.
	content := []byte("YES")
	s1, _ := Salt()
	s2, _ := Salt()
	c1, err := Commit(s1, content)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Commit(s2, content)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("identical content produced identical commitments: the salt is not in effect")
	}
}

func TestCommitRejectsShortSalt(t *testing.T) {
	if _, err := Commit(make([]byte, SaltLen-1), []byte("x")); err == nil {
		t.Fatal("a short salt was accepted")
	}
}

func TestCryptoShredding(t *testing.T) {
	// Destroying the salt makes the content unrecoverable while the commitment
	// -- and therefore every proof derived from it -- stays valid.
	salt, _ := Salt()
	content := []byte("evidence payload")
	c, err := CommitObject(salt, map[string]any{"data": string(content)})
	if err != nil {
		t.Fatal(err)
	}
	shredded := make([]byte, SaltLen) // salt destroyed
	if VerifyCommitment(c, shredded, content) {
		t.Fatal("commitment opened after the salt was destroyed")
	}
	if len(c) != 32 {
		t.Fatalf("commitment length = %d, want 32", len(c))
	}
}

// --- signatures -----------------------------------------------------------

func TestSignVerifyEd25519(t *testing.T) {
	signer, pub, err := GenerateEd25519Signer("did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"event_id": "01JY8RA3C7K2V9M0QW4T6Z8XPD", "sequence": 418}
	sig, err := SignObject(signer, DomainAttestation, payload)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Alg != AlgEdDSA || sig.KID != signer.KID() || sig.Domain != DomainAttestation {
		t.Fatalf("unexpected envelope: %+v", sig)
	}
	if err := VerifyObject(pub, DomainAttestation, payload, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignVerifyES256AndES384(t *testing.T) {
	for _, alg := range []Algorithm{AlgES256, AlgES384} {
		t.Run(string(alg), func(t *testing.T) {
			signer, pub, err := GenerateECDSASigner(alg, "did:uai:delegate:01JY8R9ZAF392N7QX2T81JH6KM#wa-1")
			if err != nil {
				t.Fatal(err)
			}
			payload := map[string]any{"vote": "YES", "case_id": "UAI-INC-000041"}
			sig, err := SignObject(signer, DomainVote, payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyObject(pub, DomainVote, payload, sig); err != nil {
				t.Fatalf("verify: %v", err)
			}
			raw, _ := sig.Bytes()
			want := map[Algorithm]int{AlgES256: 64, AlgES384: 96}[alg]
			if len(raw) != want {
				t.Fatalf("signature is %d bytes, want fixed-width R||S of %d", len(raw), want)
			}
		})
	}
}

func TestCrossDomainReplayRejected(t *testing.T) {
	// The core property of domain separation: a signature made over a vote
	// must not verify as an attestation, even though the bytes are valid.
	signer, pub, err := GenerateEd25519Signer("did:uai:delegate:01JY8R9ZAF392N7QX2T81JH6KM#key-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"x": 1}
	sig, err := SignObject(signer, DomainVote, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyObject(pub, DomainAttestation, payload, sig); err == nil {
		t.Fatal("a vote signature verified as an attestation")
	}

	// Relabelling the envelope does not help: the signed bytes include the
	// original domain, so verification still fails.
	forged := sig
	forged.Domain = DomainAttestation
	if err := VerifyObject(pub, DomainAttestation, payload, forged); err == nil {
		t.Fatal("relabelling the domain defeated domain separation")
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	signer, pub, err := GenerateEd25519Signer("did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"amount": 100}
	sig, err := SignObject(signer, DomainAttestation, payload)
	if err != nil {
		t.Fatal(err)
	}
	payload["amount"] = 1000000
	if err := VerifyObject(pub, DomainAttestation, payload, sig); err == nil {
		t.Fatal("a tampered payload verified")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	signer, _, err := GenerateEd25519Signer("did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1")
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, err := GenerateEd25519Signer("did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-2")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignObject(signer, DomainAttestation, map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyObject(otherPub, DomainAttestation, map[string]any{"a": 1}, sig); err == nil {
		t.Fatal("a signature verified under an unrelated key")
	}
}

func TestKeyTypeMismatchRejected(t *testing.T) {
	signer, _, err := GenerateECDSASigner(AlgES256, "kid")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignObject(signer, DomainVote, map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	var notAKey ed25519.PublicKey = make([]byte, ed25519.PublicKeySize)
	if err := VerifyObject(notAKey, DomainVote, map[string]any{"a": 1}, sig); err == nil {
		t.Fatal("an ECDSA signature verified against an Ed25519 key")
	}
}

func TestSignatureSurvivesJSONRoundTrip(t *testing.T) {
	signer, pub, err := GenerateEd25519Signer("did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1")
	if err != nil {
		t.Fatal(err)
	}
	type envelope struct {
		Payload   map[string]any `json:"payload"`
		Signature Signature      `json:"signature"`
	}
	payload := map[string]any{"purpose": "customer_support", "seq": 7}
	sig, err := SignObject(signer, DomainAttestation, payload)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(envelope{payload, sig})
	if err != nil {
		t.Fatal(err)
	}
	var back envelope
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	if err := VerifyObject(pub, DomainAttestation, back.Payload, back.Signature); err != nil {
		t.Fatalf("signature did not survive a JSON round trip: %v", err)
	}
}
