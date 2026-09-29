package federation_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/federation"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

const (
	asnA   = federation.ASN(1001)
	asnB   = federation.ASN(2001)
	ulidA  = "01JY8RA3C7K2V9M0QW4T6Z8XPD"
	digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func registryKey(t *testing.T, asn federation.ASN) (uaicrypto.Signer, any, uaicrypto.JWK) {
	t.Helper()
	s, pub, err := uaicrypto.GenerateEd25519Signer(federation.RegistryDID(asn) + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := uaicrypto.JWKFromPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	return s, pub, jwk
}

func helloFrom(t *testing.T, asn federation.ASN, at time.Time) (federation.Hello, any) {
	t.Helper()
	signer, pub, jwk := registryKey(t, asn)
	h, err := federation.Sign(signer, federation.Hello{
		UAIASN: asn, RegistryDID: federation.RegistryDID(asn), RegistryName: "Test Registry",
		Endpoint: "https://r.example/federation", PublicJWK: jwk,
		Timestamp: uaicrypto.NewTimestamp(at), Nonce: "0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, pub
}

func announcementFrom(t *testing.T, origin federation.ASN, at time.Time, seq int64) (federation.Announcement, any) {
	t.Helper()
	signer, pub, _ := registryKey(t, origin)
	a, err := federation.SignAnnouncement(signer, federation.Announcement{
		OriginUAIASN: origin, AgentDID: federation.AgentDID(origin, ulidA),
		AgentStatus: "ACTIVE", Timestamp: uaicrypto.NewTimestamp(at),
		Sequence: seq, CredentialHash: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, pub
}

// ── registry identity ───────────────────────────────────────────────────────

func TestRegistryDIDRoundTrips(t *testing.T) {
	for _, asn := range []federation.ASN{1, 1001, 4294967295} {
		did := federation.RegistryDID(asn)
		got, err := federation.ParseRegistryDID(did)
		if err != nil {
			t.Fatalf("%s: %v", did, err)
		}
		if got != asn {
			t.Errorf("%s parsed as AS%d", did, got)
		}
	}
	for _, bad := range []string{"", "did:uai:agent:01JY8RA3C7K2V9M0QW4T6Z8XPD",
		"did:uai-registry:0", "did:uai-registry:abc", "did:uai-registry:1001x"} {
		if _, err := federation.ParseRegistryDID(bad); err == nil {
			t.Errorf("%q was accepted as a registry DID", bad)
		}
	}
}

// TestRegistrySignsAndVerifies is the base case every other test varies from.
func TestRegistrySignsAndVerifies(t *testing.T) {
	h, pub := helloFrom(t, asnA, time.Now())
	if h.Type != federation.TypeHello || h.ProtocolVersion != federation.ProtocolVersion {
		t.Fatalf("Sign did not stamp the envelope: %+v", h)
	}
	if err := h.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(pub); err != nil {
		t.Fatal(err)
	}
}

// TestModifiedHelloFailsVerification: every member is covered, so changing any
// of them has to break the signature. A payload where only some members were
// signed would let a peer be renamed, re-endpointed, or renumbered in flight.
func TestModifiedHelloFailsVerification(t *testing.T) {
	mutations := map[string]func(*federation.Hello){
		"the ASN":       func(h *federation.Hello) { h.UAIASN = asnB },
		"the DID":       func(h *federation.Hello) { h.RegistryDID = federation.RegistryDID(asnB) },
		"the name":      func(h *federation.Hello) { h.RegistryName = "Somebody Else" },
		"the endpoint":  func(h *federation.Hello) { h.Endpoint = "https://attacker.example" },
		"the nonce":     func(h *federation.Hello) { h.Nonce = "ffffffffffffffff" },
		"the timestamp": func(h *federation.Hello) { h.Timestamp = uaicrypto.NewTimestamp(time.Now().Add(time.Hour)) },
	}
	for what, mutate := range mutations {
		t.Run(what, func(t *testing.T) {
			h, pub := helloFrom(t, asnA, time.Now())
			mutate(&h)
			if err := h.Verify(pub); err == nil {
				t.Fatalf("changing %s did not break the signature", what)
			}
		})
	}
}

func TestUnsignedHelloIsRefused(t *testing.T) {
	h, pub := helloFrom(t, asnA, time.Now())
	h.Signature = uaicrypto.Signature{}
	if err := h.Verify(pub); err == nil {
		t.Fatal("an unsigned hello verified")
	}
}

// TestHelloSignedInAnotherDomainIsRefused. Domain separation is the only thing
// stopping a signature made for one purpose being presented for another.
func TestHelloSignedInAnotherDomainIsRefused(t *testing.T) {
	signer, pub, jwk := registryKey(t, asnA)
	h := federation.Hello{
		UAIASN: asnA, RegistryDID: federation.RegistryDID(asnA), RegistryName: "R",
		Endpoint: "https://r.example", PublicJWK: jwk,
		Timestamp: uaicrypto.NewTimestamp(time.Now()), Nonce: "abc",
		Type: federation.TypeHello, ProtocolVersion: federation.ProtocolVersion,
	}
	payload, err := h.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	// A perfectly good signature, made for attestations.
	sig, err := signer.Sign(uaicrypto.DomainAttestation, payload)
	if err != nil {
		t.Fatal(err)
	}
	h.Signature = sig
	if err := h.Verify(pub); err == nil {
		t.Fatal("an attestation signature was accepted as a registry hello")
	}
}

// TestHelloWhoseDIDAndASNDisagree: a message naming two registries.
func TestHelloWhoseDIDAndASNDisagree(t *testing.T) {
	h, _ := helloFrom(t, asnA, time.Now())
	h.RegistryDID = federation.RegistryDID(asnB)
	if err := h.Validate(time.Now()); err == nil {
		t.Fatal("a hello claiming two different registries validated")
	}
}

// TestExpiredHelloIsRefused, in both directions: a message from the past can be
// replayed, and one from the future is a clock nobody can reason about.
func TestExpiredHelloIsRefused(t *testing.T) {
	for what, at := range map[string]time.Time{
		"too old":    time.Now().Add(-federation.MaxClockSkew - time.Minute),
		"too future": time.Now().Add(federation.MaxClockSkew + time.Minute),
	} {
		t.Run(what, func(t *testing.T) {
			h, _ := helloFrom(t, asnA, at)
			if err := h.Validate(time.Now()); err == nil {
				t.Fatalf("a hello %s was accepted", what)
			}
		})
	}
}

// ── announcements ───────────────────────────────────────────────────────────

func TestAnnouncementSignsAndVerifies(t *testing.T) {
	a, pub := announcementFrom(t, asnA, time.Now(), 1)
	if err := a.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(pub); err != nil {
		t.Fatal(err)
	}
}

func TestModifiedAnnouncementFailsVerification(t *testing.T) {
	mutations := map[string]func(*federation.Announcement){
		"the agent DID": func(a *federation.Announcement) {
			a.AgentDID = federation.AgentDID(asnA, "01JY8RA3C7K2V9M0QW4T6Z8XPE")
		},
		"the status":          func(a *federation.Announcement) { a.AgentStatus = "REVOKED" },
		"the sequence":        func(a *federation.Announcement) { a.Sequence = 9999 },
		"the credential hash": func(a *federation.Announcement) { a.CredentialHash = strings.Replace(digest, "a", "b", 1) },
		"the origin":          func(a *federation.Announcement) { a.OriginUAIASN = asnB },
	}
	for what, mutate := range mutations {
		t.Run(what, func(t *testing.T) {
			a, pub := announcementFrom(t, asnA, time.Now(), 1)
			mutate(&a)
			if err := a.Verify(pub); err == nil {
				t.Fatalf("changing %s did not break the signature", what)
			}
		})
	}
}

// TestAnnouncementAboutAnotherRegistrysAgent is the rule that keeps authority
// where it belongs: a registry may speak for what it issued and nothing else.
func TestAnnouncementAboutAnotherRegistrysAgent(t *testing.T) {
	signer, pub, _ := registryKey(t, asnA)
	a, err := federation.SignAnnouncement(signer, federation.Announcement{
		OriginUAIASN: asnA,
		// AS1001 announcing an identity that names AS2001 as its authority.
		AgentDID:    federation.AgentDID(asnB, ulidA),
		AgentStatus: "REVOKED", Timestamp: uaicrypto.NewTimestamp(time.Now()),
		Sequence: 1, CredentialHash: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The signature is genuine. That is the point: verification alone is not
	// authority, and a registry with a valid key could otherwise revoke
	// somebody else's agents by saying so.
	if err := a.Verify(pub); err != nil {
		t.Fatalf("the fixture's own signature should verify: %v", err)
	}
	if err := a.Validate(time.Now()); err == nil {
		t.Fatal("AS1001 was allowed to announce an identity belonging to AS2001")
	}
}

func TestAnnouncementWithUnknownStatus(t *testing.T) {
	a, _ := announcementFrom(t, asnA, time.Now(), 1)
	a.AgentStatus = "PROBABLY_FINE"
	if err := a.Validate(time.Now()); err == nil {
		t.Fatal("a status this registry does not understand was accepted")
	}
}

func TestSequenceMustAdvance(t *testing.T) {
	if err := federation.CheckSequence(10, 11); err != nil {
		t.Fatalf("11 after 10 should advance: %v", err)
	}
	for _, incoming := range []int64{10, 9, 0, -1} {
		if err := federation.CheckSequence(10, incoming); err == nil {
			t.Errorf("sequence %d was accepted after 10", incoming)
		}
	}
}

// TestDecodeRefusesUnknownMembers is how "an announcement carries no prompts,
// no conversations and no PII" stops being a sentence in a document.
func TestDecodeRefusesUnknownMembers(t *testing.T) {
	a, _ := announcementFrom(t, asnA, time.Now(), 1)
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var loose map[string]any
	if err := json.Unmarshal(raw, &loose); err != nil {
		t.Fatal(err)
	}
	loose["conversation"] = "the customer said their card number was 4111 1111 1111 1111"
	smuggled, err := json.Marshal(loose)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := federation.Decode[federation.Announcement](smuggled); err == nil {
		t.Fatal("an announcement carrying an extra member was accepted; a decoder that " +
			"ignores unknown members accepts whatever a peer chooses to attach")
	}
	// And the clean one still decodes, so the check is not simply refusing all.
	if _, err := federation.Decode[federation.Announcement](raw); err != nil {
		t.Fatalf("a well-formed announcement was refused: %v", err)
	}
}

// TestReasonNamesTheCause: a peer that is refused has to know what to fix.
func TestReasonNamesTheCause(t *testing.T) {
	cases := map[error]string{
		nil:                            "ACCEPTED",
		federation.ErrUnknownPeer:      "UNKNOWN_PEER",
		federation.ErrStaleSequence:    "STALE_SEQUENCE",
		federation.ErrInvalidSignature: "INVALID_SIGNATURE",
		federation.ErrUnsigned:         "INVALID_SIGNATURE",
		federation.ErrClockSkew:        "STALE_TIMESTAMP",
		federation.ErrInvalidPayload:   "INVALID_PAYLOAD",
		federation.ErrWrongAuthority:   "WRONG_AUTHORITY",
	}
	for err, want := range cases {
		if got := federation.Reason(err); got != want {
			t.Errorf("Reason(%v) = %q, want %q", err, got, want)
		}
	}
}
