package uaiid

import (
	"strings"
	"testing"
	"time"
)

func TestULIDRoundTrip(t *testing.T) {
	for i := 0; i < 1000; i++ {
		u, err := NewULID()
		if err != nil {
			t.Fatalf("NewULID: %v", err)
		}
		s := u.String()
		if len(s) != encodedLen {
			t.Fatalf("encoded length = %d, want %d", len(s), encodedLen)
		}
		back, err := ParseULID(s)
		if err != nil {
			t.Fatalf("ParseULID(%q): %v", s, err)
		}
		if back != u {
			t.Fatalf("round trip mismatch: %x != %x", back, u)
		}
	}
}

func TestULIDKnownVector(t *testing.T) {
	// The canonical all-zero and all-one ULIDs pin the encoder's bit layout.
	var zero ULID
	if got, want := zero.String(), strings.Repeat("0", 26); got != want {
		t.Fatalf("zero ULID = %q, want %q", got, want)
	}
	var max ULID
	for i := range max {
		max[i] = 0xFF
	}
	if got, want := max.String(), "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"; got != want {
		t.Fatalf("max ULID = %q, want %q", got, want)
	}
	back, err := ParseULID("7ZZZZZZZZZZZZZZZZZZZZZZZZZ")
	if err != nil || back != max {
		t.Fatalf("ParseULID(max) = %x, %v", back, err)
	}
}

func TestULIDIsTimeSortable(t *testing.T) {
	base := time.Date(2026, 9, 22, 14, 2, 1, 0, time.UTC)
	var prev string
	for i := 0; i < 50; i++ {
		u, err := NewULIDAt(base.Add(time.Duration(i) * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		s := u.String()
		if prev != "" && !(prev < s) {
			t.Fatalf("ULIDs not lexicographically sortable: %q >= %q", prev, s)
		}
		prev = s
	}
}

func TestULIDTimestampPreserved(t *testing.T) {
	want := time.Date(2026, 9, 22, 14, 2, 1, 117_000_000, time.UTC)
	u, err := NewULIDAt(want)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Time(); !got.Equal(want) {
		t.Fatalf("Time() = %s, want %s", got, want)
	}
}

func TestParseULIDRejects(t *testing.T) {
	cases := map[string]string{
		"too short":     "01JY8R9ZAF392N7QX2T81JH6K",
		"too long":      "01JY8R9ZAF392N7QX2T81JH6KMM",
		"bad character": "01JY8R9ZAF392N7QX2T81JH6K!",
		"overflow":      "8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseULID(s); err == nil {
				t.Fatalf("ParseULID(%q) succeeded, want error", s)
			}
		})
	}
}

func TestCrockfordLeniencyCanonicalizes(t *testing.T) {
	// I, L and O are accepted on input and normalize to 1, 1 and 0.
	lenient := "01JY8R9ZAF392N7QX2T8IJH6KM"
	strict := "01JY8R9ZAF392N7QX2T81JH6KM"
	a, err := ParseULID(lenient)
	if err != nil {
		t.Fatalf("lenient parse: %v", err)
	}
	b, err := ParseULID(strict)
	if err != nil {
		t.Fatalf("strict parse: %v", err)
	}
	if a != b {
		t.Fatal("Crockford-equivalent spellings decoded differently")
	}
	if a.String() != strict {
		t.Fatalf("canonical form = %q, want %q", a.String(), strict)
	}
}

func TestIDBothSpellingsAreOneIdentifier(t *testing.T) {
	id, err := New(EntityAgent)
	if err != nil {
		t.Fatal(err)
	}
	uai := id.String()
	did := id.DID()

	if !strings.HasPrefix(uai, "uai:agent:") {
		t.Fatalf("UAI-ID form = %q", uai)
	}
	if !strings.HasPrefix(did, "did:uai:agent:") {
		t.Fatalf("DID form = %q", did)
	}
	// The whole point of the design: one string operation converts between them.
	if did != "did:"+uai {
		t.Fatalf("DID is not the UAI-ID with a did: prefix: %q vs %q", did, uai)
	}

	fromUAI, err := Parse(uai)
	if err != nil {
		t.Fatal(err)
	}
	fromDID, err := Parse(did)
	if err != nil {
		t.Fatal(err)
	}
	if fromUAI != fromDID {
		t.Fatal("the two spellings parsed to different identifiers")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"no prefix":      "agent:01JY8R9ZAF392N7QX2T81JH6KM",
		"wrong method":   "did:web:example.com",
		"unknown entity": "uai:robot:01JY8R9ZAF392N7QX2T81JH6KM",
		"missing ulid":   "uai:agent:",
		"missing entity": "uai:01JY8R9ZAF392N7QX2T81JH6KM",
		"empty":          "",
		"bad ulid":       "uai:agent:notaulid",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(s); err == nil {
				t.Fatalf("Parse(%q) succeeded, want error", s)
			}
		})
	}
}

func TestParseCaseInsensitiveEntityAndULID(t *testing.T) {
	canonical := "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"
	for _, variant := range []string{
		"UAI:AGENT:01JY8R9ZAF392N7QX2T81JH6KM",
		"uai:Agent:01jy8r9zaf392n7qx2t81jh6km",
		"  uai:agent:01JY8R9ZAF392N7QX2T81JH6KM  ",
	} {
		id, err := Parse(variant)
		if err != nil {
			t.Fatalf("Parse(%q): %v", variant, err)
		}
		if id.String() != canonical {
			t.Fatalf("Parse(%q).String() = %q, want %q", variant, id.String(), canonical)
		}
	}
}

func TestUniqueness(t *testing.T) {
	const n = 20000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id, err := New(EntityAgent)
		if err != nil {
			t.Fatal(err)
		}
		s := id.String()
		if _, dup := seen[s]; dup {
			t.Fatalf("duplicate identifier generated: %s", s)
		}
		seen[s] = struct{}{}
	}
}

func TestDIDURL(t *testing.T) {
	id := MustParse("uai:agent:01JY8R9ZAF392N7QX2T81JH6KM")
	want := "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1"
	if got := id.DIDURL("key-1"); got != want {
		t.Fatalf("DIDURL = %q, want %q", got, want)
	}
	if got := id.DIDURL("#key-1"); got != want {
		t.Fatalf("DIDURL with leading # = %q, want %q", got, want)
	}
	back, frag, err := ParseDIDURL(want)
	if err != nil {
		t.Fatal(err)
	}
	if back != id || frag != "key-1" {
		t.Fatalf("ParseDIDURL = %v, %q", back, frag)
	}
}

func TestTextMarshalling(t *testing.T) {
	id := MustParse("did:uai:owner:01JY8R9ZB00000000000000000")
	b, err := id.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	// Canonical serialization is always the UAI-ID form.
	if string(b) != "uai:owner:01JY8R9ZB00000000000000000" {
		t.Fatalf("MarshalText = %q", b)
	}
	var back ID
	if err := back.UnmarshalText(b); err != nil {
		t.Fatal(err)
	}
	if back != id {
		t.Fatal("text round trip changed the identifier")
	}
}
