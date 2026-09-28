package attest_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rodmontiel/uai/pkg/attest"
)

// The spellings a client actually produces. Python's datetime.isoformat emits
// exactly six fractional digits, JavaScript's toISOString exactly three, and
// neither trims: one timestamp in ten from either ends in a zero.
var wireSpellings = []string{
	"2026-09-22T14:02:04.505896Z", // six digits, no trailing zero
	"2026-09-22T14:02:04.505890Z", // six digits, one trailing zero  <- the failing case
	"2026-09-22T14:02:04.500000Z", // six digits, all zeros
	"2026-09-22T14:02:04.000000Z", // six zeros
	"2026-09-22T14:02:04.500Z",    // three digits, trailing zeros
	"2026-09-22T14:02:04Z",        // no fraction at all
	"2026-09-22T11:02:04-03:00",   // an offset rather than Z
}

// TestTimestampSurvivesTheRoundTrip is the whole reason the type exists.
//
// A verifier that re-serializes a timestamp computes the canonical bytes of
// §10.4 over a document the agent never sent. The signature then does not
// match, and the agent is told its signature is invalid -- which is both wrong
// and unactionable. time.Time did exactly this: Go's RFC3339Nano drops trailing
// zeros, so "…04.505890Z" came back as "…04.50589Z".
func TestTimestampSurvivesTheRoundTrip(t *testing.T) {
	for _, spelling := range wireSpellings {
		t.Run(spelling, func(t *testing.T) {
			in := []byte(`"` + spelling + `"`)
			var ts attest.Timestamp
			if err := json.Unmarshal(in, &ts); err != nil {
				t.Fatalf("decoding %s: %v", spelling, err)
			}
			out, err := json.Marshal(ts)
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != string(in) {
				t.Fatalf("a timestamp changed on the way through:\n  sent      %s\n  re-emitted %s\n"+
					"Every byte of it is covered by the agent's signature.", in, out)
			}
		})
	}
}

// TestAttestationSigningBytesUseTheReceivedTimestamp is the same defect one
// level up: what a verifier hashes must be what the agent wrote.
func TestAttestationSigningBytesUseTheReceivedTimestamp(t *testing.T) {
	for _, spelling := range wireSpellings {
		t.Run(spelling, func(t *testing.T) {
			a := sample()
			if err := json.Unmarshal([]byte(`"`+spelling+`"`), &a.Timestamp); err != nil {
				t.Fatal(err)
			}
			bytes, err := a.SigningBytes()
			if err != nil {
				t.Fatal(err)
			}
			want := `"timestamp":"` + spelling + `"`
			if !strings.Contains(string(bytes), want) {
				t.Fatalf("the canonical bytes do not carry the timestamp that arrived.\n"+
					"  want to find  %s\n  in            %s", want, bytes)
			}
		})
	}
}

// TestAttestationVerifiesAfterAWireRoundTrip signs a statement, sends it as a
// client would, and verifies what the server decoded. This is the end-to-end
// shape of the bug: every individual piece looked right, and one action in ten
// was refused.
func TestAttestationVerifiesAfterAWireRoundTrip(t *testing.T) {
	for _, spelling := range wireSpellings {
		t.Run(spelling, func(t *testing.T) {
			s, pub := signer(t, agentDID+"#key-1")

			// The client: build, sign, serialize.
			a := sample()
			if err := json.Unmarshal([]byte(`"`+spelling+`"`), &a.Timestamp); err != nil {
				t.Fatal(err)
			}
			signed, err := attest.Sign(s, a)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}

			// The server: decode and verify.
			var received attest.Attestation
			if err := json.Unmarshal(body, &received); err != nil {
				t.Fatal(err)
			}
			if err := attest.Verify(pub, received); err != nil {
				t.Fatalf("a statement this agent really signed was refused: %v\n"+
					"timestamp on the wire: %s", err, spelling)
			}
		})
	}
}

// TestTimestampRefusesWhatIsNotAnInstant: the spelling is preserved, but only
// for something that is a timestamp. Passing arbitrary text through verbatim
// would let a client choose bytes the verifier never understood.
func TestTimestampRefusesWhatIsNotAnInstant(t *testing.T) {
	for _, bad := range []string{`"not a time"`, `"2026-13-45T99:99:99Z"`, `1758549724`, `null`} {
		var ts attest.Timestamp
		if err := json.Unmarshal([]byte(bad), &ts); err == nil {
			t.Errorf("%s was accepted as a timestamp", bad)
		}
	}
}
