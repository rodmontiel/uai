// Timestamp: the instant a signed object carries, spelled as it arrived.
package uaicrypto

import (
	"encoding/json"
	"fmt"
	"time"
)

// Timestamp is an RFC 3339 instant that survives a JSON round trip byte for byte.
//
// time.Time does not, and the difference is not cosmetic. Go's RFC3339Nano drops
// trailing zeros from the fractional seconds, so an signed object carrying
// "...:00.505890Z" came back out of a Go struct as "...:00.50589Z". The canonical
// bytes were then computed over a document the agent never sent, the
// signature did not match, and the agent was told its signature was invalid.
// It was not: the verifier had changed the statement before checking it.
//
// It is not a rare case either. A client emitting six fractional digits -- which
// is what Python's datetime.isoformat does -- ends one timestamp in ten with a
// zero, so roughly one statement in ten was refused, at random, with an error
// naming the wrong party.
//
// So the spelling that arrived is kept and re-emitted. RFC 8785 preserves string
// values verbatim, which means the only way to canonicalize what the agent
// signed is to keep what the agent wrote.
type Timestamp struct {
	time.Time
	// wire is the string this value was decoded from, empty when it was built
	// in Go rather than received.
	wire string
}

// NewTimestamp wraps an instant produced locally, which has no wire form yet.
func NewTimestamp(t time.Time) Timestamp { return Timestamp{Time: t.UTC()} }

// MarshalJSON re-emits exactly what was received, or the canonical form for an
// instant this process created.
func (ts Timestamp) MarshalJSON() ([]byte, error) {
	if ts.wire != "" {
		return json.Marshal(ts.wire)
	}
	return json.Marshal(ts.Time)
}

// UnmarshalJSON records the spelling as well as the instant.
func (ts *Timestamp) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("attest: timestamp is not a JSON string: %w", err)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return fmt.Errorf("attest: timestamp %q is not RFC 3339: %w", s, err)
	}
	ts.Time, ts.wire = t, s
	return nil
}
