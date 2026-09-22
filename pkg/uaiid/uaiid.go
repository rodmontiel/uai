package uaiid

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Entity is the class of thing an identifier names.
type Entity string

// The five entity classes defined by UAI v0.1.
const (
	EntityAgent    Entity = "agent"
	EntityOwner    Entity = "owner"
	EntityOrg      Entity = "org"
	EntityDelegate Entity = "delegate"
	EntityCountry  Entity = "country"
)

// Scheme prefixes. A UAI-ID and its DID are the same identifier with and
// without the DID scheme prefix; there is no mapping table and therefore no
// possibility of drift between the two.
const (
	SchemeUAI = "uai:"
	SchemeDID = "did:uai:"
	// DIDMethod is the W3C DID method name registered by UAI.
	DIDMethod = "uai"
)

// ErrInvalidEntity is returned for an unknown entity class.
var ErrInvalidEntity = errors.New("uaiid: unknown entity class")

// ErrMalformed is returned when a string is not a well-formed UAI identifier.
var ErrMalformed = errors.New("uaiid: malformed identifier")

var knownEntities = map[Entity]bool{
	EntityAgent: true, EntityOwner: true, EntityOrg: true,
	EntityDelegate: true, EntityCountry: true,
}

// Valid reports whether e is a defined entity class.
func (e Entity) Valid() bool { return knownEntities[e] }

// ID is a parsed UAI identifier.
type ID struct {
	entity Entity
	ulid   ULID
}

// New mints an identifier for the given entity class.
func New(entity Entity) (ID, error) {
	if !entity.Valid() {
		return ID{}, fmt.Errorf("%w: %q", ErrInvalidEntity, entity)
	}
	u, err := NewULID()
	if err != nil {
		return ID{}, err
	}
	return ID{entity: entity, ulid: u}, nil
}

// NewAt mints an identifier carrying a specific creation time. Intended for
// tests and for replaying historical records; production code uses New.
func NewAt(entity Entity, t time.Time) (ID, error) {
	if !entity.Valid() {
		return ID{}, fmt.Errorf("%w: %q", ErrInvalidEntity, entity)
	}
	u, err := NewULIDAt(t)
	if err != nil {
		return ID{}, err
	}
	return ID{entity: entity, ulid: u}, nil
}

// Parse accepts either spelling: "uai:agent:01JY..." or "did:uai:agent:01JY...".
func Parse(s string) (ID, error) {
	raw := strings.TrimSpace(s)
	// URI scheme components are case-insensitive (RFC 3986 §3.1), so the
	// prefix is matched case-insensitively even though it is always emitted
	// lowercase.
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, SchemeDID):
		raw = raw[len(SchemeDID):]
	case strings.HasPrefix(lower, SchemeUAI):
		raw = raw[len(SchemeUAI):]
	default:
		return ID{}, fmt.Errorf("%w: missing uai: or did:uai: prefix in %q", ErrMalformed, s)
	}
	entityPart, ulidPart, ok := strings.Cut(raw, ":")
	if !ok {
		return ID{}, fmt.Errorf("%w: expected <entity>:<ulid> in %q", ErrMalformed, s)
	}
	// The scheme and entity class are case-insensitive on input and always
	// emitted lowercase; the ULID is always emitted uppercase.
	entity := Entity(strings.ToLower(entityPart))
	if !entity.Valid() {
		return ID{}, fmt.Errorf("%w: %q", ErrInvalidEntity, entityPart)
	}
	u, err := ParseULID(ulidPart)
	if err != nil {
		return ID{}, err
	}
	return ID{entity: entity, ulid: u}, nil
}

// MustParse is Parse for constants and tests; it panics on error.
func MustParse(s string) ID {
	id, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return id
}

// Entity returns the identifier's entity class.
func (id ID) Entity() Entity { return id.entity }

// ULID returns the identifier's raw ULID.
func (id ID) ULID() ULID { return id.ulid }

// Time returns the identifier's creation time, to the millisecond.
func (id ID) Time() time.Time { return id.ulid.Time() }

// String returns the canonical UAI-ID form: uai:<entity>:<ULID>.
func (id ID) String() string {
	if id.entity == "" {
		return ""
	}
	return SchemeUAI + string(id.entity) + ":" + id.ulid.String()
}

// DID returns the canonical DID form: did:uai:<entity>:<ULID>.
func (id ID) DID() string {
	if id.entity == "" {
		return ""
	}
	return SchemeDID + string(id.entity) + ":" + id.ulid.String()
}

// DIDURL returns a DID URL with the given fragment, e.g. a verification method:
// did:uai:agent:01JY...#key-1
func (id ID) DIDURL(fragment string) string {
	return id.DID() + "#" + strings.TrimPrefix(fragment, "#")
}

// IsZero reports whether the identifier is the zero value.
func (id ID) IsZero() bool { return id.entity == "" }

// MarshalText implements encoding.TextMarshaler, so IDs serialize as their
// canonical UAI-ID form in JSON.
func (id ID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler, accepting both spellings.
func (id *ID) UnmarshalText(b []byte) error {
	parsed, err := Parse(string(b))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// ParseDIDURL splits a DID URL into its identifier and fragment.
func ParseDIDURL(s string) (ID, string, error) {
	base, fragment, _ := strings.Cut(s, "#")
	id, err := Parse(base)
	if err != nil {
		return ID{}, "", err
	}
	return id, fragment, nil
}
