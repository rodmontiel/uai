// Package keys implements key history and the rule that decides which key
// verifies a historical signature.
//
// The rule, from docs/protocol/03-identity.md section 6.7:
//
//	A signature over an event MUST be verified against the key material that
//	was valid at the event's log-attested time, not at verification time.
//
// Resolving "the current key" instead is the most common verification bug in
// systems like this. It is silent: everything works until the first rotation,
// and then every historical signature stops verifying at once — which looks
// exactly like mass forgery.
//
// The distinction between rotation and compromise is the other half. A rotated
// key keeps verifying everything it signed before it was retired. A compromised
// key stops verifying everything signed from the declared compromise time
// onward, while its earlier signatures stay sound, because the blast radius of
// a stolen key is bounded by when it was stolen.
package keys

import (
	"crypto"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Protection records how strongly a private key is held. It maps to the
// assurance levels in docs/protocol/03-identity.md section 6.8.
type Protection string

// Key protection levels.
const (
	ProtectionSoftware      Protection = "SOFTWARE"
	ProtectionTPM2          Protection = "TPM2"
	ProtectionSecureEnclave Protection = "SECURE_ENCLAVE"
	ProtectionHSM           Protection = "HSM"
	ProtectionCloudKMS      Protection = "CLOUD_KMS"
	ProtectionWebAuthn      Protection = "WEBAUTHN"
)

// HardwareBacked reports whether the protection level is hardware-backed, which
// is the requirement from UAI-AL2 upward.
func (p Protection) HardwareBacked() bool {
	switch p {
	case ProtectionTPM2, ProtectionSecureEnclave, ProtectionHSM, ProtectionCloudKMS, ProtectionWebAuthn:
		return true
	default:
		return false
	}
}

var (
	// ErrKeyNotFound is returned when no key matches the verification method.
	ErrKeyNotFound = errors.New("keys: no key with that verification method")
	// ErrNotYetValid is returned when the key had not been introduced yet.
	ErrNotYetValid = errors.New("keys: key was not yet valid at that time")
	// ErrExpired is returned when the key's validity window had ended.
	ErrExpired = errors.New("keys: key had expired at that time")
	// ErrRevoked is returned for a signature made after the key was retired.
	ErrRevoked = errors.New("keys: key had been revoked at that time")
	// ErrCompromised is returned for a signature made at or after a declared compromise.
	ErrCompromised = errors.New("keys: key was declared compromised at or before that time")
	// ErrInvalidWindow is returned when a key's validity window is incoherent.
	ErrInvalidWindow = errors.New("keys: validity window is not ordered")
	// ErrDuplicateKey is returned when a verification method is added twice.
	ErrDuplicateKey = errors.New("keys: verification method already present")
)

// Key is one entry in an identity's key history.
type Key struct {
	// KID is the DID URL of the verification method, e.g.
	// did:uai:agent:01JY...#key-1
	KID string
	// Alg is the UAI-CS-1 algorithm this key signs with.
	Alg uaicrypto.Algorithm
	// Public is the public key.
	Public crypto.PublicKey
	// Protection records how the private key is held.
	Protection Protection
	// ValidFrom is when the key entered the DID Document.
	ValidFrom time.Time
	// ValidUntil, when set, ends the key's planned validity.
	ValidUntil time.Time
	// RevokedAt, when set, is when the key was retired by normal rotation.
	// Signatures made BEFORE this moment remain valid: rotation must not
	// invalidate history.
	RevokedAt time.Time
	// CompromiseDeclaredAt, when set, is when the private key was declared
	// stolen. Signatures made at or after this moment are invalid, and earlier
	// ones remain sound.
	CompromiseDeclaredAt time.Time
	// LogIndex is the transparency log entry that committed the DID Document
	// version introducing this key. A key with no log index has not been
	// published and cannot be relied on by a third party.
	LogIndex int64
}

// Validate checks that the key's own fields are coherent.
func (k Key) Validate() error {
	if k.KID == "" {
		return errors.New("keys: key has no verification method identifier")
	}
	if k.Public == nil {
		return fmt.Errorf("keys: %s has no public key", k.KID)
	}
	if k.ValidFrom.IsZero() {
		return fmt.Errorf("keys: %s has no validity start", k.KID)
	}
	if !k.ValidUntil.IsZero() && !k.ValidUntil.After(k.ValidFrom) {
		return fmt.Errorf("%w: %s valid_until %s is not after valid_from %s",
			ErrInvalidWindow, k.KID, k.ValidUntil, k.ValidFrom)
	}
	if !k.RevokedAt.IsZero() && k.RevokedAt.Before(k.ValidFrom) {
		return fmt.Errorf("%w: %s revoked before it was valid", ErrInvalidWindow, k.KID)
	}
	return nil
}

// Granularity is the resolution at which key validity is evaluated.
//
// It is one second because that is the resolution of the timestamps UAI
// actually receives: RFC 9421 `created` is an integer number of seconds, and a
// Data Integrity proof's `created` is an RFC 3339 instant that implementations
// routinely emit without a fractional part. Comparing a second-granular
// signature time against a nanosecond-precision boundary makes every boundary
// ambiguous by up to a second, and the ambiguity showed up immediately: a key
// stored with valid_from = 12:32:33.800 rejected the agent's very first request,
// whose signature time was the truncated 12:32:33.
//
// Every boundary is therefore truncated to this granularity, which resolves the
// ambiguity in a consistent direction:
//
//   - ValidFrom truncated down means a key is usable from the START of the
//     second it was introduced in. Slightly permissive, by less than a second,
//     at the only moment when nothing has been signed with it yet.
//   - ValidUntil, RevokedAt and CompromiseDeclaredAt truncated down mean a key
//     stops being usable from the START of the second in which it ended.
//     Conservative, which is the direction these three must err in.
const Granularity = time.Second

func floor(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.Truncate(Granularity)
}

// UsableAt reports whether the key verifies a signature made at t, and why not
// when it does not.
func (k Key) UsableAt(t time.Time) error {
	if t.Before(floor(k.ValidFrom)) {
		return fmt.Errorf("%w: %s valid from %s, signature at %s",
			ErrNotYetValid, k.KID, k.ValidFrom.UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
	}
	// Compromise is checked before the softer conditions: a stolen key is not
	// merely retired, and the error a caller sees should say so.
	if !k.CompromiseDeclaredAt.IsZero() && !t.Before(floor(k.CompromiseDeclaredAt)) {
		return fmt.Errorf("%w: %s compromised at %s, signature at %s",
			ErrCompromised, k.KID, k.CompromiseDeclaredAt.UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
	}
	if !k.ValidUntil.IsZero() && t.After(floor(k.ValidUntil)) {
		return fmt.Errorf("%w: %s expired %s, signature at %s",
			ErrExpired, k.KID, k.ValidUntil.UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
	}
	if !k.RevokedAt.IsZero() && t.After(floor(k.RevokedAt)) {
		return fmt.Errorf("%w: %s revoked %s, signature at %s",
			ErrRevoked, k.KID, k.RevokedAt.UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
	}
	return nil
}

// History is the ordered key history of one identity. It is safe for
// concurrent use.
type History struct {
	mu   sync.RWMutex
	did  string
	keys map[string]Key
}

// NewHistory returns an empty history for a DID.
func NewHistory(did string) *History {
	return &History{did: did, keys: make(map[string]Key)}
}

// DID returns the identity this history belongs to.
func (h *History) DID() string { return h.did }

// Add introduces a key. Keys are never replaced or removed: a retired key stays
// in the history so that the signatures it made remain verifiable forever.
func (h *History) Add(k Key) error {
	if err := k.Validate(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.keys[k.KID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateKey, k.KID)
	}
	h.keys[k.KID] = k
	return nil
}

// Keys returns the history ordered by validity start, oldest first.
func (h *History) Keys() []Key {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Key, 0, len(h.keys))
	for _, k := range h.keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ValidFrom.Equal(out[j].ValidFrom) {
			return out[i].KID < out[j].KID
		}
		return out[i].ValidFrom.Before(out[j].ValidFrom)
	})
	return out
}

// Rotate retires the current key and introduces its replacement.
//
// The grace period is why both keys are accepted for a window: an agent with
// buffered attestations, or a replica that has not yet reloaded its DID
// Document, would otherwise have its in-flight signatures rejected.
func (h *History) Rotate(oldKID string, replacement Key, at time.Time, grace time.Duration) error {
	if err := replacement.Validate(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	old, ok := h.keys[oldKID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, oldKID)
	}
	if _, exists := h.keys[replacement.KID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateKey, replacement.KID)
	}
	if at.Before(old.ValidFrom) {
		return fmt.Errorf("%w: rotating %s before it was valid", ErrInvalidWindow, oldKID)
	}
	old.RevokedAt = at.Add(grace)
	h.keys[oldKID] = old
	h.keys[replacement.KID] = replacement
	return nil
}

// DeclareCompromise marks a key as stolen from a point in time.
//
// This is not rotation. Every signature made at or after `at` with this key
// becomes invalid, including ones already accepted, because the protocol cannot
// distinguish the holder from the thief after that moment. Signatures made
// before it stay valid, which is what bounds the damage.
func (h *History) DeclareCompromise(kid string, at time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	k, ok := h.keys[kid]
	if !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}
	if !k.CompromiseDeclaredAt.IsZero() && k.CompromiseDeclaredAt.Before(at) {
		// An earlier declaration is strictly safer: never move the boundary later.
		return nil
	}
	k.CompromiseDeclaredAt = at
	h.keys[kid] = k
	return nil
}

// At returns the key that verifies a signature made at t.
func (h *History) At(kid string, t time.Time) (Key, error) {
	h.mu.RLock()
	k, ok := h.keys[kid]
	h.mu.RUnlock()
	if !ok {
		return Key{}, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}
	if err := k.UsableAt(t); err != nil {
		return Key{}, err
	}
	return k, nil
}

// Resolver adapts the history to the key resolver that pkg/pop and the
// attestation verifier expect.
//
// The signature is (kid, at) rather than (kid) alone on purpose: a resolver
// that cannot be given a point in time cannot implement the rule this package
// exists for.
func (h *History) Resolver() func(kid string, at time.Time) (crypto.PublicKey, error) {
	return func(kid string, at time.Time) (crypto.PublicKey, error) {
		k, err := h.At(kid, at)
		if err != nil {
			return nil, err
		}
		return k.Public, nil
	}
}

// Registry holds key histories for many identities.
type Registry struct {
	mu         sync.RWMutex
	identities map[string]*History
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{identities: make(map[string]*History)}
}

// History returns the history for a DID, creating it if absent.
func (r *Registry) History(did string) *History {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.identities[did]
	if !ok {
		h = NewHistory(did)
		r.identities[did] = h
	}
	return h
}

// Lookup returns an existing history without creating one.
func (r *Registry) Lookup(did string) (*History, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.identities[did]
	return h, ok
}

// Resolver resolves any verification method across the registry, by taking the
// DID from the part of the DID URL before the fragment.
func (r *Registry) Resolver() func(kid string, at time.Time) (crypto.PublicKey, error) {
	return func(kid string, at time.Time) (crypto.PublicKey, error) {
		did, _, found := cutFragment(kid)
		if !found {
			return nil, fmt.Errorf("%w: %q is not a DID URL with a fragment", ErrKeyNotFound, kid)
		}
		h, ok := r.Lookup(did)
		if !ok {
			return nil, fmt.Errorf("%w: no history for %s", ErrKeyNotFound, did)
		}
		k, err := h.At(kid, at)
		if err != nil {
			return nil, err
		}
		return k.Public, nil
	}
}

func cutFragment(didURL string) (did, fragment string, found bool) {
	for i := 0; i < len(didURL); i++ {
		if didURL[i] == '#' {
			return didURL[:i], didURL[i+1:], true
		}
	}
	return didURL, "", false
}
