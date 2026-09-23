package keys_test

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/keys"
	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

const did = "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"

func mustKey(t *testing.T, kid string, from time.Time) (keys.Key, uaicrypto.Signer) {
	t.Helper()
	signer, pub, err := uaicrypto.GenerateEd25519Signer(kid)
	if err != nil {
		t.Fatal(err)
	}
	return keys.Key{
		KID: kid, Alg: uaicrypto.AlgEdDSA, Public: pub,
		Protection: keys.ProtectionTPM2, ValidFrom: from, LogIndex: 1,
	}, signer
}

func TestKeyValidityWindow(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	k, _ := mustKey(t, did+"#key-1", base)
	k.ValidUntil = base.Add(365 * 24 * time.Hour)

	if err := k.UsableAt(base.Add(-time.Hour)); !errors.Is(err, keys.ErrNotYetValid) {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
	if err := k.UsableAt(base.Add(time.Hour)); err != nil {
		t.Fatalf("key should be usable inside its window: %v", err)
	}
	if err := k.UsableAt(base.Add(400 * 24 * time.Hour)); !errors.Is(err, keys.ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestRotationDoesNotInvalidateHistory(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := keys.NewHistory(did)

	k1, _ := mustKey(t, did+"#key-1", base)
	if err := h.Add(k1); err != nil {
		t.Fatal(err)
	}

	rotateAt := base.Add(30 * 24 * time.Hour)
	k2, _ := mustKey(t, did+"#key-2", rotateAt)
	if err := h.Rotate(k1.KID, k2, rotateAt, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	// The whole point: a signature made before rotation still verifies.
	if _, err := h.At(k1.KID, base.Add(time.Hour)); err != nil {
		t.Fatalf("rotation invalidated history: %v", err)
	}
	// Inside the grace window both keys work, so buffered attestations and
	// replicas that have not reloaded the document are not rejected.
	if _, err := h.At(k1.KID, rotateAt.Add(time.Hour)); err != nil {
		t.Fatalf("old key should still work during the grace period: %v", err)
	}
	if _, err := h.At(k2.KID, rotateAt.Add(time.Hour)); err != nil {
		t.Fatalf("new key should work from its start: %v", err)
	}
	// After the grace window the old key no longer signs anything new.
	if _, err := h.At(k1.KID, rotateAt.Add(48*time.Hour)); !errors.Is(err, keys.ErrRevoked) {
		t.Fatalf("expected ErrRevoked after the grace period, got %v", err)
	}
	// And it is still in the history: keys are never removed.
	if len(h.Keys()) != 2 {
		t.Fatalf("history holds %d keys, want 2", len(h.Keys()))
	}
}

func TestCompromiseBoundsTheBlastRadius(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := keys.NewHistory(did)
	k, _ := mustKey(t, did+"#key-1", base)
	if err := h.Add(k); err != nil {
		t.Fatal(err)
	}

	stolenAt := base.Add(10 * 24 * time.Hour)
	if err := h.DeclareCompromise(k.KID, stolenAt); err != nil {
		t.Fatal(err)
	}

	// Before the declared compromise the signatures stay sound. This is the
	// difference between a bounded incident and losing all history at once.
	if _, err := h.At(k.KID, stolenAt.Add(-time.Hour)); err != nil {
		t.Fatalf("signatures before the compromise must remain valid: %v", err)
	}
	// From the compromise onward nothing signed by this key can be trusted,
	// because the protocol cannot tell the holder from the thief.
	if _, err := h.At(k.KID, stolenAt); !errors.Is(err, keys.ErrCompromised) {
		t.Fatalf("expected ErrCompromised at the boundary, got %v", err)
	}
	if _, err := h.At(k.KID, stolenAt.Add(time.Hour)); !errors.Is(err, keys.ErrCompromised) {
		t.Fatalf("expected ErrCompromised after the boundary, got %v", err)
	}
}

func TestCompromiseNeverMovesTheBoundaryLater(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := keys.NewHistory(did)
	k, _ := mustKey(t, did+"#key-1", base)
	if err := h.Add(k); err != nil {
		t.Fatal(err)
	}
	early := base.Add(5 * 24 * time.Hour)
	late := base.Add(20 * 24 * time.Hour)

	if err := h.DeclareCompromise(k.KID, early); err != nil {
		t.Fatal(err)
	}
	// A later declaration must not narrow the window that is already distrusted:
	// moving the boundary forward would retroactively re-trust signatures.
	if err := h.DeclareCompromise(k.KID, late); err != nil {
		t.Fatal(err)
	}
	if _, err := h.At(k.KID, early.Add(time.Hour)); !errors.Is(err, keys.ErrCompromised) {
		t.Fatalf("a later declaration re-trusted a distrusted period: %v", err)
	}
	// An earlier declaration is strictly safer and must be honored.
	earlier := base.Add(24 * time.Hour)
	if err := h.DeclareCompromise(k.KID, earlier); err != nil {
		t.Fatal(err)
	}
	if _, err := h.At(k.KID, earlier.Add(time.Hour)); !errors.Is(err, keys.ErrCompromised) {
		t.Fatalf("an earlier declaration was not honored: %v", err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	h := keys.NewHistory(did)
	if _, err := h.At(did+"#nope", time.Now()); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestDuplicateKeyRejected(t *testing.T) {
	base := time.Now()
	h := keys.NewHistory(did)
	k, _ := mustKey(t, did+"#key-1", base)
	if err := h.Add(k); err != nil {
		t.Fatal(err)
	}
	if err := h.Add(k); !errors.Is(err, keys.ErrDuplicateKey) {
		t.Fatalf("expected ErrDuplicateKey, got %v", err)
	}
}

func TestInvalidKeyRejected(t *testing.T) {
	h := keys.NewHistory(did)
	base := time.Now()
	cases := map[string]keys.Key{
		"no kid":        {Alg: uaicrypto.AlgEdDSA, Public: ed25519.PublicKey{}, ValidFrom: base},
		"no public key": {KID: did + "#k", Alg: uaicrypto.AlgEdDSA, ValidFrom: base},
		"no start":      {KID: did + "#k", Alg: uaicrypto.AlgEdDSA, Public: ed25519.PublicKey{}},
		"window reversed": {KID: did + "#k", Alg: uaicrypto.AlgEdDSA, Public: ed25519.PublicKey{},
			ValidFrom: base, ValidUntil: base.Add(-time.Hour)},
	}
	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			if err := h.Add(k); err == nil {
				t.Fatal("an incoherent key was accepted")
			}
		})
	}
}

func TestHardwareBacking(t *testing.T) {
	if keys.ProtectionSoftware.HardwareBacked() {
		t.Fatal("a software key must not count as hardware-backed")
	}
	for _, p := range []keys.Protection{
		keys.ProtectionTPM2, keys.ProtectionSecureEnclave,
		keys.ProtectionHSM, keys.ProtectionCloudKMS, keys.ProtectionWebAuthn,
	} {
		if !p.HardwareBacked() {
			t.Fatalf("%s should be hardware-backed", p)
		}
	}
}

func TestRegistryResolverDrivesProofOfPossession(t *testing.T) {
	// End to end: a signed request verifies through the registry, and stops
	// verifying once the key it used is declared compromised.
	base := time.Now().Add(-time.Hour)
	reg := keys.NewRegistry()
	k, signer := mustKey(t, did+"#key-1", base)
	if err := reg.History(did).Add(k); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"event_id":"01JY8RA3C7K2V9M0QW4T6Z8XPD"}`)
	req, err := http.NewRequest(http.MethodPost, "https://api.uai.world/v1/actions/attest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pop.SignRequest(signer, req, body, uaicrypto.DomainAttestation,
		"uai:agent:01JY8R9ZAF392N7QX2T81JH6KM", "8f1c2b9d4e6a7c3f0b1d2e3a4c5b6d7e"); err != nil {
		t.Fatal(err)
	}

	opts := pop.VerifyOptions{
		Domain: uaicrypto.DomainAttestation, Resolve: reg.Resolver(),
	}
	if _, err := pop.VerifyRequest(req, body, opts); err != nil {
		t.Fatalf("verification through the registry failed: %v", err)
	}

	if err := reg.History(did).DeclareCompromise(k.KID, base); err != nil {
		t.Fatal(err)
	}
	if _, err := pop.VerifyRequest(req, body, opts); !errors.Is(err, keys.ErrCompromised) {
		t.Fatalf("expected the request to stop verifying after a compromise, got %v", err)
	}
}

func TestRegistryResolverRejectsMalformedKID(t *testing.T) {
	reg := keys.NewRegistry()
	resolve := reg.Resolver()
	if _, err := resolve(did, time.Now()); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Fatalf("a DID without a fragment should not resolve to a key, got %v", err)
	}
	if _, err := resolve("did:uai:agent:unknown#key-1", time.Now()); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound for an unknown identity, got %v", err)
	}
}

func TestKeysOrderedByValidity(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := keys.NewHistory(did)
	for i, offset := range []time.Duration{48 * time.Hour, 0, 24 * time.Hour} {
		k, _ := mustKey(t, did+"#key-"+string(rune('a'+i)), base.Add(offset))
		if err := h.Add(k); err != nil {
			t.Fatal(err)
		}
	}
	got := h.Keys()
	for i := 1; i < len(got); i++ {
		if got[i].ValidFrom.Before(got[i-1].ValidFrom) {
			t.Fatalf("history is not ordered oldest first: %v", got)
		}
	}
}

// TestBoundariesAreSecondGranular pins the fix for a bug that only an
// end-to-end run could surface: an agent could not use its own key in the
// second it was registered, because RFC 9421 signature timestamps are whole
// seconds while the stored validity carried nanoseconds.
func TestBoundariesAreSecondGranular(t *testing.T) {
	_, pub, err := uaicrypto.GenerateEd25519Signer("did:uai:agent:01JY#key-1")
	if err != nil {
		t.Fatal(err)
	}
	// Introduced mid-second, as a real INSERT does.
	introduced := time.Date(2026, 9, 23, 12, 32, 33, 800_000_000, time.UTC)
	k := keys.Key{KID: "did:uai:agent:01JY#key-1", Public: pub, ValidFrom: introduced}

	// The signature time a verifier actually receives: the same second, floored.
	signedAt := introduced.Truncate(time.Second)
	if err := k.UsableAt(signedAt); err != nil {
		t.Errorf("a key must be usable in the second it was introduced: %v", err)
	}
	// The second before is still too early. The permissiveness is bounded.
	if err := k.UsableAt(signedAt.Add(-time.Second)); !errors.Is(err, keys.ErrNotYetValid) {
		t.Errorf("got %v, want ErrNotYetValid a second early", err)
	}

	// Closing boundaries err the other way: a key compromised mid-second is
	// already unusable for signatures stamped with that second.
	compromised := k
	compromised.CompromiseDeclaredAt = time.Date(2026, 9, 23, 13, 0, 0, 500_000_000, time.UTC)
	if err := compromised.UsableAt(compromised.CompromiseDeclaredAt.Truncate(time.Second)); !errors.Is(err, keys.ErrCompromised) {
		t.Errorf("got %v, want ErrCompromised in the second of the declaration", err)
	}
	if err := compromised.UsableAt(compromised.CompromiseDeclaredAt.Add(-time.Second)); err != nil {
		t.Errorf("a second before the declaration the key was still good: %v", err)
	}
}
