package policy_test

import (
	"errors"
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/policy"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

func files(rule string) policy.Files {
	return policy.Files{
		"policy/decision.rego": []byte(rule),
		"data/taxonomy.json":   []byte(`{"thresholds":{}}`),
	}
}

func manifest(t *testing.T, f policy.Files, threshold string, signers ...uaicrypto.Signer) (policy.Manifest, policy.Authority) {
	t.Helper()
	hash, err := policy.HashContent(f)
	if err != nil {
		t.Fatal(err)
	}
	m := policy.Manifest{
		PolicyID: "GASC", PolicyVersion: "2027.4",
		EffectiveDate: time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC),
		Jurisdictions: []string{"*"}, BundleHash: hash, Threshold: threshold,
	}
	auth := policy.Authority{}
	for _, s := range signers {
		a, err := policy.SignBundle(s, hash)
		if err != nil {
			t.Fatal(err)
		}
		m.Approvals = append(m.Approvals, a)
		auth[s.KID()] = s.Public()
	}
	return m, auth
}

func signer(t *testing.T, n int) uaicrypto.Signer {
	t.Helper()
	s, _, err := uaicrypto.GenerateEd25519Signer("did:web:council.uai.world#gasc-" + string(rune('0'+n)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSuccessionIsEnforced covers the §12.1.1 MUST that keeps policy history as
// tamper-evident as action history: without the link, a bundle could be swapped
// for an older, more permissive one and nothing in the manifest would say so.
func TestSuccessionIsEnforced(t *testing.T) {
	old, _ := manifest(t, files("package gasc"), "1-of-1", signer(t, 1))
	old.PolicyVersion = "2027.3"
	old.EffectiveDate = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("a genuine successor is accepted", func(t *testing.T) {
		next, _ := manifest(t, files("package gasc\n# v4"), "1-of-1", signer(t, 1))
		next.PreviousPolicyHash = old.BundleHash
		if err := policy.VerifySuccession(next, old); err != nil {
			t.Fatalf("a genuine successor must verify: %v", err)
		}
	})

	t.Run("a bundle claiming no predecessor is refused", func(t *testing.T) {
		next, _ := manifest(t, files("package gasc\n# v4"), "1-of-1", signer(t, 1))
		if err := policy.VerifySuccession(next, old); !errors.Is(err, policy.ErrChainBroken) {
			t.Errorf("got %v, want ErrChainBroken", err)
		}
	})

	t.Run("a bundle pointing at the wrong predecessor is refused", func(t *testing.T) {
		next, _ := manifest(t, files("package gasc\n# v4"), "1-of-1", signer(t, 1))
		next.PreviousPolicyHash = "sha256:" + string(make([]byte, 0)) +
			"0000000000000000000000000000000000000000000000000000000000000000"
		if err := policy.VerifySuccession(next, old); !errors.Is(err, policy.ErrChainBroken) {
			t.Errorf("got %v, want ErrChainBroken", err)
		}
	})

	t.Run("a successor cannot take effect before what it replaces", func(t *testing.T) {
		// Otherwise "replacing" a bundle with one backdated before it would let
		// an older, more permissive policy be presented as the current one.
		next, _ := manifest(t, files("package gasc\n# v4"), "1-of-1", signer(t, 1))
		next.PreviousPolicyHash = old.BundleHash
		next.EffectiveDate = old.EffectiveDate.Add(-time.Hour)
		if err := policy.VerifySuccession(next, old); !errors.Is(err, policy.ErrChainBroken) {
			t.Errorf("got %v, want ErrChainBroken", err)
		}
	})
}

// TestThresholdArithmetic: an unsatisfiable or malformed threshold must be
// refused rather than interpreted generously.
func TestThresholdArithmetic(t *testing.T) {
	f := files("package gasc")
	for _, bad := range []string{"", "3", "3-of", "of-5", "0-of-5", "6-of-5", "x-of-5"} {
		m, auth := manifest(t, f, bad, signer(t, 1))
		if err := policy.Verify(m, f, auth); err == nil {
			t.Errorf("threshold %q was accepted", bad)
		}
	}
}

// TestEmptyBundleIsRefused: a bundle with no policy files decides nothing, and
// a PDP that loaded one would answer every request from the default alone.
func TestEmptyBundleIsRefused(t *testing.T) {
	if _, err := policy.HashContent(policy.Files{"manifest.json": []byte("{}")}); err == nil {
		t.Error("a bundle with no policy files was hashed")
	}
}

// TestHashIgnoresTheManifestAndSignatures: they are derived from the content,
// so including them would make the hash depend on itself.
func TestHashIgnoresTheManifestAndSignatures(t *testing.T) {
	bare := files("package gasc")
	withMeta := files("package gasc")
	withMeta["manifest.json"] = []byte(`{"bundle_hash":"sha256:whatever"}`)
	withMeta[".signatures/gasc-1.sig"] = []byte("zSignature")

	a, err := policy.HashContent(bare)
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.HashContent(withMeta)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("the manifest or signatures changed the content hash: %s vs %s", a, b)
	}
}

// TestHashIsPathSensitive: moving a file must change the hash, or a rule could
// be relocated into a directory the loader ignores.
func TestHashIsPathSensitive(t *testing.T) {
	a, err := policy.HashContent(policy.Files{"policy/a.rego": []byte("package gasc")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.HashContent(policy.Files{"policy/b.rego": []byte("package gasc")})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("the same content at a different path produced the same hash")
	}
}
