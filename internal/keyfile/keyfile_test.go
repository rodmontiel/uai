package keyfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSetKIDPreservesKeyMaterial is the only thing SetKID must never get wrong.
// It rewrites a file holding a private key, and a rewrite that changes the key
// destroys the one thing on disk that cannot be regenerated: every signature the
// old key made stops verifying, and there is no second copy to restore from.
func TestSetKIDPreservesKeyMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.jwk")
	if err := Generate(path, "did:uai:owner:OLD#key-1"); err != nil {
		t.Fatal(err)
	}
	before, err := PublicJWK(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeThumb, err := before.ThumbprintString()
	if err != nil {
		t.Fatal(err)
	}

	if err := SetKID(path, "did:uai:owner:NEW#key-1"); err != nil {
		t.Fatal(err)
	}

	after, err := PublicJWK(path)
	if err != nil {
		t.Fatalf("the file no longer parses as a key: %v", err)
	}
	afterThumb, err := after.ThumbprintString()
	if err != nil {
		t.Fatal(err)
	}
	// Derived from the private half by PublicJWK, so an identical thumbprint
	// means the private key itself survived, not merely the public member.
	if afterThumb != beforeThumb {
		t.Fatalf("relabelling changed the key: thumbprint %s became %s", beforeThumb, afterThumb)
	}
	if after.Kid != "did:uai:owner:NEW#key-1" {
		t.Errorf("kid = %q, want the new one", after.Kid)
	}
	// Load is stricter than PublicJWK: it checks that the public member on disk
	// agrees with the private one. A rewrite that updated one and not the other
	// would pass the check above and fail here.
	if _, err := Load(path, "did:uai:owner:NEW#key-1"); err != nil {
		t.Fatalf("the relabelled key no longer loads: %v", err)
	}
}

// TestSetKIDKeepsPermissions guards the mode across the temp-file-and-rename.
// os.CreateTemp makes 0600, but a future rewrite using os.WriteFile with 0644
// would leave a private key world-readable and nothing else would notice.
func TestSetKIDKeepsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.jwk")
	if err := Generate(path, "a#key-1"); err != nil {
		t.Fatal(err)
	}
	if err := SetKID(path, "b#key-1"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("mode is %#o; a private key must not be readable by group or other", perm)
	}
}

// TestSetKIDIsIdempotent: re-labelling to the kid a file already carries must
// not rewrite it at all. Every rewrite of a private key is a chance to lose one.
func TestSetKIDIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.jwk")
	if err := Generate(path, "same#key-1"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetKID(path, "same#key-1"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the file was rewritten even though the kid did not change")
	}
}

// TestSetKIDLeavesNoTempFile: the temp file carries the same private key as the
// original, so one left behind in .keys/ is a second copy of key material that
// nobody knows exists.
func TestSetKIDLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owner.jwk")
	if err := Generate(path, "a#key-1"); err != nil {
		t.Fatal(err)
	}
	if err := SetKID(path, "b#key-1"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "owner.jwk" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want only owner.jwk", names)
	}
}

// TestSetKIDRefusesGarbage: a file that is not a key must fail before the
// rename, so a bad path cannot replace good key material with valid-looking JSON.
func TestSetKIDRefusesGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-key.jwk")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetKID(path, "x#key-1"); err == nil {
		t.Fatal("SetKID accepted a file that is not JSON")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "{not json" {
		t.Error("the file was modified despite the refusal")
	}
}

// TestGenerateRefusesToOverwrite restates in a test what the doc comment on
// Generate promises. Overwriting an issuer key invalidates every credential
// issued under it, and O_EXCL is the only thing standing between that and a
// re-run of a setup script.
func TestGenerateRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.jwk")
	if err := Generate(path, "a#key-1"); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Generate(path, "b#key-1"); err == nil {
		t.Fatal("Generate overwrote an existing key")
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("the existing key changed")
	}
	var doc privateJWK
	if err := json.Unmarshal(second, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Kid != "a#key-1" {
		t.Errorf("kid = %q, want the original", doc.Kid)
	}
}
