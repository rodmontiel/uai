package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestResigningDoesNotMoveTheEffectiveDate.
//
// This has now been a defect twice. The signing tool defaulted the effective
// date to a fixed future value, so re-signing a bundle after editing one rule
// silently moved when the whole thing took effect — and a gateway that fails
// closed then refuses to start, correctly reporting a change nobody made.
//
// Re-signing answers "who approves these rules". It must not also answer "when
// do they apply".
func TestResigningDoesNotMoveTheEffectiveDate(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"policy_id":"GASC","policy_version":"2027.4",` +
		`"effective_date":"2026-01-01T00:00:00Z","bundle_hash":"sha256:aa","threshold":"3-of-5"}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := effectiveDate(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("effective date = %s, want the manifest's %s", got, want)
	}

	// An explicit flag still wins: staging a successor for a future quarter is
	// the normal release path.
	staged, err := effectiveDate(dir, "2027-04-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if staged.Year() != 2027 {
		t.Fatalf("an explicit -effective was ignored: %s", staged)
	}
}

// TestANewBundleMustStateItsEffectiveDate: picking one on the operator's behalf
// would turn a deliberate governance act into an accident.
func TestANewBundleMustStateItsEffectiveDate(t *testing.T) {
	if _, err := effectiveDate(t.TempDir(), ""); err == nil {
		t.Fatal("a bundle with no manifest and no -effective was given a date")
	}
}
