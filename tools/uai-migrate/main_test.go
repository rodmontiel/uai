package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationOrdering(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"0001_init.up.sql", "0001_init.down.sql",
		"0002_governance.up.sql", "0002_governance.down.sql",
		"0010_later.up.sql", "0010_later.down.sql",
		"README.md",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("-- x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	up, err := migrations(dir, "up")
	if err != nil {
		t.Fatal(err)
	}
	wantUp := []string{"0001_init.up.sql", "0002_governance.up.sql", "0010_later.up.sql"}
	assertNames(t, "up", up, wantUp)

	down, err := migrations(dir, "down")
	if err != nil {
		t.Fatal(err)
	}
	// Rolling back must reverse the order, or a migration would be undone
	// before the one that depends on it.
	wantDown := []string{"0010_later.down.sql", "0002_governance.down.sql", "0001_init.down.sql"}
	assertNames(t, "down", down, wantDown)
}

func TestMigrationRejectsUnknownDirection(t *testing.T) {
	if _, err := migrations(t.TempDir(), "sideways"); err == nil {
		t.Fatal("an unknown direction was accepted")
	}
}

func assertNames(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d files, want %d (%v)", label, len(got), len(want), got)
	}
	for i := range want {
		if filepath.Base(got[i]) != want[i] {
			t.Fatalf("%s[%d] = %s, want %s", label, i, filepath.Base(got[i]), want[i])
		}
	}
}
