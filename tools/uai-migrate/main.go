// Command uai-migrate applies the UAI SQL migrations.
//
// It is deliberately small and dependency-free: it shells out to psql rather
// than linking a driver, so the migration path has no Go dependency that could
// differ from what a DBA runs by hand. Production uses forward-only migrations;
// the down direction exists for development.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("PG_DSN"), "PostgreSQL connection string")
	dir := flag.String("dir", "db/migrations", "directory holding the .up.sql / .down.sql files")
	steps := flag.Int("steps", 0, "for down: how many migrations to roll back (0 = all)")
	flag.Parse()

	direction := "up"
	if args := flag.Args(); len(args) > 0 {
		direction = args[0]
	}
	if *dsn == "" {
		fail(errors.New("no DSN: pass -dsn or set PG_DSN"))
	}
	if _, err := exec.LookPath("psql"); err != nil {
		fail(fmt.Errorf("psql not found in PATH: %w", err))
	}

	files, err := migrations(*dir, direction)
	if err != nil {
		fail(err)
	}
	if direction == "down" && *steps > 0 && *steps < len(files) {
		files = files[:*steps]
	}
	if len(files) == 0 {
		fmt.Printf("no %s migrations found in %s\n", direction, *dir)
		return
	}

	for _, f := range files {
		fmt.Printf("  %-4s %s\n", direction, filepath.Base(f))
		// ON_ERROR_STOP makes a failed statement fail the whole run rather than
		// leaving the schema half-applied.
		cmd := exec.Command("psql", *dsn, "-v", "ON_ERROR_STOP=1", "-q", "-f", f)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fail(fmt.Errorf("%s: %w", filepath.Base(f), err))
		}
	}
	fmt.Printf("applied %d migration(s) %s\n", len(files), direction)
}

// migrations returns the migration files for a direction, ordered so that "up"
// runs oldest-first and "down" runs newest-first.
func migrations(dir, direction string) ([]string, error) {
	if direction != "up" && direction != "down" {
		return nil, fmt.Errorf("direction must be up or down, got %q", direction)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	suffix := "." + direction + ".sql"
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), suffix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	if direction == "down" {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, nil
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "uai-migrate: %v\n", err)
	os.Exit(1)
}
