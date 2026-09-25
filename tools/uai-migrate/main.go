// Command uai-migrate applies the UAI SQL migrations.
//
// It is deliberately small and dependency-free: it shells out to psql rather
// than linking a driver, so the migration path has no Go dependency that could
// differ from what a DBA runs by hand. Production uses forward-only migrations;
// the down direction exists for development.
package main

import (
	"crypto/sha256"
	"encoding/hex"
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
	// baseline is up's bookkeeping without up's effects: it records every
	// migration as applied without running one. For a database that already
	// carries the schema from before this tool kept a ledger. Separated from
	// `up` and named plainly, because a mode that silently marks unapplied
	// migrations as done is exactly the thing that must never happen by accident.
	baseline := direction == "baseline"
	if baseline {
		direction = "up"
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

	if err := ensureLedger(*dsn); err != nil {
		fail(err)
	}
	done, err := applied(*dsn)
	if err != nil {
		fail(err)
	}

	ran := 0
	for _, f := range files {
		name := filepath.Base(f)
		sum, err := checksum(f)
		if err != nil {
			fail(err)
		}
		if direction == "up" {
			if prior, ok := done[name]; ok {
				if prior != sum {
					// An applied migration that changed on disk means this
					// database and the file no longer describe the same schema,
					// and no amount of re-running fixes that. Applying it again
					// would half-apply a diff nobody wrote.
					fail(fmt.Errorf("%s was applied with a different content (recorded %s, on disk %s).\n"+
						"A migration that changed after it ran describes a schema this database does not have.\n"+
						"Write a new migration instead of editing an applied one.",
						name, short(prior), short(sum)))
				}
				fmt.Printf("  skip %s\n", name)
				continue
			}
		} else if _, ok := done[name]; !ok {
			// Nothing to roll back. Running the down file anyway would drop
			// objects this migration never created.
			fmt.Printf("  skip %s (never applied)\n", name)
			continue
		}

		if baseline {
			fmt.Printf("  mark %s\n", name)
		} else {
			fmt.Printf("  %-4s %s\n", direction, name)
			// ON_ERROR_STOP makes a failed statement fail the whole run rather
			// than leaving the schema half-applied.
			cmd := exec.Command("psql", *dsn, "-v", "ON_ERROR_STOP=1", "-q", "-f", f)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				fail(fmt.Errorf("%s: %w", name, err))
			}
		}
		if err := record(*dsn, direction, name, sum); err != nil {
			fail(err)
		}
		ran++
	}
	switch {
	case baseline:
		fmt.Printf("marked %d migration(s) as already applied; nothing was run\n", ran)
	case ran == 0 && direction == "up":
		fmt.Println("already up to date")
	default:
		fmt.Printf("applied %d migration(s) %s\n", ran, direction)
	}
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

// ── the ledger ──────────────────────────────────────────────────────────────
//
// Without it this tool re-ran every file on every invocation, so it worked
// exactly once per database: the second `make dev` failed on
// `type "agent_status" already exists`. A migration tool that only works on an
// empty database is a tool that teaches people to delete their data.

const ledgerDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   text PRIMARY KEY,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

func ensureLedger(dsn string) error {
	return psql(dsn, ledgerDDL)
}

// applied returns the migrations this database has, by filename and checksum.
func applied(dsn string) (map[string]string, error) {
	out, err := psqlOut(dsn, "SELECT filename || ' ' || checksum FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	done := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		name, sum, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			done[name] = sum
		}
	}
	return done, nil
}

func record(dsn, direction, name, sum string) error {
	if direction == "down" {
		return psql(dsn, fmt.Sprintf(
			"DELETE FROM schema_migrations WHERE filename = %s", quote(name)))
	}
	return psql(dsn, fmt.Sprintf(
		"INSERT INTO schema_migrations (filename, checksum) VALUES (%s, %s)",
		quote(name), quote(sum)))
}

func checksum(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

// quote renders a SQL string literal. The only values reaching it are migration
// filenames and hex digests, but building SQL by concatenation without escaping
// is a habit that survives the context it was safe in.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func psql(dsn, sql string) error {
	cmd := exec.Command("psql", dsn, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func psqlOut(dsn, sql string) (string, error) {
	cmd := exec.Command("psql", dsn, "-v", "ON_ERROR_STOP=1", "-qtAc", sql)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return string(out), err
}
