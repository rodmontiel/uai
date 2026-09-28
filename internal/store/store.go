// Package store is the PostgreSQL persistence layer.
//
// It lives under internal/ rather than pkg/ on purpose: it needs a database
// driver, and pkg/ is the verification core that must stay dependency-free
// (see docs/protocol/18-repository-structure.md section 25.2.1).
//
// The database is a cache of verifiable truth, not the source of it. Every
// consequential row carries its own signature and commitment, and the same
// facts are committed to the transparency log. A database administrator with
// full access can cause an outage; they cannot produce a forgery that survives
// verification against the log and the ledger.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Common errors. Callers map these to UAI_* API codes.
var (
	// ErrNotFound is returned when a row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned on a uniqueness violation that is not a fork.
	ErrConflict = errors.New("store: conflict")
	// ErrKeyNotUnique is returned when a public key is already registered to a
	// different identity. Separate from ErrConflict because the caller's answer
	// is different: not "retry", but "that key is somebody else's name".
	ErrKeyNotUnique = errors.New("store: key already names another identity")
	// ErrChainConflict is returned when an append references a stale chain head.
	// The caller refetches the head and retries; the API surfaces this as
	// 409 UAI_CHAIN_CONFLICT.
	ErrChainConflict = errors.New("store: stale chain head")
	// ErrFork reports two COMMITTED events sharing a predecessor.
	//
	// It is deliberately never returned by an insert. Within one database a
	// fork cannot be committed at all -- the unique index sees to that -- so
	// what an insert observes is only that someone else got there first, which
	// is an ordinary race between replicas of the same agent. Reporting that as
	// a fork would raise an incident against an innocent agent every time two
	// of its replicas attested concurrently (threat T-24).
	//
	// A genuine fork is a cross-instance and cross-log observation, exactly as
	// docs/protocol/06-action-attestation.md section 10.6 describes.
	ErrFork = errors.New("store: chain fork detected")
	// ErrAppendOnly is returned when a database guard refused a mutation.
	ErrAppendOnly = errors.New("store: table is append-only")
)

// DB is a connection pool with the UAI repositories attached.
type DB struct {
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL.
func Open(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close releases the pool.
func (db *DB) Close() { db.pool.Close() }

// Pool exposes the underlying pool for tests and for repositories in other
// packages.
func (db *DB) Pool() *pgxpool.Pool { return db.pool }

// InTx runs fn inside a transaction, rolling back on error.
func (db *DB) InTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// classify turns a PostgreSQL error into one of the package's sentinel errors.
//
// The append-only guards raise a specific message, and mapping it here means a
// handler can distinguish "you tried to do something forbidden" from "the
// database is down" without parsing strings itself.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == "23505":
			// A trigger-raised uniqueness violation carries its reason in the
			// message and has no constraint to name, so preferring the
			// constraint name handed the client "conflict:" and nothing after
			// the colon -- a refusal with the reason removed.
			if strings.HasPrefix(pgErr.Message, "UAI_KEY_NOT_UNIQUE:") {
				return fmt.Errorf("%w: %s", ErrKeyNotUnique,
					strings.TrimSpace(strings.TrimPrefix(pgErr.Message, "UAI_KEY_NOT_UNIQUE:")))
			}
			if pgErr.ConstraintName == "" {
				return fmt.Errorf("%w: %s", ErrConflict, pgErr.Message)
			}
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
		case pgErr.Code == "23503":
			return fmt.Errorf("%w: %s", ErrNotFound, pgErr.ConstraintName)
		}
		if len(pgErr.Message) >= 16 && pgErr.Message[:16] == "UAI_APPEND_ONLY:" {
			return fmt.Errorf("%w: %s", ErrAppendOnly, pgErr.Message)
		}
	}
	return err
}
