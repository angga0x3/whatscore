// Package sqlite is the pure-Go SQLite storage backend (modernc.org/sqlite,
// no cgo) for the SDK's encrypted credential records and Signal session
// records.
//
// The backend only ever persists envelope ciphertext: storage/credentials
// seals plaintext before it reaches this package, and storage never
// interprets a blob it stores. See docs/architecture/storage.md for the file
// layout, pragmas, schema, and backup notes.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/angga0x3/whatscore/storage/credentials"

	// Registers the pure-Go "sqlite" database/sql driver.
	_ "modernc.org/sqlite"
)

// SchemaVersion is the schema revision this build creates and understands.
const SchemaVersion = 1

const (
	// busyTimeoutMS bounds how long SQLite waits for a competing writer
	// before returning SQLITE_BUSY.
	busyTimeoutMS = 5000
	// maxKeyBytes mirrors credentials.validateKey: the vault never forwards
	// a longer record key, and rejecting it here keeps the backend usable
	// on its own.
	maxKeyBytes = 512

	pingTimeout       = 5 * time.Second
	checkpointTimeout = 5 * time.Second
)

// Sentinels. Get wraps credentials.ErrNotFound for missing records; the rest
// describe backend state and are matched with errors.Is.
var (
	// ErrClosed is returned by every operation after Close.
	ErrClosed = errors.New("storage/sqlite: database is closed")
	// ErrInvalidKey is returned for empty or oversized record keys.
	ErrInvalidKey = errors.New("storage/sqlite: invalid record key")
	// ErrSchemaTooNew is returned when the database file was written by a
	// build with a newer schema revision.
	ErrSchemaTooNew = errors.New("storage/sqlite: schema is newer than this build")
)

// schemaStatements are idempotent so a reopen of an up-to-date file is a
// no-op. Both tables use the same column semantics as the PostgreSQL
// backend's 000007_create_credentials migration; updated_at stores Unix
// seconds because SQLite has no TIMESTAMPTZ.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER NOT NULL,
		applied_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS credentials (
		key        TEXT PRIMARY KEY NOT NULL,
		blob       BLOB NOT NULL,
		updated_at INTEGER NOT NULL DEFAULT (unixepoch())
	)`,
}

// DB is a SQLite database file holding the credential store.
//
// It is safe for concurrent use. The pool is capped at one connection (see
// Open), so writes never contend and SQLITE_BUSY is not expected in-process.
type DB struct {
	sql    *sql.DB
	path   string
	closed atomic.Bool
}

// Open opens (creating if needed) the SQLite database at path, applies the
// connection pragmas and schema, and returns a ready handle.
//
// Pragmas are set in the DSN so they apply to every connection the pool
// hands out, not just the first one: journal_mode=WAL, busy_timeout=5000,
// foreign_keys=1, synchronous=NORMAL.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("storage/sqlite: empty database path")
	}

	dsn, absPath, err := buildDSN(path)
	if err != nil {
		return nil, err
	}

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage/sqlite: open %q: %w", absPath, err)
	}

	// One connection is deliberate. It serializes writers inside the
	// process, so a deferred transaction can never fail the WAL writer
	// upgrade with SQLITE_BUSY, and it bounds modernc.org/sqlite's per-
	// connection page cache for an SDK that serves a single session. WAL
	// still lets other processes read the file concurrently. If a second
	// writer is ever needed, raise this and keep the busy timeout.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	db := &DB{sql: sqlDB, path: absPath}

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("storage/sqlite: open %q: %w", absPath, err)
	}
	if err := db.migrate(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}

// buildDSN resolves path to an absolute file: URI and appends the pragmas.
// Absolute paths keep the URI unambiguous (no host component) and let the
// url package escape spaces and reserved characters.
func buildDSN(path string) (dsn, absPath string, err error) {
	absPath, err = filepath.Abs(path)
	if err != nil {
		return "", "", fmt.Errorf("storage/sqlite: resolve %q: %w", path, err)
	}

	u := url.URL{Scheme: "file", Path: filepath.ToSlash(absPath)}
	q := u.Query()
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout("+strconv.Itoa(busyTimeoutMS)+")")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	u.RawQuery = q.Encode()

	return u.String(), absPath, nil
}

// migrate creates the schema and records the revision. A file from a newer
// build is rejected instead of being written with an older layout.
func (db *DB) migrate(ctx context.Context) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage/sqlite: begin schema transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range schemaStatements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("storage/sqlite: apply schema: %w", err)
		}
	}

	var version int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&version); err != nil {
		return fmt.Errorf("storage/sqlite: read schema version: %w", err)
	}

	switch {
	case version > SchemaVersion:
		return fmt.Errorf("%w: found %d, supported %d", ErrSchemaTooNew, version, SchemaVersion)
	case version < SchemaVersion:
		// Only revision 1 exists so far; future steps append to
		// schemaStatements and bump SchemaVersion.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_version (version, applied_at) VALUES (?, unixepoch())`,
			SchemaVersion); err != nil {
			return fmt.Errorf("storage/sqlite: record schema version: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storage/sqlite: commit schema: %w", err)
	}
	return nil
}

// Close checkpoints the WAL into the main file and closes the handle. It is
// idempotent. A checkpoint can fail (for example with a concurrent reader)
// without losing committed data: the WAL is replayed on the next open, so
// the checkpoint error is returned alongside a successful close.
func (db *DB) Close() error {
	if db.closed.Swap(true) {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), checkpointTimeout)
	defer cancel()

	var checkpointErr error
	if _, err := db.sql.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		checkpointErr = fmt.Errorf("storage/sqlite: checkpoint %q: %w", db.path, err)
	}

	if err := db.sql.Close(); err != nil {
		return errors.Join(checkpointErr, fmt.Errorf("storage/sqlite: close %q: %w", db.path, err))
	}
	return checkpointErr
}

// Path returns the absolute database file path.
func (db *DB) Path() string { return db.path }

// errIfClosed returns ErrClosed once Close has run.
func (db *DB) errIfClosed() error {
	if db.closed.Load() {
		return ErrClosed
	}
	return nil
}

// CredentialBackend persists envelope ciphertext in the credentials table.
type CredentialBackend struct {
	db *DB
}

var _ credentials.Backend = (*CredentialBackend)(nil)

// CredentialBackend returns a credential backend that shares db's pool and
// closed state.
func (db *DB) CredentialBackend() *CredentialBackend {
	return &CredentialBackend{db: db}
}

// Persistence reports whether the backend can still persist records. It
// returns ErrClosed once the database is closed, so a composition root can
// fail fast instead of discovering the closed store on the first read.
func (b *CredentialBackend) Persistence() error {
	return b.db.errIfClosed()
}

// Put upserts a sealed blob. The blob is stored verbatim.
func (b *CredentialBackend) Put(ctx context.Context, key string, blob []byte) error {
	if err := b.prepare(key); err != nil {
		return err
	}
	_, err := b.db.sql.ExecContext(ctx, `
		INSERT INTO credentials (key, blob, updated_at)
		VALUES (?, ?, unixepoch())
		ON CONFLICT(key) DO UPDATE SET blob = excluded.blob, updated_at = unixepoch()`,
		key, blob)
	if err != nil {
		return fmt.Errorf("storage/sqlite: put credential: %w", err)
	}
	return nil
}

// Get loads a sealed blob. A missing record returns an error that matches
// credentials.ErrNotFound.
func (b *CredentialBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if err := b.prepare(key); err != nil {
		return nil, err
	}

	var blob []byte
	err := b.db.sql.QueryRowContext(ctx, `SELECT blob FROM credentials WHERE key = ?`, key).Scan(&blob)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", credentials.ErrNotFound, key)
		}
		return nil, fmt.Errorf("storage/sqlite: get credential: %w", err)
	}
	return blob, nil
}

// Delete removes a record. A missing record is not an error.
func (b *CredentialBackend) Delete(ctx context.Context, key string) error {
	if err := b.prepare(key); err != nil {
		return err
	}
	if _, err := b.db.sql.ExecContext(ctx, `DELETE FROM credentials WHERE key = ?`, key); err != nil {
		return fmt.Errorf("storage/sqlite: delete credential: %w", err)
	}
	return nil
}

// prepare validates the closed state and the record key before touching SQL.
func (b *CredentialBackend) prepare(key string) error {
	if err := b.db.errIfClosed(); err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("%w: empty", ErrInvalidKey)
	}
	if len(key) > maxKeyBytes {
		return fmt.Errorf("%w: %d bytes, max %d", ErrInvalidKey, len(key), maxKeyBytes)
	}
	return nil
}
