# SQLite storage backend

`storage/sqlite` is the SDK and development default declared in
[technical specification §2 decision 6](technical-specification.md#2-locked-decisions):
SQLite through [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite),
a pure-Go driver with no cgo. The REST server keeps using PostgreSQL
(`storage/postgres`); both backends answer the same `[]byte` keyed lookups, so
the application never learns which one is active.

## Scope

The package implements `storage/credentials.Backend`:

```go
Open(path string) (*DB, error)
(*DB) Close() error
(*DB) Path() string
(*DB) CredentialBackend() *CredentialBackend

(*CredentialBackend) Put(ctx, key string, blob []byte) error
(*CredentialBackend) Get(ctx, key string) ([]byte, error)
(*CredentialBackend) Delete(ctx, key string) error
(*CredentialBackend) Persistence() error
```

`Persistence` reports whether the store can still write: it returns
`ErrClosed` once `Close` has run, so a composition root fails at startup
rather than on the first session write. The remaining `storage.Store`
interfaces (identities, prekeys, signed prekeys, sender keys, app state) are
not implemented yet; they land with the core work that consumes them, on the
same schema pattern.

## File layout

`Open` resolves `path` to an absolute path and creates the database file if
missing. It does not create parent directories; the data directory must exist
already, and the driver's error is returned if it does not. A single session
uses one file:

```
<data-dir>/whatscore.db        main database file
<data-dir>/whatscore.db-wal    write-ahead log (while a connection is open)
<data-dir>/whatscore.db-shm    shared-memory index for the WAL
```

The `-wal` and `-shm` files are part of the database, not scratch data. Do not
delete them while a process holds the file open, and copy all three when
taking a cold backup outside the checkpoint described below.

## Pragmas

Pragmas are appended to the DSN (`file:/abs/path?...&_pragma=...`) rather than
executed once after opening, so every connection the pool hands out carries
them, not just the first one:

| Pragma | Value | Why |
|--------|-------|-----|
| `journal_mode` | `WAL` | Readers do not block the writer; the setting is persistent in the file. |
| `busy_timeout` | `5000` ms | A competing process (backup tool, second SDK instance) gets a bounded wait instead of an immediate `SQLITE_BUSY`. |
| `foreign_keys` | `1` | Off by default in SQLite; enabled so later tables with references are enforced, matching PostgreSQL semantics. |
| `synchronous` | `NORMAL` | Safe with WAL: a committed transaction survives a process crash, and only an OS-level power loss can lose the last commits. `FULL` costs an fsync per write. |

The DSN also uses a `file:` URI with an absolute path and no host component,
so a relative path or a name containing reserved characters cannot be
misread as a network or temporary database.

## Schema

Schema revision 1, created idempotently on every `Open`:

```sql
CREATE TABLE schema_version (
    version    INTEGER NOT NULL,
    applied_at INTEGER NOT NULL
);

CREATE TABLE credentials (
    key        TEXT PRIMARY KEY NOT NULL,
    blob       BLOB NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
```

- `schema_version` gets exactly one row: the revision this build applied.
  Opening a file whose version is **newer** than `SchemaVersion` fails with
  `ErrSchemaTooNew` instead of writing an older layout over it.
- `credentials` mirrors the PostgreSQL
  `000007_create_credentials` migration: `key TEXT PRIMARY KEY` (declared
  `NOT NULL` here for parity with the primary-key semantics), `blob BYTEA
  NOT NULL`, `updated_at`. SQLite has no `TIMESTAMPTZ`, so `updated_at` is
  Unix seconds. `Put` upserts with `ON CONFLICT(key) DO UPDATE`.
- Keys are capped at 512 bytes and may not be empty (`ErrInvalidKey`),
  matching the vault's own `validateKey`. That limit is duplicated here
  deliberately: the backend stays correct when used without the vault.

## Ciphertext only

This backend never sees plaintext. `storage/credentials.Vault` seals each
record with AES-256-GCM under the envelope key, binding the record key as
associated data, and passes the sealed bytes here; `storage/envelope` owns the
format (`version || nonce || ciphertext || tag`). The `blob` column therefore
holds only envelope ciphertext, and the SQL layer stores and returns it
verbatim — it never parses, trims, or interprets a value.

Two consequences for operators:

- Losing `ENCRYPTION_KEY` makes the file useless; there is no recovery path
  in this package.
- A stolen file leaks record **names** (the `key` column) and blob sizes, not
  credential contents. Restrict the data directory to the service account
  (`0700` directory, `0600` file) anyway; `Open` creates the file with the
  process umask and does not change permissions afterwards.

## Concurrency

`Open` calls `sql.SetMaxOpenConns(1)` and `SetMaxIdleConns(1)`. One connection
is intentional:

- It serializes writes inside the process, so a write transaction never fails
  the WAL writer upgrade with `SQLITE_BUSY` against itself.
- It bounds memory: `modernc.org/sqlite` keeps a page cache and libc thread
  state per connection.
- An SDK client drives one WhatsApp session (spec §2 decision 3, "one session,
  one actor"), so a single writer is the whole workload.

Reads from another **process** still proceed concurrently in WAL mode, and the
`busy_timeout` covers that case. If a future deployment needs several
in-process writers, raise `SetMaxOpenConns` and keep the busy timeout; WAL does
not require one connection.

`*DB` and `*CredentialBackend` are safe for concurrent use, and `Close` is
idempotent. After `Close`, every method returns `ErrClosed`.

## Backup

`Close` runs `PRAGMA wal_checkpoint(TRUNCATE)` before closing the handle, so a
gracefully stopped process leaves all committed data in `whatscore.db` and the
WAL files empty. A checkpoint can fail when another connection is reading; that
error is returned from `Close`, and committed data is still safe because SQLite
replays the WAL on the next open.

For a hot copy of a running database, either use `VACUUM INTO 'backup.db'` or
`sqlite3 whatscore.db ".backup backup.db"` rather than copying `whatscore.db`
alone — the WAL may hold commits not yet in the main file. For a cold copy,
stop the process first, then archive all three files.

## Testing

`go test -race ./storage/sqlite/` covers open/close/reopen persistence, the
schema version row, the applied pragmas, Put/Get/Delete round trips from 0 B
to 1 MiB, overwrite semantics, `credentials.ErrNotFound` on a missing record,
an idempotent delete, key limits, closed-store errors, a newer-schema
rejection, concurrent access, and that a reopened file still reads its values.
The suite uses `t.TempDir()` files and never touches a developer database.
