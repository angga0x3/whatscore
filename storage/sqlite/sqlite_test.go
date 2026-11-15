package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
)

func openTemp(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "whatscore.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func randomBlob(t *testing.T, size int) []byte {
	t.Helper()
	blob := make([]byte, size)
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return blob
}

func TestOpenReopenPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whatscore.db")
	blob := randomBlob(t, 96)

	db, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	backend := db.CredentialBackend()
	if err := backend.Put(context.Background(), "device/registration", blob); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close after reopen: %v", err)
		}
	}()

	got, err := db.CredentialBackend().Get(context.Background(), "device/registration")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("blob changed across reopen: got %d bytes, want %d", len(got), len(blob))
	}
}

func TestSchemaVersionRecorded(t *testing.T) {
	db := openTemp(t)

	var version int
	if err := db.sql.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&version); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if version != SchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, SchemaVersion)
	}

	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&count); err != nil {
		t.Fatalf("count schema_version: %v", err)
	}
	if count != 1 {
		t.Fatalf("schema_version rows = %d, want 1 (reopen must not append)", count)
	}

	// Reopening an up-to-date file must not add another version row.
	path := db.Path()
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db2.Close() }()

	if err := db2.sql.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&count); err != nil {
		t.Fatalf("count schema_version after reopen: %v", err)
	}
	if count != 1 {
		t.Fatalf("schema_version rows after reopen = %d, want 1", count)
	}
}

func TestPragmasApplied(t *testing.T) {
	db := openTemp(t)

	var journalMode string
	if err := db.sql.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want %q", journalMode, "wal")
	}

	var busyTimeout int
	if err := db.sql.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if busyTimeout != busyTimeoutMS {
		t.Errorf("busy_timeout = %d, want %d", busyTimeout, busyTimeoutMS)
	}

	var foreignKeys int
	if err := db.sql.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, want 1", foreignKeys)
	}

	var synchronous int
	if err := db.sql.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatalf("read synchronous: %v", err)
	}
	if synchronous != 1 { // NORMAL
		t.Errorf("synchronous = %d, want 1 (NORMAL)", synchronous)
	}
}

func TestPutGetDeleteRoundTrip(t *testing.T) {
	db := openTemp(t)
	backend := db.CredentialBackend()
	ctx := context.Background()

	sizes := []int{0, 1, 15, 16, 17, 4096, 1 << 20}
	for _, size := range sizes {
		size := size
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			key := fmt.Sprintf("record/%d", size)
			blob := randomBlob(t, size)

			if err := backend.Put(ctx, key, blob); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got, err := backend.Get(ctx, key)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(got, blob) {
				t.Fatalf("Get returned %d bytes that differ from the %d stored", len(got), len(blob))
			}

			if err := backend.Delete(ctx, key); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := backend.Get(ctx, key); !errors.Is(err, credentials.ErrNotFound) {
				t.Fatalf("Get after Delete error = %v, want credentials.ErrNotFound", err)
			}
		})
	}
}

func TestPutOverwrites(t *testing.T) {
	db := openTemp(t)
	backend := db.CredentialBackend()
	ctx := context.Background()
	key := "device/registration"

	first := randomBlob(t, 64)
	second := randomBlob(t, 128)

	if err := backend.Put(ctx, key, first); err != nil {
		t.Fatalf("first Put: %v", err)
	}

	var firstStamp int64
	if err := db.sql.QueryRow(`SELECT updated_at FROM credentials WHERE key = ?`, key).Scan(&firstStamp); err != nil {
		t.Fatalf("read updated_at: %v", err)
	}

	// unixepoch() has one-second resolution; wait so an unchanged timestamp
	// would be a real failure rather than a fast clock.
	time.Sleep(1100 * time.Millisecond)

	if err := backend.Put(ctx, key, second); err != nil {
		t.Fatalf("second Put: %v", err)
	}

	got, err := backend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("overwrite kept stale blob: got %d bytes, want the %d-byte replacement", len(got), len(second))
	}

	var rows int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM credentials WHERE key = ?`, key).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 1 {
		t.Fatalf("rows for %q = %d, want 1 (upsert, not insert)", key, rows)
	}

	var secondStamp int64
	if err := db.sql.QueryRow(`SELECT updated_at FROM credentials WHERE key = ?`, key).Scan(&secondStamp); err != nil {
		t.Fatalf("read updated_at after overwrite: %v", err)
	}
	if secondStamp < firstStamp {
		t.Fatalf("updated_at went backwards: %d then %d", firstStamp, secondStamp)
	}
}

func TestGetNotFound(t *testing.T) {
	db := openTemp(t)
	_, err := db.CredentialBackend().Get(context.Background(), "missing")
	if err == nil {
		t.Fatal("Get of a missing key returned nil error")
	}
	if !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("Get missing error = %v, want errors.Is(credentials.ErrNotFound)", err)
	}
}

func TestDeleteMissingIsNotAnError(t *testing.T) {
	db := openTemp(t)
	if err := db.CredentialBackend().Delete(context.Background(), "missing"); err != nil {
		t.Fatalf("Delete of a missing key = %v, want nil", err)
	}
}

func TestKeyValidation(t *testing.T) {
	db := openTemp(t)
	backend := db.CredentialBackend()
	ctx := context.Background()

	if err := backend.Put(ctx, "", []byte("x")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Put with empty key = %v, want ErrInvalidKey", err)
	}
	if _, err := backend.Get(ctx, ""); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Get with empty key = %v, want ErrInvalidKey", err)
	}
	if err := backend.Delete(ctx, ""); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Delete with empty key = %v, want ErrInvalidKey", err)
	}

	oversized := string(bytes.Repeat([]byte("k"), maxKeyBytes+1))
	if err := backend.Put(ctx, oversized, []byte("x")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Put with %d-byte key = %v, want ErrInvalidKey", len(oversized), err)
	}
	if _, err := backend.Get(ctx, oversized); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Get with %d-byte key = %v, want ErrInvalidKey", len(oversized), err)
	}
	if err := backend.Delete(ctx, oversized); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Delete with %d-byte key = %v, want ErrInvalidKey", len(oversized), err)
	}

	// The boundary itself is legal.
	boundary := string(bytes.Repeat([]byte("k"), maxKeyBytes))
	if err := backend.Put(ctx, boundary, []byte("ok")); err != nil {
		t.Errorf("Put with %d-byte key = %v, want nil", len(boundary), err)
	}
}

func TestCloseSemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whatscore.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	backend := db.CredentialBackend()
	ctx := context.Background()

	if err := backend.Persistence(); err != nil {
		t.Fatalf("Persistence before Close = %v, want nil", err)
	}
	if err := backend.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put before Close: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := backend.Persistence(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Persistence after Close = %v, want ErrClosed", err)
	}
	if err := backend.Put(ctx, "k", []byte("v")); !errors.Is(err, ErrClosed) {
		t.Errorf("Put after Close = %v, want ErrClosed", err)
	}
	if _, err := backend.Get(ctx, "k"); !errors.Is(err, ErrClosed) {
		t.Errorf("Get after Close = %v, want ErrClosed", err)
	}
	if err := backend.Delete(ctx, "k"); !errors.Is(err, ErrClosed) {
		t.Errorf("Delete after Close = %v, want ErrClosed", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("Open(\"\") returned nil error")
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whatscore.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := db.sql.Exec(`UPDATE schema_version SET version = ?`, SchemaVersion+1); err != nil {
		t.Fatalf("bump schema version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := Open(path); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Open of newer schema = %v, want ErrSchemaTooNew", err)
	}
}

// TestConcurrentAccess exercises the single-connection pool from many
// goroutines. Run with -race.
func TestConcurrentAccess(t *testing.T) {
	db := openTemp(t)
	backend := db.CredentialBackend()
	ctx := context.Background()

	const workers = 16
	const recordsPerWorker = 8

	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for w := 0; w < workers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < recordsPerWorker; r++ {
				key := fmt.Sprintf("worker/%d/record/%d", w, r)
				blob := bytes.Repeat([]byte{byte(w), byte(r)}, 32+r)

				if err := backend.Put(ctx, key, blob); err != nil {
					errCh <- fmt.Errorf("Put %q: %w", key, err)
					return
				}
				got, err := backend.Get(ctx, key)
				if err != nil {
					errCh <- fmt.Errorf("Get %q: %w", key, err)
					return
				}
				if !bytes.Equal(got, blob) {
					errCh <- fmt.Errorf("Get %q returned a different blob", key)
					return
				}
				if _, err := backend.Get(ctx, fmt.Sprintf("worker/%d/absent/%d", w, r)); !errors.Is(err, credentials.ErrNotFound) {
					errCh <- fmt.Errorf("Get absent key error = %v, want ErrNotFound", err)
					return
				}
				if err := backend.Delete(ctx, key); err != nil {
					errCh <- fmt.Errorf("Delete %q: %w", key, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}

	var rows int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 0 {
		t.Fatalf("rows after balanced Put/Delete = %d, want 0", rows)
	}
}

// TestReopenUnderConcurrentWrites checks that a value written, read back, and
// re-read after reopening the file survives the WAL checkpoint.
func TestReopenUnderConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whatscore.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	backend := db.CredentialBackend()
	ctx := context.Background()

	const records = 32
	want := make(map[string][]byte, records)
	for i := 0; i < records; i++ {
		key := fmt.Sprintf("record/%02d", i)
		blob := randomBlob(t, 64+i)
		want[key] = blob
		if err := backend.Put(ctx, key, blob); err != nil {
			t.Fatalf("Put %q: %v", key, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()

	for key, blob := range want {
		got, err := db.CredentialBackend().Get(ctx, key)
		if err != nil {
			t.Fatalf("Get %q after reopen: %v", key, err)
		}
		if !bytes.Equal(got, blob) {
			t.Fatalf("Get %q after reopen returned a different blob", key)
		}
	}
}

// TestVaultIntegration confirms the backend satisfies credentials.Backend and
// that only envelope ciphertext reaches the table.
func TestVaultIntegration(t *testing.T) {
	db := openTemp(t)

	key, err := envelope.NewKey(bytes.Repeat([]byte{0x5a}, envelope.KeySize))
	if err != nil {
		t.Fatalf("envelope.NewKey: %v", err)
	}
	vault, err := credentials.NewVault(db.CredentialBackend(), key)
	if err != nil {
		t.Fatalf("credentials.NewVault: %v", err)
	}

	ctx := context.Background()
	plaintext := []byte(`{"registration_id":4242,"noise_key":"synthetic"}`)
	recordKey := "device/registration"

	if err := vault.Put(ctx, recordKey, plaintext); err != nil {
		t.Fatalf("vault.Put: %v", err)
	}
	got, err := vault.Get(ctx, recordKey)
	if err != nil {
		t.Fatalf("vault.Get: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("vault round trip = %q, want %q", got, plaintext)
	}

	var stored []byte
	if err := db.sql.QueryRow(`SELECT blob FROM credentials WHERE key = ?`, recordKey).Scan(&stored); err != nil {
		t.Fatalf("read stored blob: %v", err)
	}
	if bytes.Contains(stored, plaintext) {
		t.Fatal("plaintext reached the credentials table; only envelope ciphertext may be stored")
	}
	if len(stored) != envelope.HeaderSize+len(plaintext)+envelope.TagSize {
		t.Fatalf("stored blob is %d bytes, want envelope size %d",
			len(stored), envelope.HeaderSize+len(plaintext)+envelope.TagSize)
	}

	if err := vault.Delete(ctx, recordKey); err != nil {
		t.Fatalf("vault.Delete: %v", err)
	}
	if _, err := vault.Get(ctx, recordKey); !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("vault.Get after Delete = %v, want credentials.ErrNotFound", err)
	}
}
