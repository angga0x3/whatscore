//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
	"github.com/angga0x3/whatscore/storage/postgres"
	"github.com/angga0x3/whatscore/storage/postgres/migrations"
)

func TestCredentialsVaultPostgres(t *testing.T) {
	adminURL := os.Getenv("TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect to TEST_DATABASE_URL: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(ctx) })

	testDB := "whatscore_cred_" + randomSuffix(t)
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", testDB)); err != nil {
			t.Logf("cleanup: drop database %s failed: %v", testDB, err)
		}
	})
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+testDB); err != nil {
		t.Fatalf("create scratch database: %v", err)
	}
	dbURL, err := replaceDatabaseName(adminURL, testDB)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	if err := postgres.MigrateUp(dbURL, migrations.FS(), logger); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	pool, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	key, err := envelope.NewKey(bytes.Repeat([]byte{0x42}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	backend, err := postgres.NewCredentialBackend(pool)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := credentials.NewVault(backend, key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte(`{"noise":"synthetic","identity":"synthetic"}`)
	if err := vault.Put(ctx, "device/1", plaintext); err != nil {
		t.Fatalf("put: %v", err)
	}

	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT blob FROM credentials WHERE key = $1`, "device/1").Scan(&raw); err != nil {
		t.Fatalf("read raw blob: %v", err)
	}
	if bytes.Contains(raw, plaintext) {
		t.Fatal("database holds plaintext")
	}

	// A second vault over the same database must read the record back.
	secondVault, err := credentials.NewVault(backend, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := secondVault.Get(ctx, "device/1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q", got)
	}

	if err := secondVault.Delete(ctx, "device/1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := vault.Get(ctx, "device/1"); !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
