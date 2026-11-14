//go:build integration

// Integration tests run against a real PostgreSQL instance. They are skipped
// unless TEST_DATABASE_URL points at a disposable database, e.g.:
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable \
//	    go test -tags=integration ./tests/integration/...
//
// `make test-integration` orchestrates the whole thing with Docker.
package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/angga0x3/whatscore/storage/postgres"
	"github.com/angga0x3/whatscore/storage/postgres/migrations"
)

const expectedMigrationVersion = 7

var wantTables = []string{
	"sessions",
	"api_keys",
	"api_key_scopes",
	"messages",
	"events",
	"webhook_endpoints",
	"webhook_deliveries",
	"idempotency_keys",
	"credentials",
}

func TestMigrationsUpDownUp(t *testing.T) {
	adminURL := os.Getenv("TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect to TEST_DATABASE_URL: %v", err)
	}
	// The connection must outlive the cleanup below, so it is closed in a
	// cleanup registered *before* the drop-cleanup.
	t.Cleanup(func() {
		_ = admin.Close(ctx)
	})

	testDB := "whatscore_it_" + randomSuffix(t)
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", testDB)); err != nil {
			t.Logf("cleanup: drop database %s failed: %v", testDB, err)
		}
	})

	if _, err := admin.Exec(ctx, "CREATE DATABASE "+testDB); err != nil {
		t.Fatalf("create scratch database %s: %v", testDB, err)
	}

	dbURL, err := replaceDatabaseName(adminURL, testDB)
	if err != nil {
		t.Fatalf("derive scratch database URL: %v", err)
	}

	logger := slog.New(slog.DiscardHandler)

	// 1. Up: all migrations apply cleanly.
	if err := postgres.MigrateUp(dbURL, migrations.FS(), logger); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	assertSchemaState(t, ctx, dbURL)

	// 2. Down: the schema is fully reversible.
	if err := postgres.MigrateDownAll(dbURL, migrations.FS(), logger); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	assertTablesAbsent(t, ctx, dbURL)

	// 3. Up again: idempotent re-application works.
	if err := postgres.MigrateUp(dbURL, migrations.FS(), logger); err != nil {
		t.Fatalf("migrate up (second run): %v", err)
	}
	assertSchemaState(t, ctx, dbURL)
}

func assertSchemaState(t *testing.T, ctx context.Context, dbURL string) {
	t.Helper()

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect to scratch database: %v", err)
	}
	defer conn.Close(ctx)

	for _, table := range wantTables {
		var exists bool
		err := conn.QueryRow(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, table).Scan(&exists)
		if err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s does not exist after migrations", table)
		}
	}

	var version int
	if err := conn.QueryRow(ctx, "SELECT version FROM schema_migrations").Scan(&version); err != nil {
		t.Fatalf("read schema_migrations.version: %v", err)
	}
	if version != expectedMigrationVersion {
		t.Errorf("schema_migrations.version = %d, want %d", version, expectedMigrationVersion)
	}
}

func assertTablesAbsent(t *testing.T, ctx context.Context, dbURL string) {
	t.Helper()

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect to scratch database: %v", err)
	}
	defer conn.Close(ctx)

	for _, table := range wantTables {
		var exists bool
		err := conn.QueryRow(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, table).Scan(&exists)
		if err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if exists {
			t.Errorf("table %s still exists after down migrations", table)
		}
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generate random suffix: %v", err)
	}
	return hex.EncodeToString(buf)
}

func replaceDatabaseName(databaseURL, newDB string) (string, error) {
	// The test URL is expected to end in a path segment that is the database
	// name, possibly followed by a query string.
	base := databaseURL
	query := ""
	if i := indexQuery(base); i >= 0 {
		base, query = databaseURL[:i], databaseURL[i:]
	}
	idx := lastPathIndex(base)
	if idx <= 0 {
		return "", fmt.Errorf("cannot determine database name in %q", databaseURL)
	}
	return base[:idx] + "/" + newDB + query, nil
}

func indexQuery(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '?' {
			return i
		}
	}
	return -1
}

func lastPathIndex(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}
