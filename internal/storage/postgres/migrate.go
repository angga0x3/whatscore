package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	// Registers the "pgx" database/sql driver used below.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// MigrateUp applies all pending migrations from migrationsFS.
// It is idempotent: with no pending migrations it is a no-op.
//
// golang-migrate takes a PostgreSQL advisory lock for the duration, so it is
// safe to run this at startup even with overlapping deployments.
func MigrateUp(databaseURL string, migrationsFS fs.FS, logger *slog.Logger) error {
	m, err := newMigrator(databaseURL, migrationsFS)
	if err != nil {
		return err
	}
	defer closeMigrator(m, logger)

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}

	logMigrationState(m, logger)
	return nil
}

// MigrateDownAll rolls back every migration. Used by tests that need a clean
// schema, not by the application at runtime.
func MigrateDownAll(databaseURL string, migrationsFS fs.FS, logger *slog.Logger) error {
	m, err := newMigrator(databaseURL, migrationsFS)
	if err != nil {
		return err
	}
	defer closeMigrator(m, logger)

	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("revert migrations: %w", err)
	}

	logMigrationState(m, logger)
	return nil
}

func newMigrator(databaseURL string, migrationsFS fs.FS) (*migrate.Migrate, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create migration driver: %w", err)
	}

	source, err := iofs.New(migrationsFS, ".")
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("load embedded migrations: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create migrator: %w", err)
	}
	return m, nil
}

// closeMigrator releases the advisory lock and the underlying connections.
// Close returns one error per resource (source, database); both are logged.
func closeMigrator(m *migrate.Migrate, logger *slog.Logger) {
	if errSource, errDB := m.Close(); errSource != nil || errDB != nil {
		logger.Error("failed to close migrator",
			"source_error", errSource,
			"database_error", errDB,
		)
	}
}

func logMigrationState(m *migrate.Migrate, logger *slog.Logger) {
	version, dirty, err := m.Version()
	switch {
	case errors.Is(err, migrate.ErrNilVersion):
		logger.Info("database schema is empty (no migrations applied)")
	case err != nil:
		logger.Error("failed to read migration version", "error", err)
	default:
		entry := slog.String("version", fmt.Sprintf("%06d", version))
		if dirty {
			logger.Error("database schema is in a DIRTY migration state, manual intervention required", entry)
		} else {
			logger.Info("database schema is up to date", entry)
		}
	}
}
