// Package postgres owns the PostgreSQL connection pool and schema migrations.
//
// WhatsCore keeps its own tables (sessions, messages, webhooks, ...) in the
// same database as the whatsmeow device store, but it never touches the
// whatsmeow tables directly — those are owned by the engine.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pingTimeout = 5 * time.Second

// NewPool creates a pgx connection pool and verifies connectivity with a
// bounded ping before returning.
func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database config: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}

// PingChecker adapts the pool to the readiness check contract used by the
// HTTP layer (handlers.Checker). It is satisfied structurally, so the
// storage package does not need to import the transport package.
type PingChecker struct {
	Pool *pgxpool.Pool
}

// Name implements handlers.Checker.
func (c PingChecker) Name() string { return "database" }

// Check implements handlers.Checker.
func (c PingChecker) Check(ctx context.Context) error {
	return c.Pool.Ping(ctx)
}
