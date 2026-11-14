package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/angga0x3/whatscore/storage/credentials"
)

// CredentialBackend persists envelope ciphertext in the credentials table.
type CredentialBackend struct {
	pool *pgxpool.Pool
}

var _ credentials.Backend = (*CredentialBackend)(nil)

// NewCredentialBackend returns a backend over pool.
func NewCredentialBackend(pool *pgxpool.Pool) (*CredentialBackend, error) {
	if pool == nil {
		return nil, fmt.Errorf("postgres: nil pool")
	}
	return &CredentialBackend{pool: pool}, nil
}

// Put upserts a sealed blob.
func (b *CredentialBackend) Put(ctx context.Context, key string, blob []byte) error {
	_, err := b.pool.Exec(ctx, `
		INSERT INTO credentials (key, blob, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET blob = EXCLUDED.blob, updated_at = NOW()`,
		key, blob)
	if err != nil {
		return fmt.Errorf("postgres: put credential: %w", err)
	}
	return nil
}

// Get loads a sealed blob.
func (b *CredentialBackend) Get(ctx context.Context, key string) ([]byte, error) {
	var blob []byte
	if err := b.pool.QueryRow(ctx, `SELECT blob FROM credentials WHERE key = $1`, key).Scan(&blob); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", credentials.ErrNotFound, key)
		}
		return nil, fmt.Errorf("postgres: get credential: %w", err)
	}
	return blob, nil
}

// Delete removes a record.
func (b *CredentialBackend) Delete(ctx context.Context, key string) error {
	if _, err := b.pool.Exec(ctx, `DELETE FROM credentials WHERE key = $1`, key); err != nil {
		return fmt.Errorf("postgres: delete credential: %w", err)
	}
	return nil
}
