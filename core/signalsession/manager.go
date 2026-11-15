// Package signalsession persists per-peer Signal ratchet state through an
// encrypted store. The manager is stateless; the store owns concurrency.
package signalsession

import (
	"context"
	"errors"
	"fmt"
)

// ErrInvalidAddress is returned for unusable session ids or peers.
var ErrInvalidAddress = errors.New("core/signalsession: invalid address")

// Store persists opaque records. *storage/credentials.Vault satisfies it.
type Store interface {
	Put(ctx context.Context, key string, blob []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

// Manager maps (session, peer) to an encrypted ratchet state.
type Manager struct {
	store     Store
	sessionID string
}

// New validates the store and session id.
func New(store Store, sessionID string) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("core/signalsession: nil store")
	}
	if err := validateToken(sessionID, "session id", 128); err != nil {
		return nil, err
	}
	return &Manager{store: store, sessionID: sessionID}, nil
}
