// Package signalsession persists per-peer Signal ratchet state through an
// encrypted store. The manager is stateless about the ratchet; the store owns
// concurrency and durability.
package signalsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
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
	notFound  func(error) bool

	// mu serializes the read-modify-write of the peer index. Records are
	// independent, but two concurrent saves of different peers would
	// otherwise drop one index entry.
	mu sync.Mutex
}

// Option configures a Manager.
type Option func(*Manager) error

// WithNotFound teaches the manager how its store reports a missing record.
// The predicate belongs to the caller because this package never imports a
// backend; without one, a failed index read is an error rather than "nothing
// saved yet".
func WithNotFound(fn func(error) bool) Option {
	return func(m *Manager) error {
		if fn == nil {
			return fmt.Errorf("core/signalsession: nil not-found predicate")
		}
		m.notFound = fn
		return nil
	}
}

// New validates the store and session id.
func New(store Store, sessionID string, opts ...Option) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("core/signalsession: nil store")
	}
	if err := validateToken(sessionID, "session id", 128); err != nil {
		return nil, err
	}
	m := &Manager{store: store, sessionID: sessionID}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// indexKey names the peer list. It deliberately sits outside the
// "sessions/<id>/signal/" prefix so no peer name can collide with it.
func (m *Manager) indexKey() string { return "sessions/" + m.sessionID + "/signal.index" }

// Peers returns every peer with a stored record, in the order it was first
// saved. A missing index means nothing has been saved yet.
//
// The index exists because a restore has to know which peers to load: the
// store is a key/value vault with no enumeration, and a client that cannot
// restore its ratchets loses every message a peer sends after a restart.
func (m *Manager) Peers(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.peers(ctx)
}

// peers reads the index. The caller holds mu.
func (m *Manager) peers(ctx context.Context) ([]string, error) {
	raw, err := m.store.Get(ctx, m.indexKey())
	if err != nil {
		if m.notFound != nil && m.notFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("core/signalsession: load peer index: %w", err)
	}
	var peers []string
	if err := json.Unmarshal(raw, &peers); err != nil {
		return nil, fmt.Errorf("core/signalsession: decode peer index: %w", err)
	}
	return peers, nil
}

// addPeer records peer in the index if it is not already there. The caller
// holds mu.
func (m *Manager) addPeer(ctx context.Context, peer string) error {
	peers, err := m.peers(ctx)
	if err != nil {
		return err
	}
	for _, known := range peers {
		if known == peer {
			return nil
		}
	}
	raw, err := json.Marshal(append(peers, peer))
	if err != nil {
		return fmt.Errorf("core/signalsession: encode peer index: %w", err)
	}
	if err := m.store.Put(ctx, m.indexKey(), raw); err != nil {
		return fmt.Errorf("core/signalsession: save peer index: %w", err)
	}
	return nil
}
