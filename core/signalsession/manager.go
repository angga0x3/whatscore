// Package signalsession persists per-peer Signal ratchet state through an
// encrypted store. The manager is stateless; the store owns concurrency.
package signalsession

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/angga0x3/whatscore/protocol/signal"
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

// Save encodes and stores the state for peer.
func (m *Manager) Save(ctx context.Context, peer string, state *signal.State) error {
	if state == nil {
		return fmt.Errorf("core/signalsession: nil state")
	}
	key, err := m.key(peer)
	if err != nil {
		return err
	}
	raw, err := state.MarshalBinary()
	if err != nil {
		return fmt.Errorf("core/signalsession: encode %q: %w", peer, err)
	}
	if err := m.store.Put(ctx, key, raw); err != nil {
		return fmt.Errorf("core/signalsession: save %q: %w", peer, err)
	}
	return nil
}

// Load reads and decodes the state for peer.
func (m *Manager) Load(ctx context.Context, peer string) (*signal.State, error) {
	key, err := m.key(peer)
	if err != nil {
		return nil, err
	}
	raw, err := m.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	state, err := signal.ParseState(raw)
	if err != nil {
		return nil, fmt.Errorf("core/signalsession: decode %q: %w", peer, err)
	}
	return state, nil
}

// Delete removes the state for peer.
func (m *Manager) Delete(ctx context.Context, peer string) error {
	key, err := m.key(peer)
	if err != nil {
		return err
	}
	if err := m.store.Delete(ctx, key); err != nil {
		return fmt.Errorf("core/signalsession: delete %q: %w", peer, err)
	}
	return nil
}

func (m *Manager) key(peer string) (string, error) {
	if err := validateToken(peer, "peer", 256); err != nil {
		return "", err
	}
	return "sessions/" + m.sessionID + "/signal/" + peer, nil
}

func validateToken(value, field string, limit int) error {
	if value == "" {
		return fmt.Errorf("%w: empty %s", ErrInvalidAddress, field)
	}
	if len(value) > limit {
		return fmt.Errorf("%w: %s longer than %d bytes", ErrInvalidAddress, field, limit)
	}
	if strings.ContainsAny(value, " \t\r\n/") {
		return fmt.Errorf("%w: %s contains a separator or whitespace", ErrInvalidAddress, field)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return fmt.Errorf("%w: %s contains non-printable bytes", ErrInvalidAddress, field)
		}
	}
	return nil
}
