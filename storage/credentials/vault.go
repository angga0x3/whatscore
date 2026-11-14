// Package credentials stores engine credential blobs through an envelope
// key. Backends only see ciphertext; the record key is bound as AAD.
package credentials

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/angga0x3/whatscore/storage/envelope"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("credentials: not found")

// Backend persists opaque blobs keyed by record name.
type Backend interface {
	Put(ctx context.Context, key string, blob []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

// Vault encrypts and authenticates blobs before handing them to a Backend.
type Vault struct {
	backend Backend
	key     *envelope.Key
}

// NewVault wires a backend to an encryption key.
func NewVault(backend Backend, key *envelope.Key) (*Vault, error) {
	if backend == nil {
		return nil, fmt.Errorf("credentials: nil backend")
	}
	if key == nil {
		return nil, fmt.Errorf("credentials: nil key")
	}
	return &Vault{backend: backend, key: key}, nil
}

// Put seals plaintext under key and stores it.
func (v *Vault) Put(ctx context.Context, key string, plaintext []byte) error {
	if err := validateKey(key); err != nil {
		return err
	}
	sealed, err := v.key.Seal(plaintext, []byte(key))
	if err != nil {
		return fmt.Errorf("credentials: seal %q: %w", key, err)
	}
	if err := v.backend.Put(ctx, key, sealed); err != nil {
		return fmt.Errorf("credentials: put %q: %w", key, err)
	}
	return nil
}

// Get loads and opens the record for key.
func (v *Vault) Get(ctx context.Context, key string) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	sealed, err := v.backend.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	plaintext, err := v.key.Open(sealed, []byte(key))
	if err != nil {
		return nil, fmt.Errorf("credentials: open %q: %w", key, err)
	}
	return plaintext, nil
}

// Delete removes the record for key. Missing records are not an error.
func (v *Vault) Delete(ctx context.Context, key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := v.backend.Delete(ctx, key); err != nil {
		return fmt.Errorf("credentials: delete %q: %w", key, err)
	}
	return nil
}

func validateKey(key string) error {
	if key == "" {
		return fmt.Errorf("credentials: empty key")
	}
	if len(key) > 512 {
		return fmt.Errorf("credentials: key longer than 512 bytes")
	}
	return nil
}

// MemoryBackend is a concurrency-safe in-memory Backend for tests and the
// future SDK default.
type MemoryBackend struct {
	mu      sync.RWMutex
	records map[string][]byte
}

// NewMemoryBackend returns an empty MemoryBackend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{records: make(map[string][]byte)}
}

// Put stores a copy of blob.
func (m *MemoryBackend) Put(_ context.Context, key string, blob []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[key] = append([]byte(nil), blob...)
	return nil
}

// Get returns a copy of the stored blob.
func (m *MemoryBackend) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	blob, ok := m.records[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return append([]byte(nil), blob...), nil
}

// Delete removes a record.
func (m *MemoryBackend) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, key)
	return nil
}
