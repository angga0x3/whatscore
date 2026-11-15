package prekeys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/angga0x3/whatscore/protocol/signal"
	storecreds "github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
)

type memoryStore struct {
	mu      sync.Mutex
	records map[string][]byte
}

func newMemoryStore() *memoryStore { return &memoryStore{records: map[string][]byte{}} }

func (m *memoryStore) Put(_ context.Context, key string, blob []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[key] = append([]byte(nil), blob...)
	return nil
}

func (m *memoryStore) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	blob, ok := m.records[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), blob...), nil
}

func (m *memoryStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, key)
	return nil
}

func testIdentity(t *testing.T) (signal.KeyPair, signal.Signer) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512(private.Seed())
	var pair signal.KeyPair
	copy(pair.Private[:], digest[:32])
	pair.Private[0] &= 248
	pair.Private[31] &= 127
	pair.Private[31] |= 64
	pub, err := curve25519.X25519(pair.Private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pair.Public[:], pub)
	return pair, signal.XEdDSASigner{Private: pair.Private}
}

func newManager(t *testing.T, store Store) *Manager {
	t.Helper()
	identity, signer := testIdentity(t)
	manager, err := New(context.Background(), store, "session-1", identity, signer, Config{
		SignedPreKeyID: 7,
		OneTimeCount:   4,
		FirstOneTimeID: 100,
		RotateAfter:    time.Hour,
		Now:            func() time.Time { return time.Unix(1000, 0) },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return manager
}

func TestGenerateAndLoad(t *testing.T) {
	store := newMemoryStore()
	manager := newManager(t, store)

	signed, err := manager.SignedPreKey(7)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := testIdentity(t)
	if err := signed.Verify(manager.Identity().Public); err != nil {
		t.Fatalf("signature: %v", err)
	}
	_ = identity
	if manager.OneTimeCount() != 4 {
		t.Fatalf("one-time count = %d", manager.OneTimeCount())
	}

	bundle := manager.Bundle(true)
	if bundle.SignedPreKeyID != 7 || bundle.OneTimePreKeyID != 100 || bundle.OneTimePreKey == nil {
		t.Fatalf("bundle = %#v", bundle)
	}
	if err := signal.ParsePreKeyBundle(bundle); err != nil {
		t.Fatalf("bundle validation: %v", err)
	}
	if manager.Bundle(false).OneTimePreKey != nil {
		t.Fatal("one-time prekey leaked into the no-one-time bundle")
	}

	// A reopened manager reads the same material back.
	identity2 := manager.Identity()
	reopened, err := New(context.Background(), store, "session-1", identity2, signal.XEdDSASigner{}, Config{
		SignedPreKeyID: 7, OneTimeCount: 4, FirstOneTimeID: 100,
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	again, err := reopened.SignedPreKey(7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Pair.Public[:], signed.Pair.Public[:]) || !bytes.Equal(again.Signature, signed.Signature) {
		t.Fatal("reopened signed prekey differs")
	}
	if reopened.OneTimeCount() != 4 {
		t.Fatalf("reopened one-time count = %d", reopened.OneTimeCount())
	}
}

func TestConsumeAndReplenish(t *testing.T) {
	ctx := context.Background()
	manager := newManager(t, newMemoryStore())

	prekey, err := manager.OneTimePreKey(100)
	if err != nil || prekey == nil {
		t.Fatalf("lookup: %v", err)
	}
	if err := manager.ConsumeOneTimePreKey(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.OneTimePreKey(100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed key still present: %v", err)
	}
	if err := manager.ConsumeOneTimePreKey(ctx, 100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double consume: %v", err)
	}

	if err := manager.Replenish(ctx, 6); err != nil {
		t.Fatal(err)
	}
	if manager.OneTimeCount() != 6 {
		t.Fatalf("count = %d", manager.OneTimeCount())
	}
	// Replenished ids must not collide with consumed ones.
	bundle := manager.Bundle(true)
	if bundle.OneTimePreKeyID == 100 {
		t.Fatalf("replenished bundle reused id 100: %#v", bundle)
	}
}

func TestRotation(t *testing.T) {
	store := newMemoryStore()
	now := time.Unix(1000, 0)
	identity, signer := testIdentity(t)
	manager, err := New(context.Background(), store, "s1", identity, signer, Config{
		SignedPreKeyID: 3, OneTimeCount: 2, FirstOneTimeID: 1,
		RotateAfter: time.Hour,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := manager.SignedPreKey(3)
	if manager.NeedRotation() {
		t.Fatal("fresh key must not need rotation")
	}
	now = now.Add(2 * time.Hour)
	if !manager.NeedRotation() {
		t.Fatal("stale key must need rotation")
	}
	if err := manager.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, _ := manager.SignedPreKey(3)
	if bytes.Equal(first.Pair.Public[:], second.Pair.Public[:]) {
		t.Fatal("rotation did not change the key")
	}
	if manager.NeedRotation() {
		t.Fatal("rotated key still stale")
	}
}

func TestValidation(t *testing.T) {
	store := newMemoryStore()
	identity, signer := testIdentity(t)
	ctx := context.Background()

	cases := map[string]struct {
		store  Store
		id     string
		signer signal.Signer
		cfg    Config
	}{
		"nil store":    {nil, "s", signer, Config{}},
		"empty id":     {store, "", signer, Config{}},
		"bad id":       {store, "a/b", signer, Config{}},
		"nil signer":   {store, "s", nil, Config{}},
		"negative oto": {store, "s", signer, Config{OneTimeCount: -1}},
		"too many oto": {store, "s", signer, Config{OneTimeCount: maxOneTime + 1}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(ctx, tc.store, tc.id, identity, tc.signer, tc.cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("want ErrInvalidConfig, got %v", err)
			}
		})
	}

	manager := newManager(t, store)
	if _, err := manager.SignedPreKey(99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong signed id: %v", err)
	}
	if _, err := manager.OneTimePreKey(999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong one-time id: %v", err)
	}
	if err := manager.Replenish(ctx, maxOneTime+1); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("replenish limit: %v", err)
	}
	if _, err := unmarshal([]byte{0xFF}); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("bad record: %v", err)
	}
	raw := marshal(manager.state)
	if _, err := unmarshal(raw[:len(raw)-1]); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("truncated record: %v", err)
	}
	if _, err := unmarshal(append(append([]byte(nil), raw...), 0x00)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("trailing bytes: %v", err)
	}
}

func TestNotFoundMapping(t *testing.T) {
	backend := storecreds.NewMemoryBackend()
	key, err := envelope.NewKey(bytes.Repeat([]byte{0x42}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	vault, err := storecreds.NewVault(backend, key)
	if err != nil {
		t.Fatal(err)
	}
	identity, signer := testIdentity(t)
	// The vault reports its own not-found sentinel; the caller maps it.
	manager, err := New(context.Background(), vault, "s1", identity, signer, Config{
		SignedPreKeyID: 1, OneTimeCount: 1, FirstOneTimeID: 5,
		NotFound: func(err error) bool { return errors.Is(err, storecreds.ErrNotFound) },
	})
	if err != nil {
		t.Fatalf("vault-backed new: %v", err)
	}
	if manager.OneTimeCount() != 1 {
		t.Fatalf("count = %d", manager.OneTimeCount())
	}
}

func TestConcurrentAccess(t *testing.T) {
	manager := newManager(t, newMemoryStore())
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.Bundle(true)
			_, _ = manager.SignedPreKey(7)
			_, _ = manager.OneTimePreKey(100)
			_ = manager.NeedRotation()
			_ = manager.OneTimeCount()
		}()
	}
	wg.Wait()
}

func BenchmarkBundle(b *testing.B) {
	store := newMemoryStore()
	identity, signer := testIdentityBench(b)
	manager, err := New(context.Background(), store, "bench", identity, signer, Config{
		SignedPreKeyID: 1, OneTimeCount: 8, FirstOneTimeID: 1,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = manager.Bundle(true)
	}
}

func testIdentityBench(b *testing.B) (signal.KeyPair, signal.Signer) {
	b.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	digest := sha512.Sum512(private.Seed())
	var pair signal.KeyPair
	copy(pair.Private[:], digest[:32])
	pair.Private[0] &= 248
	pair.Private[31] &= 127
	pair.Private[31] |= 64
	pub, err := curve25519.X25519(pair.Private[:], curve25519.Basepoint)
	if err != nil {
		b.Fatal(err)
	}
	copy(pair.Public[:], pub)
	return pair, signal.XEdDSASigner{Private: pair.Private}
}
