package signalsession

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/angga0x3/whatscore/protocol/signal"
	storecreds "github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
)

func testState(t *testing.T) *signal.State {
	t.Helper()
	pair, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	root := signal.RootKey{1}
	chain := signal.ChainKey{2}
	state := signal.NewResponder(root, pair, chain)
	if _, _, err := state.NextOutbound(); err != nil {
		t.Fatal(err)
	}
	return state
}

func newManager(t *testing.T) (*Manager, *storecreds.MemoryBackend) {
	t.Helper()
	key, err := envelope.NewKey(bytes.Repeat([]byte{0x42}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	backend := storecreds.NewMemoryBackend()
	vault, err := storecreds.NewVault(backend, key)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(vault, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	return manager, backend
}

func TestSaveLoadContinues(t *testing.T) {
	ctx := context.Background()
	manager, _ := newManager(t)
	original := testState(t)

	if err := manager.Save(ctx, "628123@s.whatsapp.net", original); err != nil {
		t.Fatal(err)
	}
	loaded, err := manager.Load(ctx, "628123@s.whatsapp.net")
	if err != nil {
		t.Fatal(err)
	}
	first, err := original.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	second, err := loaded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("loaded state differs")
	}

	originalHeader, originalKeys, err := original.NextOutbound()
	if err != nil {
		t.Fatal(err)
	}
	loadedHeader, loadedKeys, err := loaded.NextOutbound()
	if err != nil {
		t.Fatal(err)
	}
	if originalHeader != loadedHeader || originalKeys != loadedKeys {
		t.Fatal("loaded state does not continue the chain")
	}
}

func TestPeerBindingAndDelete(t *testing.T) {
	ctx := context.Background()
	manager, backend := newManager(t)
	if err := manager.Save(ctx, "a@s.whatsapp.net", testState(t)); err != nil {
		t.Fatal(err)
	}
	blob, err := backend.Get(ctx, "sessions/session-1/signal/a@s.whatsapp.net")
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Put(ctx, "sessions/session-1/signal/b@s.whatsapp.net", blob); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Load(ctx, "b@s.whatsapp.net"); !errors.Is(err, envelope.ErrDecryptFailed) {
		t.Fatalf("copied blob: %v", err)
	}

	if err := manager.Delete(ctx, "a@s.whatsapp.net"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Load(ctx, "a@s.whatsapp.net"); !errors.Is(err, storecreds.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	if _, err := manager.Load(ctx, "missing@s.whatsapp.net"); !errors.Is(err, storecreds.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := New(nil, "s"); err == nil {
		t.Fatal("nil store must fail")
	}
	manager, _ := newManager(t)
	if _, err := New(manager.store, ""); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("empty session: %v", err)
	}
	if _, err := New(manager.store, "bad/id"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("bad session: %v", err)
	}
	if err := manager.Save(ctx, "peer", nil); err == nil {
		t.Fatal("nil state must fail")
	}
	for _, peer := range []string{"", "has space", "has\tslash/", strings.Repeat("a", 257), "nul\x00"} {
		if err := manager.Save(ctx, peer, testState(t)); !errors.Is(err, ErrInvalidAddress) {
			t.Fatalf("peer %q: %v", peer, err)
		}
		if _, err := manager.Load(ctx, peer); !errors.Is(err, ErrInvalidAddress) {
			t.Fatalf("load peer %q: %v", peer, err)
		}
		if err := manager.Delete(ctx, peer); !errors.Is(err, ErrInvalidAddress) {
			t.Fatalf("delete peer %q: %v", peer, err)
		}
	}
}

func TestConcurrentPeers(t *testing.T) {
	ctx := context.Background()
	manager, _ := newManager(t)
	state := testState(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			peer := fmt.Sprintf("peer%d@s.whatsapp.net", i)
			if err := manager.Save(ctx, peer, state); err != nil {
				t.Errorf("save %s: %v", peer, err)
				return
			}
			if _, err := manager.Load(ctx, peer); err != nil {
				t.Errorf("load %s: %v", peer, err)
			}
		}(i)
	}
	wg.Wait()
}

func BenchmarkSaveLoad(b *testing.B) {
	key, err := envelope.NewKey(bytes.Repeat([]byte{0x42}, envelope.KeySize))
	if err != nil {
		b.Fatal(err)
	}
	vault, err := storecreds.NewVault(storecreds.NewMemoryBackend(), key)
	if err != nil {
		b.Fatal(err)
	}
	manager, err := New(vault, "session-1")
	if err != nil {
		b.Fatal(err)
	}
	state := newBenchState(b)
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := manager.Save(ctx, "628123@s.whatsapp.net", state); err != nil {
			b.Fatal(err)
		}
		if _, err := manager.Load(ctx, "628123@s.whatsapp.net"); err != nil {
			b.Fatal(err)
		}
	}
}

func newBenchState(b *testing.B) *signal.State {
	b.Helper()
	pair, err := signal.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	state := signal.NewResponder(signal.RootKey{1}, pair, signal.ChainKey{2})
	if _, _, err := state.NextOutbound(); err != nil {
		b.Fatal(err)
	}
	return state
}
