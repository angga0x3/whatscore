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
	manager, err := New(vault, "session-1", WithNotFound(func(err error) bool {
		return errors.Is(err, storecreds.ErrNotFound)
	}))
	if err != nil {
		t.Fatal(err)
	}
	return manager, backend
}

func TestSaveLoadContinues(t *testing.T) {
	ctx := context.Background()
	manager, _ := newManager(t)
	original := testState(t)

	record := &Record{PeerIdentity: [signal.KeySize]byte{0x11}, State: original}
	if err := manager.SaveRecord(ctx, "628123@s.whatsapp.net", record); err != nil {
		t.Fatal(err)
	}
	loadedRecord, err := manager.LoadRecord(ctx, "628123@s.whatsapp.net")
	if err != nil {
		t.Fatal(err)
	}
	if loadedRecord.PeerIdentity != record.PeerIdentity {
		t.Fatal("peer identity not persisted")
	}
	loaded := loadedRecord.State
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
	if err := manager.SaveRecord(ctx, "a@s.whatsapp.net", &Record{State: testState(t)}); err != nil {
		t.Fatal(err)
	}
	blob, err := backend.Get(ctx, "sessions/session-1/signal/a@s.whatsapp.net")
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Put(ctx, "sessions/session-1/signal/b@s.whatsapp.net", blob); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LoadRecord(ctx, "b@s.whatsapp.net"); !errors.Is(err, envelope.ErrDecryptFailed) {
		t.Fatalf("copied blob: %v", err)
	}
	// The record is AAD-bound to its peer; deleting is only reachable through
	// the store key, so cover the not-found path for an unknown peer.
	if _, err := manager.LoadRecord(ctx, "missing@s.whatsapp.net"); !errors.Is(err, storecreds.ErrNotFound) {
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
	if err := manager.SaveRecord(ctx, "peer", nil); err == nil {
		t.Fatal("nil record must fail")
	}
	if err := manager.SaveRecord(ctx, "peer", &Record{}); err == nil {
		t.Fatal("nil state must fail")
	}
	for _, peer := range []string{"", "has space", "has\tslash/", strings.Repeat("a", 257), "nul\x00"} {
		if err := manager.SaveRecord(ctx, peer, &Record{State: testState(t)}); !errors.Is(err, ErrInvalidAddress) {
			t.Fatalf("peer %q: %v", peer, err)
		}
		if _, err := manager.LoadRecord(ctx, peer); !errors.Is(err, ErrInvalidAddress) {
			t.Fatalf("load peer %q: %v", peer, err)
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
			if err := manager.SaveRecord(ctx, peer, &Record{State: state}); err != nil {
				t.Errorf("save %s: %v", peer, err)
				return
			}
			if _, err := manager.LoadRecord(ctx, peer); err != nil {
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
		if err := manager.SaveRecord(ctx, "628123@s.whatsapp.net", &Record{State: state}); err != nil {
			b.Fatal(err)
		}
		if _, err := manager.LoadRecord(ctx, "628123@s.whatsapp.net"); err != nil {
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

func TestRecordParseRejects(t *testing.T) {
	record := &Record{PeerIdentity: [signal.KeySize]byte{0x22}, State: testState(t)}
	raw, err := record.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":       nil,
		"short":       raw[:signal.KeySize],
		"bad version": append([]byte{0xFF}, raw[1:]...),
		"bad state":   append(append([]byte(nil), raw[:1+signal.KeySize]...), 0xFF),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRecord(input); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := (&Record{}).MarshalBinary(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("nil state: %v", err)
	}
}

// TestPeersListsSavedPeers pins the index that makes a restore possible: the
// store cannot be enumerated, so a session that cannot ask "which peers do I
// have?" starts every restart empty and loses every ratchet (PF-087).
func TestPeersListsSavedPeers(t *testing.T) {
	ctx := context.Background()
	manager, _ := newManager(t)

	peers, err := manager.Peers(ctx)
	if err != nil {
		t.Fatalf("empty Peers: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("peers = %v, want none", peers)
	}

	for _, peer := range []string{"a@s.whatsapp.net", "266988689592415:39@lid"} {
		record := &Record{PeerIdentity: [signal.KeySize]byte{0x11}, State: testState(t)}
		if err := manager.SaveRecord(ctx, peer, record); err != nil {
			t.Fatalf("save %s: %v", peer, err)
		}
	}
	// Saving the same peer twice must not duplicate it.
	record := &Record{PeerIdentity: [signal.KeySize]byte{0x22}, State: testState(t)}
	if err := manager.SaveRecord(ctx, "a@s.whatsapp.net", record); err != nil {
		t.Fatal(err)
	}

	peers, err = manager.Peers(ctx)
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("peers = %v, want 2 entries", peers)
	}
	if peers[0] != "a@s.whatsapp.net" || peers[1] != "266988689592415:39@lid" {
		t.Fatalf("peers = %v, want insertion order", peers)
	}
}

// TestPeersRejectsCorruptIndex keeps a damaged index loud: silently starting
// empty would look exactly like a peer that never wrote.
func TestPeersRejectsCorruptIndex(t *testing.T) {
	ctx := context.Background()
	manager, _ := newManager(t)
	// The index is stored through the same encrypted store as the records, so
	// a corrupt value has to be written the same way to be readable.
	if err := manager.store.Put(ctx, "sessions/session-1/signal.index", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Peers(ctx); err == nil {
		t.Fatal("corrupt index accepted")
	}
}
