package client

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

type memorySessions struct {
	records map[string]*PeerRecord
	err     error
}

func (m *memorySessions) LoadRecord(_ context.Context, peer string) (*PeerRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	record, ok := m.records[peer]
	if !ok {
		return nil, errors.New("not found")
	}
	return record, nil
}

func (m *memorySessions) SaveRecord(_ context.Context, peer string, record *PeerRecord) error {
	if m.err != nil {
		return m.err
	}
	m.records[peer] = record
	return nil
}

func encryptedPair(t *testing.T) (alice, bob *signal.State, aliceID, bobID [32]byte) {
	t.Helper()
	aliceID, bobID = [32]byte{0x11}, [32]byte{0x22}
	root := signal.RootKey{0x33}
	chain := signal.ChainKey{0x44}
	ratchet, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob = signal.NewResponder(root, ratchet, chain)
	alice, err = signal.NewInitiator(root, ratchet.Public, chain)
	if err != nil {
		t.Fatal(err)
	}
	return alice, bob, aliceID, bobID
}

func TestSendEncryptedPersists(t *testing.T) {
	conn := newFakeConn()
	bus := events.NewBus()
	store := &memorySessions{records: make(map[string]*PeerRecord)}
	c, err := New("session-1", WithDialer(&fakeDialer{conn: conn}), WithBus(bus), WithSessionStore(store))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}

	alice, _, aliceID, bobID := encryptedPair(t)
	peer := "628123@s.whatsapp.net"
	record := &PeerRecord{PeerIdentity: bobID, State: alice}
	store.records[peer] = record
	c.SetSignalIdentity(aliceID)

	id, err := c.SendEncrypted(ctx, Message{To: peer, Text: "halo"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if id == "" {
		t.Fatal("empty id")
	}
	if store.records[peer] == nil {
		t.Fatal("session not persisted")
	}

	// The persisted state must have advanced: the same session cannot produce
	// the identical ciphertext twice.
	before, err := store.records[peer].State.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SendEncrypted(ctx, Message{To: peer, Text: "lagi"}); err != nil {
		t.Fatalf("second send: %v", err)
	}
	after, err := store.records[peer].State.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("ratchet state did not advance")
	}
}

func TestSendEncryptedCarrierChoice(t *testing.T) {
	conn := newFakeConn()
	bus := events.NewBus()
	store := &memorySessions{records: make(map[string]*PeerRecord)}
	c, err := New("session-1", WithDialer(&fakeDialer{conn: conn}), WithBus(bus), WithSessionStore(store))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	c.SetSignalIdentity([32]byte{0x11})

	peer := "628123@s.whatsapp.net"
	// No stored session and no bundle source: typed error, nothing sent.
	if _, err := c.SendEncrypted(ctx, Message{To: peer, Text: "x"}); !errors.Is(err, coremessaging.ErrNoSession) {
		t.Fatalf("want ErrNoSession, got %v", err)
	}
	select {
	case frame := <-conn.writes:
		t.Fatalf("unexpected write: %x", frame)
	case <-time.After(100 * time.Millisecond):
	}

	// A stored session uses the msg carrier.
	alice, _, aliceID, bobID := encryptedPair(t)
	store.records[peer] = &PeerRecord{PeerIdentity: bobID, State: alice}
	c.SetSignalIdentity(aliceID)
	if _, err := c.SendEncrypted(ctx, Message{To: peer, Text: "x"}); err != nil {
		t.Fatal(err)
	}
	frame := <-conn.writes
	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	// ParseEncryptedText reads the inbound shape, which stamps "from".
	node.Attrs["from"] = peer
	envelope, err := stanza.ParseEncryptedText(node)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Carrier != stanza.CarrierMsg {
		t.Fatalf("carrier = %q", envelope.Carrier)
	}
}

func TestSendEncryptedErrors(t *testing.T) {
	store := &memorySessions{records: map[string]*PeerRecord{}, err: errors.New("store down")}
	bus := events.NewBus()
	c, err := New("session-1", WithDialer(&fakeDialer{conn: newFakeConn()}), WithBus(bus), WithSessionStore(store))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	if _, err := c.SendEncrypted(context.Background(), Message{To: "1@s.whatsapp.net", Text: "x"}); !errors.Is(err, coremessaging.ErrNoSession) {
		t.Fatalf("store error should look like no session, got %v", err)
	}

	plain, err := New("s2", WithDialer(&fakeDialer{conn: newFakeConn()}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.SendEncrypted(context.Background(), Message{To: "1@s.whatsapp.net"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
	if err := plain.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
