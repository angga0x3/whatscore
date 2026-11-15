package client

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corecredentials "github.com/angga0x3/whatscore/core/credentials"
	"github.com/angga0x3/whatscore/core/events"
	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/core/session"
	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
	"github.com/angga0x3/whatscore/protocol/transport"
	storecreds "github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
)

type fakeConn struct {
	frames chan []byte
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeConn() *fakeConn {
	return &fakeConn{frames: make(chan []byte), writes: make(chan []byte, 8), closed: make(chan struct{})}
}

func (f *fakeConn) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case frame := <-f.frames:
		return frame, nil
	case <-f.closed:
		return nil, transport.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeConn) WriteFrame(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-f.closed:
		return transport.ErrClosed
	default:
	}
	f.writes <- append([]byte(nil), frame...)
	return nil
}

func (f *fakeConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

type fakeDialer struct {
	conn *fakeConn
	err  error
}

func (d *fakeDialer) Dial(context.Context, transport.Endpoint) (transport.FrameConn, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

func testClient(t *testing.T, opts ...Option) (*Client, *events.Bus) {
	t.Helper()
	bus := events.NewBus()
	all := append([]Option{WithDialer(&fakeDialer{conn: newFakeConn()}), WithBus(bus)}, opts...)
	c, err := New("session-1", all...)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	return c, bus
}

func waitEvent(t *testing.T, sub *events.Subscription, want events.Type) events.Event {
	t.Helper()
	select {
	case ev := <-sub.C:
		if ev.Type != want {
			t.Fatalf("event = %q, want %q", ev.Type, want)
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
		return events.Event{}
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty id: %v", err)
	}
	options := map[string]Option{
		"nil dialer":     WithDialer(nil),
		"nil bus":        WithBus(nil),
		"nil logger":     WithLogger(nil),
		"nil creds":      WithCredentials(nil),
		"nil reconnect":  WithReconnectPolicy(nil),
		"empty endpoint": WithEndpoint(transport.Endpoint{}),
		"nil connector":  WithConnector(nil),
		"nil handler":    WithFrameHandler(nil),
	}
	for name, opt := range options {
		t.Run(name, func(t *testing.T) {
			if _, err := New("s", opt); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("want ErrInvalidConfig, got %v", err)
			}
		})
	}
	c, err := New("s")
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if c.ID() != "s" {
		t.Fatalf("id = %q", c.ID())
	}
	if c.Credentials() != nil {
		t.Fatal("default client has credentials")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestConnectDisconnect(t *testing.T) {
	ctx := context.Background()
	c, _ := testClient(t)
	sub := c.Subscribe()
	defer sub.Close()

	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	ev := waitEvent(t, sub, events.TypeConnected)
	if ev.SessionID != "session-1" {
		t.Fatalf("session id = %q", ev.SessionID)
	}
	if state, err := c.State(ctx); err != nil || state != session.StateConnected {
		t.Fatalf("state = %v, %v", state, err)
	}

	if err := c.Disconnect(ctx); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	waitEvent(t, sub, events.TypeDisconnected)
	if state, err := c.State(ctx); err != nil || state != session.StateDisconnected {
		t.Fatalf("state = %v, %v", state, err)
	}
}

func TestConnectCanceled(t *testing.T) {
	c, _ := testClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Connect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestSendMessage(t *testing.T) {
	conn := newFakeConn()
	bus := events.NewBus()
	c, err := New("session-1", WithDialer(&fakeDialer{conn: conn}), WithBus(bus))
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

	id, err := c.SendMessage(ctx, Message{To: "628123@s.whatsapp.net", Text: "hello"})
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if len(id) != 20 {
		t.Fatalf("id = %q", id)
	}

	var frame []byte
	select {
	case frame = <-conn.writes:
	case <-time.After(2 * time.Second):
		t.Fatal("message frame was not written")
	}
	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	msg, err := stanza.ParseTextMessage(node)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msg.ID != id || msg.Text != "hello" || msg.To.String() != "628123@s.whatsapp.net" {
		t.Fatalf("message = %#v", msg)
	}
}

func TestSendMessageRequiresConnection(t *testing.T) {
	c, _ := testClient(t)
	if _, err := c.SendMessage(context.Background(), Message{To: "1@s.whatsapp.net", Text: "x"}); !errors.Is(err, session.ErrNotConnected) {
		t.Fatalf("want ErrNotConnected, got %v", err)
	}
}

func TestCloseOwnBus(t *testing.T) {
	c, err := New("s", WithDialer(&fakeDialer{conn: newFakeConn()}))
	if err != nil {
		t.Fatal(err)
	}
	sub := c.Subscribe()
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case _, ok := <-sub.C:
		if ok {
			t.Fatal("owned bus still delivers after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owned bus was not closed")
	}
}

func TestInjectedBusStaysOpen(t *testing.T) {
	bus := events.NewBus()
	c, err := New("s", WithDialer(&fakeDialer{conn: newFakeConn()}), WithBus(bus))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	sub := bus.Subscribe()
	bus.Publish(events.Event{Type: events.TypeConnected, SessionID: "other"})
	select {
	case ev := <-sub.C:
		if ev.SessionID != "other" {
			t.Fatalf("session id = %q", ev.SessionID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("injected bus was closed")
	}
	bus.Close()
}

func TestCredentialsAccessor(t *testing.T) {
	key, err := envelope.NewKey(bytes.Repeat([]byte{0x42}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := corecredentials.NewManager(mustVault(t, key))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := testClient(t, WithCredentials(manager))
	if c.Credentials() != manager {
		t.Fatal("credentials manager not attached")
	}
}

func mustVault(t *testing.T, key *envelope.Key) *storecreds.Vault {
	t.Helper()
	vault, err := storecreds.NewVault(storecreds.NewMemoryBackend(), key)
	if err != nil {
		t.Fatal(err)
	}
	return vault
}

type recordingConnector struct {
	called atomic.Bool
}

func (c *recordingConnector) Connect(_ context.Context, raw transport.FrameConn) (transport.FrameConn, error) {
	c.called.Store(true)
	return raw, nil
}

func TestConnectorAndFrameHandler(t *testing.T) {
	conn := newFakeConn()
	connector := &recordingConnector{}
	frames := make(chan []byte, 1)
	bus := events.NewBus()
	c, err := New("session-1",
		WithDialer(&fakeDialer{conn: conn}),
		WithBus(bus),
		WithConnector(connector),
		WithFrameHandler(session.FrameHandlerFunc(func(_ context.Context, frame []byte) error {
			frames <- append([]byte(nil), frame...)
			return nil
		})),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})

	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !connector.called.Load() {
		t.Fatal("connector was not called")
	}
	conn.frames <- []byte("frame")
	select {
	case got := <-frames:
		if string(got) != "frame" {
			t.Fatalf("frame = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frame handler was not called")
	}
}

func TestConcurrentStateQueries(t *testing.T) {
	ctx := context.Background()
	c, _ := testClient(t)
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.State(ctx); err != nil {
				t.Errorf("state: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestInboundMessageEvent(t *testing.T) {
	conn := newFakeConn()
	bus := events.NewBus()
	c, err := New("session-1", WithDialer(&fakeDialer{conn: conn}), WithBus(bus))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	sub := c.Subscribe()
	defer sub.Close()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, sub, events.TypeConnected)

	frame, err := binary.NewCodec(nil).Encode(&binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id": "IN1", "type": "text", "from": "628123@s.whatsapp.net", "t": "1700000000",
		},
		Children: []binary.Node{{Tag: "body", Bytes: []byte("halo")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.frames <- frame

	ev := waitEvent(t, sub, events.TypeMessage)
	if ev.Message == nil {
		t.Fatalf("event = %#v", ev)
	}
	if ev.Message.ID != "IN1" || ev.Message.Chat != "628123@s.whatsapp.net" ||
		ev.Message.Text != "halo" || ev.Message.Direction != events.DirectionIncoming {
		t.Fatalf("message = %#v", ev.Message)
	}
}

func TestInboundRunsCustomHandlerToo(t *testing.T) {
	conn := newFakeConn()
	bus := events.NewBus()
	frames := make(chan []byte, 1)
	c, err := New("session-1",
		WithDialer(&fakeDialer{conn: conn}),
		WithBus(bus),
		WithFrameHandler(session.FrameHandlerFunc(func(_ context.Context, frame []byte) error {
			frames <- append([]byte(nil), frame...)
			return nil
		})),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	sub := c.Subscribe()
	defer sub.Close()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, sub, events.TypeConnected)

	frame, err := binary.NewCodec(nil).Encode(&binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id": "IN2", "type": "text", "from": "1@s.whatsapp.net",
		},
		Children: []binary.Node{{Tag: "body", Bytes: []byte("x")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.frames <- frame

	waitEvent(t, sub, events.TypeMessage)
	select {
	case got := <-frames:
		if len(got) == 0 {
			t.Fatal("custom handler received an empty frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("custom handler was not called")
	}
}

func TestSendReceipt(t *testing.T) {
	conn := newFakeConn()
	bus := events.NewBus()
	c, err := New("session-1", WithDialer(&fakeDialer{conn: conn}), WithBus(bus))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.SendReceipt(context.Background(), "628123@s.whatsapp.net", "MSG1", "read"); err != nil {
		t.Fatalf("SendReceipt: %v", err)
	}
	var frame []byte
	select {
	case frame = <-conn.writes:
	case <-time.After(2 * time.Second):
		t.Fatal("receipt frame was not written")
	}
	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := stanza.ParseReceipt(node)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ID != "MSG1" || receipt.Type != "read" {
		t.Fatalf("receipt = %#v", receipt)
	}
}

func TestSignalSendWiring(t *testing.T) {
	conn := newFakeConn()
	bus := events.NewBus()
	c, err := New("session-1", WithDialer(&fakeDialer{conn: conn}), WithBus(bus))
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

	root := signal.RootKey{0x33}
	chain := signal.ChainKey{0x44}
	ratchet, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peerState, err := signal.NewInitiator(root, ratchet.Public, chain)
	if err != nil {
		t.Fatal(err)
	}
	identity := [32]byte{0x11}
	c.SetSignalIdentity(identity)
	peer := "628123@s.whatsapp.net"
	if err := c.SetSignalPeer(peer, &coremessaging.PeerSession{PeerIdentity: [32]byte{0x22}, State: peerState}); err != nil {
		t.Fatal(err)
	}

	id, state, err := c.SendEncryptedMessage(ctx, peer, "halo")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if id == "" || state == nil {
		t.Fatalf("id = %q", id)
	}
	select {
	case frame := <-conn.writes:
		node, err := binary.NewCodec(nil).Decode(bytes.NewReader(frame))
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := stanza.ParseEncryptedText(node)
		if err != nil {
			t.Fatal(err)
		}
		if encrypted.Carrier != stanza.CarrierMsg || encrypted.ID != id {
			t.Fatalf("envelope = %#v", encrypted)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("encrypted frame was not written")
	}
}

func TestInboundEncryptedEvent(t *testing.T) {
	conn := newFakeConn()
	bus := events.NewBus()
	c, err := New("session-1", WithDialer(&fakeDialer{conn: conn}), WithBus(bus))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	sub := c.Subscribe()
	defer sub.Close()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, sub, events.TypeConnected)

	aliceID, bobID := [32]byte{0x11}, [32]byte{0x22}
	root := signal.RootKey{0x33}
	chain := signal.ChainKey{0x44}
	ratchet, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	alice, err := signal.NewInitiator(root, ratchet.Public, chain)
	if err != nil {
		t.Fatal(err)
	}
	bob := signal.NewResponder(root, ratchet, chain)

	peer := "628123@s.whatsapp.net"
	c.SetReceiveSignalIdentity(bobID)
	if err := c.SetReceiveSignalPeer(peer, &coremessaging.PeerSession{PeerIdentity: aliceID, State: bob}); err != nil {
		t.Fatal(err)
	}

	payload, err := stanza.EncodeTextMessage("masuk")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := alice.Encrypt(payload, aliceID, bobID)
	if err != nil {
		t.Fatal(err)
	}
	node, err := stanza.BuildEncryptedText(stanza.EncryptedText{
		ID: "IN9", To: stanza.JID{User: "628123", Server: stanza.UserServer},
		Carrier: stanza.CarrierMsg, Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := binary.NewCodec(nil).Encode(node)
	if err != nil {
		t.Fatal(err)
	}
	conn.frames <- frame

	ev := waitEvent(t, sub, events.TypeMessage)
	if ev.Message == nil || ev.Message.ID != "IN9" || ev.Message.Text != "masuk" {
		t.Fatalf("message = %#v", ev.Message)
	}
}
