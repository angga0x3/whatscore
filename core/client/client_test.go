package client

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corecredentials "github.com/angga0x3/whatscore/core/credentials"
	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/core/session"
	"github.com/angga0x3/whatscore/protocol/transport"
	storecreds "github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
)

type fakeConn struct {
	closed chan struct{}
	once   sync.Once
}

func newFakeConn() *fakeConn { return &fakeConn{closed: make(chan struct{})} }

func (f *fakeConn) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case <-f.closed:
		return nil, transport.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeConn) WriteFrame(ctx context.Context, _ []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-f.closed:
		return transport.ErrClosed
	default:
		return nil
	}
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

func TestSendMessageNotImplemented(t *testing.T) {
	c, _ := testClient(t)
	id, err := c.SendMessage(context.Background(), NewTextMessage("hello"))
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("want ErrNotImplemented, got %v", err)
	}
	if id != "" {
		t.Fatalf("id = %q", id)
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
