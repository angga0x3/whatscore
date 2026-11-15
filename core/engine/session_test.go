package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/core/session"
	"github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// TestConnectorPerformsHandshake drives Engine.Connector over an in-memory
// pipe: the adapter must run the Noise handshake on an already-dialed raw
// connection and hand back a connection whose frames are encrypted.
func TestConnectorPerformsHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	crew, err := New(engineConfig(fs, newFakeDialer(func(context.Context, transport.FrameConn) error { return nil }), t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	raw, server := newPipePair()
	serverErr := make(chan error, 1)
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		secure, _, err := fs.handshake(ctx, server)
		if err != nil {
			serverErr <- fmt.Errorf("server handshake: %w", err)
			return
		}
		// Read the client's first post-handshake frame as ciphertext first:
		// a plaintext node here would mean the adapter returned the raw
		// connection.
		frame, err := server.ReadFrame(ctx)
		if err != nil {
			serverErr <- fmt.Errorf("server raw read: %w", err)
			return
		}
		if _, decodeErr := binary.NewCodec(nil).Decode(bytes.NewReader(frame)); decodeErr == nil {
			serverErr <- errors.New("client frame decodes as plaintext; it was not encrypted")
			return
		}
		secure.mu.Lock()
		plain, err := secure.readAEAD.Open(nil, frameNonce(secure.readSeq), frame, nil)
		secure.readSeq++
		secure.mu.Unlock()
		if err != nil {
			serverErr <- fmt.Errorf("server decrypt: %w", err)
			return
		}
		node, err := secure.codec.Decode(bytes.NewReader(plain))
		if err != nil {
			serverErr <- fmt.Errorf("server decode: %w", err)
			return
		}
		if node.Tag != "ping" || node.Attrs["id"] != "c-1" {
			serverErr <- fmt.Errorf("server decoded %#v", node)
			return
		}
		if err := secure.WriteNode(ctx, &binary.Node{Tag: "pong", Attrs: binary.Attrs{"id": "c-1"}}); err != nil {
			serverErr <- fmt.Errorf("server write: %w", err)
			return
		}
		// The client closes next; that close is the expected end.
		_, err = server.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			serverErr <- fmt.Errorf("server idle read: %w", err)
			return
		}
		serverErr <- nil
	}()

	var connector session.Connector = crew.Connector() //nolint:staticcheck // asserts the interface shape
	conn, err := connector.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("connector.Connect: %v", err)
	}
	if conn == raw {
		t.Fatal("connector returned the raw connection; no handshake happened")
	}
	if _, ok := conn.(interface{ CipherSuiteName() string }); !ok {
		t.Fatalf("connector returned %T, want an encrypted frame connection", conn)
	}

	node, err := binary.NewCodec(nil).Encode(&binary.Node{Tag: "ping", Attrs: binary.Attrs{"id": "c-1"}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := conn.WriteFrame(ctx, node); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	reply, err := conn.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	pong, err := binary.NewCodec(nil).Decode(bytes.NewReader(reply))
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if pong.Tag != "pong" || pong.Attrs["id"] != "c-1" {
		t.Fatalf("reply = %#v", pong)
	}

	// The wrapper owns the raw connection: closing it closes the pipe, which
	// also ends the server's idle read.
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := raw.ReadFrame(ctx); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("raw read after Close = %v, want transport.ErrClosed", err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("fake server: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("fake server never finished")
	}
	<-serverDone

	if _, err := connector.Connect(ctx, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Connect(nil) = %v, want ErrInvalidConfig", err)
	}
}

// TestConnectorRejectsUnknownRoot proves a handshake failure over an
// already-dialed connection wraps ErrAuthFailed and leaves no open connection.
func TestConnectorRejectsUnknownRoot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	cfg := engineConfig(fs, newFakeDialer(func(context.Context, transport.FrameConn) error { return nil }), t)
	cfg.RootPub = bytes.Repeat([]byte{0xAA}, 32)
	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	raw, server := newPipePair()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		// The client aborts after the certificate check; ignore the close.
		_, _ = serverHandshake(ctx, server, fs.eph, fs.static, fs.cert)
	}()

	if _, err := crew.Connector().Connect(ctx, raw); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Connect = %v, want ErrAuthFailed", err)
	}
	if _, err := raw.ReadFrame(ctx); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("raw read after a failed handshake = %v, want transport.ErrClosed", err)
	}
	<-serverDone
}

// TestConnectorDrivesSession is the composition-root shape: one dialer on the
// session, the engine's connector injected, no second dial path. The session
// connects, writes a frame through the encrypted connection, and receives the
// server's encrypted reply.
func TestConnectorDrivesSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	var handshakes atomic.Int32
	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		secure, _, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		handshakes.Add(1)
		node, err := secure.ReadNode(ctx)
		if err != nil {
			return fmt.Errorf("server read: %w", err)
		}
		if node.Tag != "ping" {
			return fmt.Errorf("server read unexpected node %q", node.Tag)
		}
		if err := secure.WriteNode(ctx, &binary.Node{Tag: "pong"}); err != nil {
			return fmt.Errorf("server write: %w", err)
		}
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})

	// The engine's own dialer is unused here: the session dials, the
	// connector only handshakes.
	crew, err := New(engineConfig(fs, newFakeDialer(func(context.Context, transport.FrameConn) error { return nil }), t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bus := events.NewBus()
	defer bus.Close()
	received := make(chan *binary.Node, 1)

	sess, err := session.New(session.Config{
		ID:        "bridge-test",
		Endpoint:  transport.Endpoint{URL: "ws://fake.invalid/ws"},
		Dialer:    dialer,
		Connector: crew.Connector(),
		FrameHandler: session.FrameHandlerFunc(func(_ context.Context, frame []byte) error {
			node, err := binary.NewCodec(nil).Decode(bytes.NewReader(frame))
			if err != nil {
				return err
			}
			received <- node
			return nil
		}),
		Bus: bus,
	})
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}

	if err := sess.Connect(ctx); err != nil {
		t.Fatalf("session.Connect: %v", err)
	}
	if state, err := sess.State(ctx); err != nil || state != session.StateConnected {
		t.Fatalf("State = (%v, %v), want CONNECTED", state, err)
	}

	ping, err := binary.NewCodec(nil).Encode(&binary.Node{Tag: "ping"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := sess.WriteFrame(ctx, ping); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case node := <-received:
		if node.Tag != "pong" {
			t.Fatalf("session received %#v, want pong", node)
		}
	case <-ctx.Done():
		t.Fatal("session never received the decrypted reply")
	}
	// The session dialed exactly once and the connector handshaked on that
	// same connection: no second dial path exists.
	if handshakes.Load() != 1 {
		t.Fatalf("server saw %d handshakes, want 1", handshakes.Load())
	}

	if err := sess.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	dialer.wait(ctx, t)
}
