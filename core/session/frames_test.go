package session

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/transport"
)

type recordingConnector struct {
	called  atomic.Bool
	err     error
	nilConn bool
}

func (c *recordingConnector) Connect(_ context.Context, raw transport.FrameConn) (transport.FrameConn, error) {
	c.called.Store(true)
	if c.err != nil {
		return nil, c.err
	}
	if c.nilConn {
		return nil, nil
	}
	return raw, nil
}

func newFrameHarness(t *testing.T, dialer transport.Dialer, connector Connector, handler FrameHandler) (*Session, *events.Subscription) {
	t.Helper()
	bus := events.NewBus()
	s, err := New(Config{
		ID:           "frame-session",
		Dialer:       dialer,
		Bus:          bus,
		Connector:    connector,
		FrameHandler: handler,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sub := bus.Subscribe()
	t.Cleanup(func() {
		ctx := testContext(t)
		if err := s.Stop(ctx); err != nil {
			t.Errorf("Stop: %v", err)
		}
		bus.Close()
	})
	return s, sub
}

func TestConnectorAndFrameHandler(t *testing.T) {
	conn := newFakeConn()
	dialer := &scriptedDialer{outcomes: []dialOutcome{{conn: conn}}}
	connector := &recordingConnector{}
	frames := make(chan []byte, 4)
	s, sub := newFrameHarness(t, dialer, connector, FrameHandlerFunc(func(_ context.Context, frame []byte) error {
		frames <- append([]byte(nil), frame...)
		return nil
	}))

	ctx := testContext(t)
	if err := s.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !connector.called.Load() {
		t.Fatal("connector was not called")
	}
	nextEvent(t, sub, events.TypeConnected)

	conn.frames <- []byte("first")
	conn.frames <- []byte("second")
	for _, want := range []string{"first", "second"} {
		select {
		case frame := <-frames:
			if string(frame) != want {
				t.Fatalf("frame = %q, want %q", frame, want)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func TestFrameHandlerErrorDropsConnection(t *testing.T) {
	conn := newFakeConn()
	dialer := &scriptedDialer{outcomes: []dialOutcome{{conn: conn}}}
	handlerErr := errors.New("bad frame")
	s, sub := newFrameHarness(t, dialer, nil, FrameHandlerFunc(func(context.Context, []byte) error {
		return handlerErr
	}))

	if err := s.Connect(testContext(t)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	nextEvent(t, sub, events.TypeConnected)
	conn.frames <- []byte("poison")

	ev := nextEvent(t, sub, events.TypeDisconnected)
	if !errors.Is(ev.Disconnected.Reason, handlerErr) {
		t.Fatalf("disconnect reason = %v", ev.Disconnected.Reason)
	}
	nextEvent(t, sub, events.TypeError)
	requireState(t, s, StateError)
}

func TestConnectorErrorFailsDial(t *testing.T) {
	conn := newFakeConn()
	connector := &recordingConnector{err: errBoom}
	dialer := &scriptedDialer{outcomes: []dialOutcome{{conn: conn}}}
	s, sub := newFrameHarness(t, dialer, connector, nil)

	if err := s.Connect(testContext(t)); !errors.Is(err, errBoom) {
		t.Fatalf("want connector error, got %v", err)
	}
	nextEvent(t, sub, events.TypeError)
	requireState(t, s, StateError)
	select {
	case <-conn.closed:
	case <-testContext(t).Done():
		t.Fatal("raw connection was not closed after connector error")
	}
}

func TestConnectorNilConnectionFailsDial(t *testing.T) {
	conn := newFakeConn()
	connector := &recordingConnector{nilConn: true}
	dialer := &scriptedDialer{outcomes: []dialOutcome{{conn: conn}}}
	s, sub := newFrameHarness(t, dialer, connector, nil)

	if err := s.Connect(testContext(t)); err == nil {
		t.Fatal("nil connector result must fail")
	}
	nextEvent(t, sub, events.TypeError)
	requireState(t, s, StateError)
	select {
	case <-conn.closed:
	case <-testContext(t).Done():
		t.Fatal("raw connection was not closed")
	}
}
