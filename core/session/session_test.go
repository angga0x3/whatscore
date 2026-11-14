package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/transport"
)

var (
	errBoom   = errors.New("boom")
	errDrop   = errors.New("connection dropped")
	errNoPlan = errors.New("dialer script exhausted")
)

// testContext bounds waits without sleeping; every blocking assertion selects
// on a channel or context instead.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newHarness(t *testing.T, dialer transport.Dialer, policy transport.ReconnectPolicy) (*Session, *events.Subscription) {
	t.Helper()

	bus := events.NewBus()
	s, err := New(Config{
		ID:        "test-session",
		Dialer:    dialer,
		Reconnect: policy,
		Bus:       bus,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sub := bus.Subscribe()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.Stop(ctx); err != nil {
			t.Errorf("cleanup Stop: %v", err)
		}
		bus.Close()
	})
	return s, sub
}

func nextEvent(t *testing.T, sub *events.Subscription, want events.Type) events.Event {
	t.Helper()

	select {
	case ev, ok := <-sub.C:
		if !ok {
			t.Fatalf("event channel closed while waiting for %q", want)
		}
		if ev.Type != want {
			t.Fatalf("event type = %q, want %q (event %+v)", ev.Type, want, ev)
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
		return events.Event{}
	}
}

func expectNoEvent(t *testing.T, sub *events.Subscription) {
	t.Helper()
	select {
	case ev, ok := <-sub.C:
		if ok {
			t.Fatalf("unexpected event: %+v", ev)
		}
	default:
	}
}

func requireState(t *testing.T, s *Session, want State) {
	t.Helper()
	got, err := s.State(testContext(t))
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if got != want {
		t.Fatalf("state = %s, want %s", got, want)
	}
}

func TestConnectStopLifecycle(t *testing.T) {
	conn := newFakeConn()
	dialer := &scriptedDialer{outcomes: []dialOutcome{{conn: conn}}}
	s, sub := newHarness(t, dialer, nil)

	requireState(t, s, StateStopped)

	if err := s.Connect(testContext(t)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	connected := nextEvent(t, sub, events.TypeConnected)
	if connected.SessionID != "test-session" {
		t.Fatalf("connected session = %q, want test-session", connected.SessionID)
	}
	if connected.Connected == nil || connected.Connected.Reconnected {
		t.Fatalf("connected payload = %+v, want first connection", connected.Connected)
	}
	requireState(t, s, StateConnected)

	// Connect is idempotent while connected and does not emit twice.
	if err := s.Connect(testContext(t)); err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	expectNoEvent(t, sub)

	if err := s.Stop(testContext(t)); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	disconnected := nextEvent(t, sub, events.TypeDisconnected)
	if !errors.Is(disconnected.Disconnected.Reason, ErrSessionClosed) {
		t.Fatalf("disconnect reason = %v, want ErrSessionClosed", disconnected.Disconnected.Reason)
	}
	if disconnected.Disconnected.WillReconnect {
		t.Fatal("shutdown disconnect must not schedule a reconnect")
	}

	select {
	case <-conn.closed:
	default:
		t.Fatal("transport connection was not closed by Stop")
	}

	requireState(t, s, StateStopped)
	if err := s.Connect(testContext(t)); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Connect after Stop = %v, want ErrSessionClosed", err)
	}
	if err := s.Stop(testContext(t)); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if err := s.Disconnect(testContext(t)); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Disconnect after Stop = %v, want ErrSessionClosed", err)
	}
	expectNoEvent(t, sub)
}

func TestStopWhileConnecting(t *testing.T) {
	dialer := newBlockingDialer()
	s, sub := newHarness(t, dialer, nil)

	connectErr := make(chan error, 1)
	go func() { connectErr <- s.Connect(context.Background()) }()

	waitClosed(t, dialer.started, "dial start")

	if err := s.Stop(testContext(t)); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	select {
	case err := <-connectErr:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("pending Connect = %v, want ErrSessionClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending Connect did not return after Stop")
	}

	waitClosed(t, dialer.stopped, "dial cancellation")
	disconnected := nextEvent(t, sub, events.TypeDisconnected)
	if !errors.Is(disconnected.Disconnected.Reason, ErrSessionClosed) {
		t.Fatalf("disconnect reason = %v, want ErrSessionClosed", disconnected.Disconnected.Reason)
	}
	requireState(t, s, StateStopped)
}

func TestDisconnectClosesLateDialConnection(t *testing.T) {
	conn := newFakeConn()
	dialer := newControlledDialer(conn)
	defer dialer.unblock()

	s, sub := newHarness(t, dialer, nil)

	connectErr := make(chan error, 1)
	go func() { connectErr <- s.Connect(context.Background()) }()
	waitClosed(t, dialer.started, "dial start")

	if err := s.Disconnect(testContext(t)); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	select {
	case err := <-connectErr:
		if !errors.Is(err, ErrNotConnected) {
			t.Fatalf("pending Connect = %v, want ErrNotConnected", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending Connect did not return after Disconnect")
	}
	nextEvent(t, sub, events.TypeDisconnected)

	// The dialer ignores cancellation and returns after Disconnect. The actor
	// must still consume the stale result and close the connection.
	dialer.unblock()
	waitClosed(t, conn.closed, "late connection close after Disconnect")
	requireState(t, s, StateDisconnected)
}

func TestStopClosesLateDialConnection(t *testing.T) {
	conn := newFakeConn()
	dialer := newControlledDialer(conn)
	defer dialer.unblock()

	s, _ := newHarness(t, dialer, nil)

	connectErr := make(chan error, 1)
	go func() { connectErr <- s.Connect(context.Background()) }()
	waitClosed(t, dialer.started, "dial start")

	if err := s.Stop(testContext(t)); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case err := <-connectErr:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("pending Connect = %v, want ErrSessionClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending Connect did not return after Stop")
	}

	// Stop must not wait forever for a dial that ignores cancellation, and the
	// eventual connection must be released by the dial goroutine.
	dialer.unblock()
	waitClosed(t, conn.closed, "late connection close after Stop")
	requireState(t, s, StateStopped)
}

func TestConnectContextOnlyAbandonsWait(t *testing.T) {
	dialer := newBlockingDialer()
	s, sub := newHarness(t, dialer, nil)

	ctx, cancel := context.WithCancel(context.Background())
	connectErr := make(chan error, 1)
	go func() { connectErr <- s.Connect(ctx) }()
	waitClosed(t, dialer.started, "dial start")

	cancel()
	select {
	case err := <-connectErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect did not return after its context was cancelled")
	}

	// Cancelling the wait does not cancel the dial; the caller decides that
	// with Disconnect or Stop.
	requireState(t, s, StateConnecting)

	if err := s.Stop(testContext(t)); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	waitClosed(t, dialer.stopped, "dial cancellation")
	nextEvent(t, sub, events.TypeDisconnected)
}

func TestDisconnectWhileConnecting(t *testing.T) {
	dialer := newBlockingDialer()
	s, sub := newHarness(t, dialer, nil)

	connectErr := make(chan error, 1)
	go func() { connectErr <- s.Connect(context.Background()) }()
	waitClosed(t, dialer.started, "dial start")

	if err := s.Disconnect(testContext(t)); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	select {
	case err := <-connectErr:
		if !errors.Is(err, ErrNotConnected) {
			t.Fatalf("pending Connect = %v, want ErrNotConnected", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending Connect did not return after Disconnect")
	}

	waitClosed(t, dialer.stopped, "dial cancellation")
	disconnected := nextEvent(t, sub, events.TypeDisconnected)
	if disconnected.Disconnected.WillReconnect {
		t.Fatal("manual disconnect must not reconnect")
	}
	if disconnected.Disconnected.Reason != nil {
		t.Fatalf("manual disconnect reason = %v, want nil", disconnected.Disconnected.Reason)
	}
	requireState(t, s, StateDisconnected)

	if err := s.Stop(testContext(t)); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Stop from DISCONNECTED must not publish a second Disconnected event.
	expectNoEvent(t, sub)
	requireState(t, s, StateStopped)
}

func TestReconnectAfterDrop(t *testing.T) {
	first := newFakeConn()
	second := newFakeConn()
	dialer := &scriptedDialer{outcomes: []dialOutcome{{conn: first}, {conn: second}}}
	policy := &fakePolicy{delays: []time.Duration{0}}
	s, sub := newHarness(t, dialer, policy)

	if err := s.Connect(testContext(t)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	nextEvent(t, sub, events.TypeConnected)

	first.drop(errDrop)

	disconnected := nextEvent(t, sub, events.TypeDisconnected)
	if !errors.Is(disconnected.Disconnected.Reason, errDrop) {
		t.Fatalf("disconnect reason = %v, want errDrop", disconnected.Disconnected.Reason)
	}
	if !disconnected.Disconnected.WillReconnect {
		t.Fatal("drop with a policy must announce a reconnect")
	}

	reconnected := nextEvent(t, sub, events.TypeConnected)
	if reconnected.Connected == nil || !reconnected.Connected.Reconnected {
		t.Fatalf("reconnect payload = %+v, want Reconnected=true", reconnected.Connected)
	}
	if got := dialer.callCount(); got != 2 {
		t.Fatalf("dial calls = %d, want 2", got)
	}
	requireState(t, s, StateConnected)

	if err := s.Stop(testContext(t)); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	nextEvent(t, sub, events.TypeDisconnected)
}

func TestReadDropWithoutPolicyIsTerminal(t *testing.T) {
	conn := newFakeConn()
	dialer := &scriptedDialer{outcomes: []dialOutcome{{conn: conn}}}
	s, sub := newHarness(t, dialer, nil)

	if err := s.Connect(testContext(t)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	nextEvent(t, sub, events.TypeConnected)

	conn.drop(errDrop)

	disconnected := nextEvent(t, sub, events.TypeDisconnected)
	if disconnected.Disconnected.WillReconnect {
		t.Fatal("without a policy the session must not reconnect")
	}
	failure := nextEvent(t, sub, events.TypeError)
	if failure.Error == nil || !failure.Error.Fatal {
		t.Fatalf("error payload = %+v, want a fatal error", failure.Error)
	}
	if !errors.Is(failure.Error.Err, errDrop) {
		t.Fatalf("error = %v, want errDrop", failure.Error.Err)
	}
	requireState(t, s, StateError)

	if err := s.Stop(testContext(t)); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	expectNoEvent(t, sub)
	requireState(t, s, StateStopped)
}

func TestDialRetriesThenConnects(t *testing.T) {
	conn := newFakeConn()
	dialer := &scriptedDialer{outcomes: []dialOutcome{{err: errBoom}, {err: errBoom}, {conn: conn}}}
	policy := &fakePolicy{delays: []time.Duration{0, 0}}
	s, sub := newHarness(t, dialer, policy)

	if err := s.Connect(testContext(t)); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	for i := 0; i < 2; i++ {
		failure := nextEvent(t, sub, events.TypeError)
		if failure.Error == nil || failure.Error.Fatal {
			t.Fatalf("attempt %d error = %+v, want retryable", i+1, failure.Error)
		}
		if !errors.Is(failure.Error.Err, errBoom) {
			t.Fatalf("attempt %d error = %v, want errBoom", i+1, failure.Error.Err)
		}
	}
	nextEvent(t, sub, events.TypeConnected)

	if got := dialer.callCount(); got != 3 {
		t.Fatalf("dial calls = %d, want 3", got)
	}
	requireState(t, s, StateConnected)
}

func TestDialFailureExhaustsPolicy(t *testing.T) {
	dialer := &scriptedDialer{outcomes: []dialOutcome{{err: errBoom}}}
	policy := &fakePolicy{} // Next always reports false
	s, sub := newHarness(t, dialer, policy)

	err := s.Connect(testContext(t))
	if !errors.Is(err, errBoom) {
		t.Fatalf("Connect = %v, want errBoom", err)
	}
	failure := nextEvent(t, sub, events.TypeError)
	if failure.Error == nil || !failure.Error.Fatal {
		t.Fatalf("error payload = %+v, want fatal", failure.Error)
	}
	requireState(t, s, StateError)

	// A session in ERROR can be asked to connect again.
	second := newFakeConn()
	dialer.setOutcomes([]dialOutcome{{conn: second}})
	if err := s.Connect(testContext(t)); err != nil {
		t.Fatalf("Connect after ERROR: %v", err)
	}
	nextEvent(t, sub, events.TypeConnected)
	requireState(t, s, StateConnected)
}

func TestConcurrentStateQueries(t *testing.T) {
	conn := newFakeConn()
	dialer := &scriptedDialer{outcomes: []dialOutcome{{conn: conn}}}
	s, sub := newHarness(t, dialer, nil)

	if err := s.Connect(testContext(t)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	nextEvent(t, sub, events.TypeConnected)

	ctx := testContext(t)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if got, err := s.State(ctx); err != nil || got != StateConnected {
				errs <- errors.New("unexpected State result")
			}
		}()
		go func() {
			defer wg.Done()
			if err := s.Connect(ctx); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent command: %v", err)
	}
	requireState(t, s, StateConnected)
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()

	if _, err := New(Config{Dialer: &scriptedDialer{}, Bus: bus}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing ID error = %v, want ErrInvalidConfig", err)
	}
	if _, err := New(Config{ID: "s", Bus: bus}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing dialer error = %v, want ErrInvalidConfig", err)
	}
	if _, err := New(Config{ID: "s", Dialer: &scriptedDialer{}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing bus error = %v, want ErrInvalidConfig", err)
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// fakeConn is an in-memory transport.FrameConn. Drop injects a read failure.
type fakeConn struct {
	frames    chan []byte
	fail      chan error
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		frames: make(chan []byte),
		fail:   make(chan error, 1),
		closed: make(chan struct{}),
	}
}

func (c *fakeConn) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case frame := <-c.frames:
		return frame, nil
	case err := <-c.fail:
		return nil, err
	case <-c.closed:
		return nil, transport.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeConn) WriteFrame(ctx context.Context, _ []byte) error {
	select {
	case <-c.closed:
		return transport.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (c *fakeConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) drop(err error) {
	c.fail <- err
}

type dialOutcome struct {
	conn transport.FrameConn
	err  error
}

// scriptedDialer returns the scripted outcomes in order, then errNoPlan.
type scriptedDialer struct {
	mu       sync.Mutex
	outcomes []dialOutcome
	calls    int
}

func (d *scriptedDialer) Dial(context.Context, transport.Endpoint) (transport.FrameConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.calls++
	if d.calls > len(d.outcomes) {
		return nil, errNoPlan
	}
	outcome := d.outcomes[d.calls-1]
	return outcome.conn, outcome.err
}

func (d *scriptedDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func (d *scriptedDialer) setOutcomes(outcomes []dialOutcome) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.outcomes = outcomes
	d.calls = 0
}

// blockingDialer blocks until the dial context is cancelled, which is how the
// tests observe Stop/Disconnect while connecting.
type blockingDialer struct {
	started   chan struct{}
	stopped   chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

func newBlockingDialer() *blockingDialer {
	return &blockingDialer{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

func (d *blockingDialer) Dial(ctx context.Context, _ transport.Endpoint) (transport.FrameConn, error) {
	d.startOnce.Do(func() { close(d.started) })
	<-ctx.Done()
	d.stopOnce.Do(func() { close(d.stopped) })
	return nil, ctx.Err()
}

// controlledDialer ignores the dial context, waits for unblock, and then
// returns conn. It models a transport that cannot be cancelled promptly and
// lets tests force the "dial result arrives after Disconnect/Stop" race.
type controlledDialer struct {
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
	conn        transport.FrameConn
}

func newControlledDialer(conn transport.FrameConn) *controlledDialer {
	return &controlledDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
		conn:    conn,
	}
}

func (d *controlledDialer) Dial(context.Context, transport.Endpoint) (transport.FrameConn, error) {
	d.startOnce.Do(func() { close(d.started) })
	<-d.release
	return d.conn, nil
}

func (d *controlledDialer) unblock() {
	d.releaseOnce.Do(func() { close(d.release) })
}

// fakePolicy is a scripted transport.ReconnectPolicy.
type fakePolicy struct {
	mu     sync.Mutex
	delays []time.Duration
	calls  int
	resets int
}

func (p *fakePolicy) Next(int) (time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.calls >= len(p.delays) {
		return 0, false
	}
	delay := p.delays[p.calls]
	p.calls++
	return delay, true
}

func (p *fakePolicy) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resets++
}
