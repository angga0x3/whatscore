// Package session implements the one-session-one-actor runtime described in
// the technical specification (§2 decision 3, §4.12).
//
// A Session owns a single goroutine. All session state (state machine,
// transport connection, reconnect attempt, pending Connect callers) is touched
// only by that goroutine. Callers interact through methods that send commands
// over a channel and wait for a result; blocking transport I/O happens in
// helper goroutines that hand their single result back to the actor. The actor
// is therefore the only writer, and no mutex protects session state.
//
// A session obtains its transport connection through the injected
// transport.Dialer and drives it through the transport.FrameConn interface.
// Inbound frames are read and discarded: message and Signal handling belong to
// core/messaging, not this package. Reading still matters because it detects
// connection drops and feeds the transport.ReconnectPolicy.
//
// Lifecycle events are published to the injected core/events bus:
//
//	Connect:         (CONNECTING) -> CONNECTED       [Connected]
//	                 (CONNECTING) -> ERROR           [Error] (retries exhausted)
//	connection lost: (CONNECTED) -> DISCONNECTED     [Disconnected]
//	                 then reconnect -> CONNECTED     [Connected]
//	Disconnect:      (CONNECTING|CONNECTED) -> DISCONNECTED [Disconnected]
//	Stop:            (CONNECTING|CONNECTED) -> STOPPED      [Disconnected]
//
// A lost connection is retried only when a transport.ReconnectPolicy is
// configured. The session never closes the injected bus; its owner does.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// ErrInvalidConfig is returned by New when required configuration is missing.
var ErrInvalidConfig = errors.New("core/session: invalid config")

// ErrSessionClosed is returned when a command is issued after the actor has
// stopped, including to pending Connect calls that lose a race with Stop.
var ErrSessionClosed = errors.New("core/session: session closed")

// ErrNotConnected is returned to a pending Connect call when Disconnect wins
// before the connection is established.
var ErrNotConnected = errors.New("core/session: not connected")

// State is the session lifecycle state. Its String form is the uppercase name
// used by logs and adapters.
type State uint8

const (
	// StateStopped is the initial state and the final state after Stop.
	StateStopped State = iota
	// StateConnecting means a dial attempt is in flight.
	StateConnecting
	// StateConnected means a transport connection is established.
	StateConnected
	// StateDisconnected means there is no connection; a retry may still be
	// scheduled when the session is reconnecting.
	StateDisconnected
	// StateError means the session gave up after an unrecoverable failure.
	StateError
)

// String returns the uppercase state name.
func (s State) String() string {
	switch s {
	case StateStopped:
		return "STOPPED"
	case StateConnecting:
		return "CONNECTING"
	case StateConnected:
		return "CONNECTED"
	case StateDisconnected:
		return "DISCONNECTED"
	case StateError:
		return "ERROR"
	default:
		return fmt.Sprintf("STATE(%d)", uint8(s))
	}
}

// Connector wraps a dialed frame connection, for example with the Noise
// handshake. The returned connection must close the raw connection when it is
// closed. A non-nil error aborts the dial attempt.
type Connector interface {
	Connect(ctx context.Context, raw transport.FrameConn) (transport.FrameConn, error)
}

// FrameHandler consumes inbound frames. Calls are serialized per connection;
// a returned error tears the connection down and feeds the reconnect policy.
type FrameHandler interface {
	HandleFrame(ctx context.Context, frame []byte) error
}

// FrameHandlerFunc adapts a function to FrameHandler.
type FrameHandlerFunc func(ctx context.Context, frame []byte) error

// HandleFrame implements FrameHandler.
func (f FrameHandlerFunc) HandleFrame(ctx context.Context, frame []byte) error {
	return f(ctx, frame)
}

// Config describes one session. ID, Dialer, and Bus are required.
//
// Treat Config as immutable after New. A Dialer may be shared by several
// sessions and must support concurrent Dial calls. Each session needs its own
// ReconnectPolicy instance: policies own backoff state and are called only by
// that session's actor.
type Config struct {
	// ID identifies the session in logs and on every published event.
	ID string

	// Endpoint is passed verbatim to the dialer (URL and dial options).
	Endpoint transport.Endpoint

	// Dialer is the injected connection factory. Tests supply in-memory
	// implementations; production supplies transport.WebSocketDialer.
	Dialer transport.Dialer

	// Reconnect decides whether and when a lost connection is retried. A nil
	// policy disables reconnection: the first failure becomes terminal.
	Reconnect transport.ReconnectPolicy

	// Connector optionally wraps the dialed connection before it is used
	// (for example with the Noise handshake). Nil uses the raw connection.
	Connector Connector

	// FrameHandler receives inbound frames after the connector, if any.
	// Nil discards frames; reading still detects drops.
	FrameHandler FrameHandler

	// Bus receives lifecycle events. It is shared by all sessions owned by
	// the caller and is never closed by a Session.
	Bus *events.Bus

	// Logger receives structured lifecycle logs. A nil logger discards
	// output, which keeps embedding simple and tests quiet.
	Logger *slog.Logger
}

// Session is one WhatsApp session actor. It is safe for concurrent use by many
// callers; all state mutations are serialized by the actor goroutine.
type Session struct {
	id     string
	cfg    Config
	logger *slog.Logger
	bus    *events.Bus

	writeMu     sync.Mutex
	cmds        chan command
	done        chan struct{}
	dialResults chan dialResult
	baseCtx     context.Context
	baseCancel  context.CancelFunc
}

// New validates cfg and starts the actor goroutine. The session starts in
// StateStopped and does not dial until Connect is called.
func New(cfg Config) (*Session, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("%w: ID is required", ErrInvalidConfig)
	}
	if cfg.Dialer == nil {
		return nil, fmt.Errorf("%w: Dialer is required", ErrInvalidConfig)
	}
	if cfg.Bus == nil {
		return nil, fmt.Errorf("%w: Bus is required", ErrInvalidConfig)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	logger = logger.With("component", "core/session", "session", cfg.ID)

	// Own the endpoint headers so mutating the caller's map cannot race with
	// a dial attempt.
	cfg.Endpoint.ExtraHeaders = maps.Clone(cfg.Endpoint.ExtraHeaders)

	baseCtx, baseCancel := context.WithCancel(context.Background())
	s := &Session{
		id:          cfg.ID,
		cfg:         cfg,
		logger:      logger,
		bus:         cfg.Bus,
		cmds:        make(chan command),
		done:        make(chan struct{}),
		dialResults: make(chan dialResult),
		baseCtx:     baseCtx,
		baseCancel:  baseCancel,
	}
	go s.run()
	return s, nil
}

// ID returns the immutable session identifier.
func (s *Session) ID() string { return s.id }

// Connect asks the session to establish a connection and waits until it is
// connected, the reconnect policy gives up, ctx is done, or the session stops.
//
// The call is idempotent while connected. While connecting it joins the
// pending waiters. Cancelling ctx stops only the wait, not the connection
// attempt; call Disconnect or Stop to cancel the attempt.
func (s *Session) Connect(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reply := make(chan result, 1)
	waiter := connectWaiter{reply: reply, done: ctx.Done()}
	if err := s.send(ctx, command{kind: cmdConnect, waiter: waiter}); err != nil {
		return err
	}
	select {
	case r := <-reply:
		return r.err
	case <-s.done:
		return ErrSessionClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Disconnect closes any active connection and disables automatic reconnect.
// It is a no-op when the session is already disconnected or has never
// connected. A pending Connect call is resolved with ErrNotConnected.
func (s *Session) Disconnect(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reply := make(chan result, 1)
	if err := s.send(ctx, command{kind: cmdDisconnect, reply: reply}); err != nil {
		return err
	}
	select {
	case r := <-reply:
		return r.err
	case <-s.done:
		return ErrSessionClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// State returns the current lifecycle state. If ctx expires the state is not
// meaningful and the returned error is ctx.Err(); after Stop it reports
// StateStopped without contacting the actor.
func (s *Session) State(ctx context.Context) (State, error) {
	select {
	case <-s.done:
		return StateStopped, nil
	default:
	}

	if err := ctx.Err(); err != nil {
		return StateStopped, err
	}
	reply := make(chan result, 1)
	if err := s.send(ctx, command{kind: cmdState, reply: reply}); err != nil {
		return StateStopped, err
	}
	select {
	case r := <-reply:
		return r.state, r.err
	case <-s.done:
		return StateStopped, nil
	case <-ctx.Done():
		return StateStopped, ctx.Err()
	}
}

// Stop gracefully shuts the actor down and waits for it to exit or for ctx to
// expire. It is idempotent. A session that was connected or connecting emits a
// final Disconnected event carrying ErrSessionClosed before reaching
// StateStopped. Commands issued after Stop return ErrSessionClosed.
func (s *Session) Stop(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	select {
	case s.cmds <- command{kind: cmdStop}:
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WriteFrame writes one frame on the current connection. Writes are
// serialized; ErrNotConnected is returned when there is no connection.
func (s *Session) WriteFrame(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reply := make(chan result, 1)
	if err := s.send(ctx, command{kind: cmdConn, reply: reply}); err != nil {
		return err
	}
	var conn transport.FrameConn
	select {
	case r := <-reply:
		conn = r.conn
	case <-s.done:
		return ErrSessionClosed
	case <-ctx.Done():
		return ctx.Err()
	}
	if conn == nil {
		return ErrNotConnected
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := conn.WriteFrame(ctx, frame); err != nil {
		return fmt.Errorf("session %s: write frame: %w", s.id, err)
	}
	return nil
}

// send enqueues cmd unless the session is already stopping or ctx ends.
func (s *Session) send(ctx context.Context, cmd command) error {
	select {
	case <-s.done:
		return ErrSessionClosed
	case s.cmds <- cmd:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type commandKind uint8

const (
	cmdConnect commandKind = iota
	cmdDisconnect
	cmdState
	cmdConn
	cmdStop
)

type command struct {
	kind   commandKind
	reply  chan result
	waiter connectWaiter
}

// connectWaiter is one caller blocked in Connect. done is the caller's
// ctx.Done channel, used to prune abandoned waiters so a canceled Connect does
// not pin memory for the lifetime of a reconnect loop.
type connectWaiter struct {
	reply chan result
	done  <-chan struct{}
}

func (w connectWaiter) abandoned() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

type result struct {
	state State
	conn  transport.FrameConn
	err   error
}

// run is the actor entry point. It owns all session state until it returns.
func (s *Session) run() {
	defer close(s.done)
	defer s.baseCancel()

	a := &actor{s: s, state: StateStopped}
	a.loop()
}

type dialResult struct {
	gen    uint64
	conn   transport.FrameConn
	err    error
	cancel context.CancelFunc
	// ack is closed by the actor once it has taken ownership of the result.
	// The dial goroutine waits for it so it can close a connection that the
	// actor never consumed (for example when Stop wins the race).
	ack chan struct{}
}

// actor holds every piece of mutable session state. It is accessed only from
// Session.run; helper goroutines communicate solely through channels.
type actor struct {
	s *Session

	state State

	conn       transport.FrameConn
	connCancel context.CancelFunc

	dialCancel context.CancelFunc
	dialing    bool
	dialGen    uint64

	readCancel context.CancelFunc
	readCh     <-chan error

	retryTimer *time.Timer
	retryCh    <-chan time.Time

	attempt        int
	everConnected  bool
	connectWaiters []connectWaiter
}

func (a *actor) loop() {
	for {
		a.pruneWaiters()
		select {
		case cmd := <-a.s.cmds:
			if cmd.kind == cmdStop {
				a.shutdown()
				return
			}
			a.handle(cmd)
		case dr := <-a.s.dialResults:
			a.onDial(dr)
		case err := <-a.readCh:
			a.onReadError(err)
		case <-a.retryCh:
			a.stopTimer()
			a.startDial()
		}
	}
}

func (a *actor) handle(cmd command) {
	switch cmd.kind {
	case cmdConnect:
		a.connect(cmd.waiter)
	case cmdDisconnect:
		a.disconnect(cmd.reply)
	case cmdState:
		respond(cmd.reply, result{state: a.state})
	case cmdConn:
		respond(cmd.reply, result{conn: a.conn})
	}
}

func (a *actor) connect(waiter connectWaiter) {
	switch a.state {
	case StateConnected:
		respond(waiter.reply, result{})
		return
	case StateConnecting:
		if waiter.reply != nil {
			a.connectWaiters = append(a.connectWaiters, waiter)
		}
		return
	}

	// Stopped (initial), Disconnected, or Error: start a fresh connect cycle.
	// CancelPending also clears a retry timer that may be waiting from an
	// automatic reconnect, so a manual Connect never races a scheduled dial.
	a.cancelPending()
	a.attempt = 0
	if a.s.cfg.Reconnect != nil {
		a.s.cfg.Reconnect.Reset()
	}
	if waiter.reply != nil {
		a.connectWaiters = append(a.connectWaiters, waiter)
	}
	a.startDial()
}

func (a *actor) disconnect(reply chan result) {
	if a.state == StateStopped || a.state == StateDisconnected {
		respond(reply, result{})
		return
	}

	wasActive := a.state == StateConnecting || a.state == StateConnected
	a.cancelPending()
	a.attempt = 0
	if a.s.cfg.Reconnect != nil {
		a.s.cfg.Reconnect.Reset()
	}
	a.state = StateDisconnected
	if wasActive {
		a.emit(events.Event{
			Type:         events.TypeDisconnected,
			Disconnected: &events.Disconnected{WillReconnect: false},
		})
	}
	// A Connect caller that was still waiting must not hang now that the
	// connection attempt was abandoned locally.
	a.resolve(result{err: ErrNotConnected})
	respond(reply, result{})
	a.s.logger.Info("session disconnected")
}

func (a *actor) shutdown() {
	active := a.state == StateConnecting || a.state == StateConnected
	a.cancelPending()
	if active {
		a.emit(events.Event{
			Type: events.TypeDisconnected,
			Disconnected: &events.Disconnected{
				Reason:        ErrSessionClosed,
				WillReconnect: false,
			},
		})
	}
	a.state = StateStopped
	a.resolve(result{err: ErrSessionClosed})
	a.s.logger.Info("session stopped")
}

func (a *actor) startDial() {
	a.state = StateConnecting

	a.dialGen++
	gen := a.dialGen
	ctx, cancel := context.WithCancel(a.s.baseCtx)
	a.dialing = true
	a.dialCancel = cancel

	dialer := a.s.cfg.Dialer
	endpoint := a.s.cfg.Endpoint
	connector := a.s.cfg.Connector
	ack := make(chan struct{})
	a.s.logger.Debug("dialing transport")

	go func() {
		conn, err := dialer.Dial(ctx, endpoint)
		if err == nil && conn != nil && connector != nil {
			wrapped, connectErr := connector.Connect(ctx, conn)
			switch {
			case connectErr != nil:
				_ = conn.Close()
				conn, err = nil, fmt.Errorf("core/session: connector: %w", connectErr)
			case wrapped == nil:
				_ = conn.Close()
				conn, err = nil, errors.New("core/session: connector returned a nil connection")
			default:
				conn = wrapped
			}
		}
		result := dialResult{gen: gen, conn: conn, err: err, cancel: cancel, ack: ack}
		select {
		case a.s.dialResults <- result:
			// The actor either consumes this result or exits. If it exits
			// first, this goroutine still owns the connection and must close
			// it.
			select {
			case <-ack:
			case <-a.s.done:
				if conn != nil {
					_ = conn.Close()
				}
			}
		case <-a.s.done:
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
}

func (a *actor) onDial(dr dialResult) {
	if dr.ack != nil {
		defer close(dr.ack)
	}

	if dr.gen != a.dialGen || !a.dialing {
		// A result from an attempt that Disconnect or Stop already abandoned.
		if dr.cancel != nil {
			dr.cancel()
		}
		if dr.conn != nil {
			_ = dr.conn.Close()
		}
		return
	}

	a.dialing = false
	a.dialCancel = nil

	if dr.err == nil && dr.conn == nil {
		dr.err = errors.New("core/session: dialer returned a nil connection")
	}
	if dr.err != nil {
		if dr.cancel != nil {
			dr.cancel()
		}
		a.onDialError(dr.err)
		return
	}

	a.conn = dr.conn
	a.connCancel = dr.cancel
	a.state = StateConnected
	a.attempt = 0
	if a.s.cfg.Reconnect != nil {
		a.s.cfg.Reconnect.Reset()
	}
	a.startReader(dr.conn)

	reconnected := a.everConnected
	a.everConnected = true
	a.emit(events.Event{
		Type:      events.TypeConnected,
		Connected: &events.Connected{Reconnected: reconnected},
	})
	a.resolve(result{})
	a.s.logger.Info("session connected", "reconnected", reconnected)
}

func (a *actor) onDialError(err error) {
	delay, ok := a.nextRetry()
	if !ok {
		a.state = StateError
		a.emit(events.Event{
			Type:  events.TypeError,
			Error: &events.SessionError{Op: "connect", Err: err, Fatal: true},
		})
		a.resolve(result{err: fmt.Errorf("session %s: connect: %w", a.s.id, err)})
		a.s.logger.Error("session connect failed", "error", err)
		return
	}

	a.state = StateDisconnected
	a.emit(events.Event{
		Type:  events.TypeError,
		Error: &events.SessionError{Op: "connect", Err: err, Fatal: false},
	})
	a.s.logger.Warn("session connect failed; retrying", "error", err, "attempt", a.attempt)
	a.schedule(delay)
}

func (a *actor) startReader(conn transport.FrameConn) {
	ctx, cancel := context.WithCancel(a.s.baseCtx)
	ch := make(chan error, 1)
	a.readCancel = cancel
	a.readCh = ch
	handler := a.s.cfg.FrameHandler

	go func() {
		for {
			frame, err := conn.ReadFrame(ctx)
			if err != nil {
				select {
				case ch <- err:
				case <-a.s.done:
				}
				return
			}
			if handler == nil {
				continue
			}
			if err := handler.HandleFrame(ctx, frame); err != nil {
				select {
				case ch <- fmt.Errorf("core/session: frame handler: %w", err):
				case <-a.s.done:
				}
				return
			}
		}
	}()
}

func (a *actor) onReadError(err error) {
	a.readCh = nil
	if a.state != StateConnected {
		// A stale result from a connection that was already abandoned.
		return
	}

	a.closeConn()
	a.attempt = 0

	delay, ok := a.nextRetry()
	if !ok {
		a.state = StateError
		a.emit(events.Event{
			Type: events.TypeDisconnected,
			Disconnected: &events.Disconnected{
				Reason:        err,
				WillReconnect: false,
			},
		})
		a.emit(events.Event{
			Type:  events.TypeError,
			Error: &events.SessionError{Op: "read", Err: err, Fatal: true},
		})
		a.s.logger.Error("session connection lost", "error", err)
		return
	}

	a.state = StateDisconnected
	a.emit(events.Event{
		Type: events.TypeDisconnected,
		Disconnected: &events.Disconnected{
			Reason:        err,
			WillReconnect: true,
		},
	})
	a.s.logger.Warn("session connection lost; reconnecting", "error", err, "attempt", a.attempt)
	a.schedule(delay)
}

// nextRetry advances the reconnect attempt counter and asks the policy for the
// next delay. Without a policy it always reports false.
func (a *actor) nextRetry() (time.Duration, bool) {
	if a.s.cfg.Reconnect == nil {
		return 0, false
	}
	a.attempt++
	return a.s.cfg.Reconnect.Next(a.attempt)
}

func (a *actor) schedule(delay time.Duration) {
	a.stopTimer()
	if delay <= 0 {
		// Zero-delay policies (the deterministic test case) reconnect in the
		// same actor turn, still after the current event was published.
		a.startDial()
		return
	}
	a.retryTimer = time.NewTimer(delay)
	a.retryCh = a.retryTimer.C
}

func (a *actor) stopTimer() {
	if a.retryTimer != nil {
		a.retryTimer.Stop()
		a.retryTimer = nil
	}
	a.retryCh = nil
}

func (a *actor) closeConn() {
	if a.readCancel != nil {
		a.readCancel()
		a.readCancel = nil
	}
	a.readCh = nil
	if a.connCancel != nil {
		a.connCancel()
		a.connCancel = nil
	}
	if a.conn != nil {
		_ = a.conn.Close()
		a.conn = nil
	}
}

func (a *actor) cancelPending() {
	a.stopTimer()
	// Invalidate any in-flight dial. Its result still flows through
	// dialResults (so the goroutine can release the connection), but onDial
	// will see the generation mismatch and discard it.
	a.dialGen++
	a.dialing = false
	if a.dialCancel != nil {
		a.dialCancel()
		a.dialCancel = nil
	}
	a.closeConn()
}

func (a *actor) emit(ev events.Event) {
	ev.SessionID = a.s.id
	a.s.bus.Publish(ev)
}

func (a *actor) resolve(r result) {
	for _, waiter := range a.connectWaiters {
		respond(waiter.reply, r)
	}
	a.connectWaiters = nil
}

// pruneWaiters drops Connect callers whose context ended while waiting. Their
// result channel has room for one buffered value, so dropping the reference is
// all that is needed.
func (a *actor) pruneWaiters() {
	if len(a.connectWaiters) == 0 {
		return
	}
	kept := a.connectWaiters[:0]
	for _, waiter := range a.connectWaiters {
		if waiter.abandoned() {
			continue
		}
		kept = append(kept, waiter)
	}
	for i := len(kept); i < len(a.connectWaiters); i++ {
		a.connectWaiters[i] = connectWaiter{}
	}
	a.connectWaiters = kept
}

func respond(ch chan result, r result) {
	if ch == nil {
		return
	}
	select {
	case ch <- r:
	default:
		// The caller abandoned the command (usually via ctx); its buffered
		// result slot is already full, so there is nothing to do.
	}
}
