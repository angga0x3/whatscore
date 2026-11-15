package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// serveAfterHandshake runs the fake server: handshake, then send the given
// stanzas, then idle until the client closes. It is the shared body of every
// post-handshake auth test.
func serveAfterHandshake(fs *fakeServer, stanzas ...*binary.Node) func(ctx context.Context, fr transport.FrameConn) error {
	return func(ctx context.Context, fr transport.FrameConn) error {
		secure, _, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		for _, node := range stanzas {
			if err := secure.WriteNode(ctx, node); err != nil {
				return err
			}
		}
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return nil
		}
		return nil
	}
}

// connectWithAuthServer wires the engine to a fake server that answers the
// handshake with stanzas and returns the connected Conn.
func connectWithAuthServer(ctx context.Context, t *testing.T, stanzas ...*binary.Node) (*Conn, *fakeDialer) {
	t.Helper()
	fs := newFakeServer(t)
	dialer := newFakeDialer(serveAfterHandshake(fs, stanzas...))
	crew, err := New(engineConfig(fs, dialer, t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := crew.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return conn, dialer
}

// TestWaitAuthSuccess proves a bare <success> is the accepted outcome
// (PF-028) and that the reader slot is released afterwards.
func TestWaitAuthSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, dialer := connectWithAuthServer(ctx, t, &binary.Node{Tag: "success", Attrs: binary.Attrs{"lid": "100000000000001:8@lid"}})
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		dialer.wait(ctx, t)
	}()

	if err := conn.WaitAuth(ctx); err != nil {
		t.Fatalf("WaitAuth = %v, want nil", err)
	}
	// The reader slot is free again: a second reader runs instead of
	// returning ErrReaderBusy. The server sent nothing else, so the read
	// ends with the connection close once the test closes it.
	readCtx, readCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer readCancel()
	if _, err := conn.ReadNode(readCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadNode after WaitAuth = %v, want the context deadline", err)
	}
}

// TestWaitAuthSkipsAck proves the documented benign stanza is skipped.
func TestWaitAuthSkipsAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, dialer := connectWithAuthServer(ctx, t,
		&binary.Node{Tag: "ack", Attrs: binary.Attrs{"id": "x-1", "class": "message"}},
		&binary.Node{Tag: "success"},
	)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		dialer.wait(ctx, t)
	}()

	if err := conn.WaitAuth(ctx); err != nil {
		t.Fatalf("WaitAuth = %v, want nil after skipping the ack", err)
	}
}

// TestWaitAuthFailureCarriesCode proves a <failure> maps to ErrAuthFailed with
// the reason, code, and message recovered through errors.As (PF-029).
func TestWaitAuthFailureCarriesCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, dialer := connectWithAuthServer(ctx, t, &binary.Node{
		Tag: "failure",
		Attrs: binary.Attrs{
			"reason":  "401",
			"code":    "device_removed",
			"message": "logged out from another device",
		},
	})
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		dialer.wait(ctx, t)
	}()

	err := conn.WaitAuth(ctx)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("WaitAuth = %v, want ErrAuthFailed", err)
	}
	var failure *AuthError
	if !errors.As(err, &failure) {
		t.Fatalf("WaitAuth error %T is not *AuthError", err)
	}
	if failure.Reason != 401 || failure.ReasonRaw != "401" {
		t.Fatalf("reason = %d/%q, want 401", failure.Reason, failure.ReasonRaw)
	}
	if failure.Code != "device_removed" {
		t.Fatalf("code = %q", failure.Code)
	}
	if failure.Message != "logged out from another device" {
		t.Fatalf("message = %q", failure.Message)
	}
	for _, want := range []string{"reason=401", "code=device_removed", "logged out from another device"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestWaitAuthFailureRequiresCode proves a <failure> with only a reason still
// maps to ErrAuthFailed and reports the raw reason.
func TestWaitAuthFailureRequiresCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, dialer := connectWithAuthServer(ctx, t, &binary.Node{
		Tag:   "failure",
		Attrs: binary.Attrs{"reason": "not-a-number"},
	})
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		dialer.wait(ctx, t)
	}()

	err := conn.WaitAuth(ctx)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("WaitAuth = %v, want ErrAuthFailed", err)
	}
	var failure *AuthError
	if !errors.As(err, &failure) {
		t.Fatalf("WaitAuth error %T is not *AuthError", err)
	}
	if failure.Reason != 0 || failure.ReasonRaw != "not-a-number" {
		t.Fatalf("reason = %d/%q", failure.Reason, failure.ReasonRaw)
	}
	if failure.Code != "" || failure.Message != "" {
		t.Fatalf("absent attributes produced code=%q message=%q", failure.Code, failure.Message)
	}
	// An empty <failure/> must not produce an empty message either.
	empty := parseFailure(&binary.Node{Tag: "failure"})
	if empty.Error() != "engine: authentication failed" {
		t.Fatalf("empty failure = %q", empty.Error())
	}
}

// TestWaitAuthStreamError proves <stream:error> maps to ErrStreamError with
// the code attribute and the <conflict> child's type (PF-029).
func TestWaitAuthStreamError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, dialer := connectWithAuthServer(ctx, t, &binary.Node{
		Tag:   "stream:error",
		Attrs: binary.Attrs{"code": "401"},
		Children: []binary.Node{
			{Tag: "conflict", Attrs: binary.Attrs{"type": "device_removed"}},
		},
	})
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		dialer.wait(ctx, t)
	}()

	err := conn.WaitAuth(ctx)
	if !errors.Is(err, ErrStreamError) {
		t.Fatalf("WaitAuth = %v, want ErrStreamError", err)
	}
	var streamErr *StreamError
	if !errors.As(err, &streamErr) {
		t.Fatalf("WaitAuth error %T is not *StreamError", err)
	}
	if streamErr.Code != "401" || streamErr.ConflictType != "device_removed" {
		t.Fatalf("stream error = %+v", streamErr)
	}
	// A stream error is not an auth failure: the codes are separate so a
	// reconnecting caller can tell "reconnect" from "do not retry".
	if errors.Is(err, ErrAuthFailed) {
		t.Fatal("stream error must not match ErrAuthFailed")
	}
}

// TestWaitAuthUnexpectedStanza proves the fail-closed policy: an unrelated
// stanza is reported, and only that one stanza is consumed.
func TestWaitAuthUnexpectedStanza(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, dialer := connectWithAuthServer(ctx, t,
		&binary.Node{
			Tag:   "iq",
			Attrs: binary.Attrs{"id": "pair-1", "type": "get", "from": "s.whatsapp.net"},
			Children: []binary.Node{
				{Tag: "pair-device", Children: []binary.Node{{Tag: "ref", Bytes: []byte("ref-1")}}},
			},
		},
		&binary.Node{Tag: "success"},
	)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		dialer.wait(ctx, t)
	}()

	err := conn.WaitAuth(ctx)
	if !errors.Is(err, ErrUnexpectedStanza) {
		t.Fatalf("WaitAuth = %v, want ErrUnexpectedStanza", err)
	}
	// A <pair-device> must not be swallowed by WaitAuth: pairing owns it.
	// The stanza WaitAuth rejected is consumed, so the next read is the
	// <success> the server sent after it.
	node, err := conn.ReadNode(ctx)
	if err != nil {
		t.Fatalf("ReadNode after WaitAuth: %v", err)
	}
	if node.Tag != "success" {
		t.Fatalf("ReadNode after WaitAuth = %q, want success", node.Tag)
	}
}

// TestWaitAuthTimeout proves the wait is bounded by the caller's context only.
func TestWaitAuthTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The server completes the handshake and then stays silent.
	conn, dialer := connectWithAuthServer(ctx, t)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		dialer.wait(ctx, t)
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer waitCancel()
	start := time.Now()
	err := conn.WaitAuth(waitCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitAuth = %v, want context.DeadlineExceeded", err)
	}
	if errors.Is(err, ErrAuthFailed) {
		t.Fatal("a timeout must not be reported as an auth failure")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("WaitAuth returned after %v, well past its deadline", elapsed)
	}
}

// TestWaitAuthReaderOwnership proves WaitAuth competes for the single reader
// slot like every other reader, and that a closed Conn refuses it.
func TestWaitAuthReaderOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The server stays silent so the pump blocks instead of racing a
	// stanza it would consume.
	conn, dialer := connectWithAuthServer(ctx, t)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		dialer.wait(ctx, t)
	}()

	// Claim the slot with the pump; WaitAuth must be refused instead of
	// racing the pump inside the AEAD counter.
	if _, err := conn.StartPump(ctx); err != nil {
		t.Fatalf("StartPump: %v", err)
	}
	if err := conn.WaitAuth(ctx); !errors.Is(err, ErrReaderBusy) {
		t.Fatalf("WaitAuth during pump = %v, want ErrReaderBusy", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := conn.WaitAuth(ctx); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("WaitAuth after Close = %v, want ErrNotConnected", err)
	}
}

// TestWaitAuthSanitizesServerText proves free-form server text is capped and
// stripped of control characters before it reaches an error or a log line.
func TestWaitAuthSanitizesServerText(t *testing.T) {
	long := strings.Repeat("A", maxServerTextLen*2) + "\nsecond line"
	failure := parseFailure(&binary.Node{
		Tag:   "failure",
		Attrs: binary.Attrs{"reason": "400", "message": long},
	})
	if strings.ContainsAny(failure.Message, "\r\n\t") {
		t.Fatalf("message kept control characters: %q", failure.Message)
	}
	if len([]rune(failure.Message)) > maxServerTextLen+3 {
		t.Fatalf("message is %d runes, want at most %d plus the marker",
			len([]rune(failure.Message)), maxServerTextLen)
	}
	if !strings.HasSuffix(failure.Message, "...") {
		t.Fatalf("truncated message %q has no marker", failure.Message)
	}

	// Unprintable characters become '?' instead of reaching a terminal.
	sanitized := sanitizeServerText("a\x00b\x1bc\x7f")
	if sanitized != "a?b?c?" {
		t.Fatalf("sanitizeServerText = %q", sanitized)
	}
	if sanitizeServerText("") != "" {
		t.Fatal("empty input must stay empty")
	}
}
