package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// newTestWSServer starts an HTTP test server that upgrades every request to a
// WebSocket connection and runs handler on the raw server-side connection.
// The handler runs on its own goroutine: it may use t.Errorf/t.Log but never
// t.Fatal (FailNow must be called from the test goroutine).
func newTestWSServer(t *testing.T, handler func(t *testing.T, ws *websocket.Conn)) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, http.Header(nil))
		if err != nil {
			t.Errorf("upgrade failed: %v", err)
			return
		}
		defer func() { _ = ws.Close() }()
		handler(t, ws)
	}))
	t.Cleanup(srv.Close)                  // registered first: runs last
	t.Cleanup(srv.CloseClientConnections) // runs first: unblocks parked handlers
	return srv
}

// wsURL converts an httptest http:// URL into a ws:// URL.
func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}

// appendFrame appends [3-byte big-endian length][payload] to dst (PF-003).
func appendFrame(dst, payload []byte) []byte {
	n := len(payload)
	dst = append(dst, byte(n>>16), byte(n>>8), byte(n))
	return append(dst, payload...)
}

// fillPseudoRandom fills b deterministically with pseudo-random bytes
// (synthetic data only — nothing here is derived from the live protocol).
func fillPseudoRandom(b []byte, seed uint64) {
	rng := rand.New(rand.NewPCG(seed, seed))
	for i := range b {
		b[i] = byte(rng.UintN(256))
	}
}

// dialTestConn dials srv with a WebSocketDialer and returns the framed
// connection; it is closed automatically when the test ends.
func dialTestConn(ctx context.Context, t *testing.T, srv *httptest.Server) FrameConn {
	t.Helper()
	d := &WebSocketDialer{}
	fc, err := d.Dial(ctx, Endpoint{URL: wsURL(srv.URL), HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = fc.Close() })
	return fc
}

// drainUntilClose consumes server-side messages until the connection ends.
func drainUntilClose(ws *websocket.Conn) {
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			return
		}
	}
}

// TestReadFrameMultipleFramesInOneMessage: one WebSocket binary message
// carrying two frames must yield both payloads in order (PF-003).
func TestReadFrameMultipleFramesInOneMessage(t *testing.T) {
	p1 := []byte("frame-one-payload")
	p2 := []byte("frame-two")
	srv := newTestWSServer(t, func(t *testing.T, ws *websocket.Conn) {
		msg := appendFrame(appendFrame(nil, p1), p2)
		if err := ws.WriteMessage(websocket.BinaryMessage, msg); err != nil {
			t.Errorf("server write: %v", err)
			return
		}
		drainUntilClose(ws)
	})

	fc := dialTestConn(context.Background(), t, srv)
	ctx := context.Background()

	got1, err := fc.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("ReadFrame 1: %v", err)
	}
	if !bytes.Equal(got1, p1) {
		t.Fatalf("frame 1 = %q, want %q", got1, p1)
	}

	got2, err := fc.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("ReadFrame 2: %v", err)
	}
	if !bytes.Equal(got2, p2) {
		t.Fatalf("frame 2 = %q, want %q", got2, p2)
	}
}

// TestReadFrameFrameSpanningMessages: a frame split across several WebSocket
// messages — mid length-prefix and mid payload — must be reassembled, and
// bytes of the next frame already present in the same message must be kept
// for the following ReadFrame (PF-003).
func TestReadFrameFrameSpanningMessages(t *testing.T) {
	p1 := make([]byte, 90)
	p2 := make([]byte, 50)
	fillPseudoRandom(p1, 1)
	fillPseudoRandom(p2, 2)

	stream := appendFrame(appendFrame(nil, p1), p2) // 3+90+3+50 bytes
	if len(stream) != 146 {
		t.Fatalf("test setup: stream = %d bytes, want 146", len(stream))
	}
	chunks := [][]byte{
		stream[0:2],   // mid length-prefix of frame 1
		stream[2:10],  // rest of frame 1's length prefix + 7 payload bytes
		stream[10:94], // rest of p1 and the first byte of frame 2's length prefix
		stream[94:120],
		stream[120:],
	}

	srv := newTestWSServer(t, func(t *testing.T, ws *websocket.Conn) {
		for i, chunk := range chunks {
			if err := ws.WriteMessage(websocket.BinaryMessage, chunk); err != nil {
				t.Errorf("server chunk %d: %v", i, err)
				return
			}
		}
		drainUntilClose(ws)
	})

	fc := dialTestConn(context.Background(), t, srv)
	ctx := context.Background()

	got1, err := fc.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("ReadFrame 1: %v", err)
	}
	if !bytes.Equal(got1, p1) {
		t.Fatalf("frame 1 mismatch (%d bytes)", len(got1))
	}

	got2, err := fc.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("ReadFrame 2: %v", err)
	}
	if !bytes.Equal(got2, p2) {
		t.Fatalf("frame 2 mismatch (%d bytes)", len(got2))
	}
}

// TestLargeFrameRoundTripAndOversize: a 1 MB pseudo-random frame round-trips
// through the framing layer, and a payload of FrameMaxSize bytes is rejected
// with ErrFrameTooLarge (PF-003).
func TestLargeFrameRoundTripAndOversize(t *testing.T) {
	payload := make([]byte, 1<<20)
	fillPseudoRandom(payload, 42)

	srv := newTestWSServer(t, func(t *testing.T, ws *websocket.Conn) {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if mt != websocket.BinaryMessage {
			t.Errorf("server read: message type %d, want binary", mt)
			return
		}
		if !bytes.HasPrefix(data, IntroHeader) {
			t.Errorf("first message lacks intro header (PF-003)")
			return
		}
		body := data[len(IntroHeader):]
		if len(body) < frameHeaderLen {
			t.Errorf("first message too short for length prefix")
			return
		}
		n := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
		if n != len(payload) {
			t.Errorf("length prefix = %d, want %d", n, len(payload))
			return
		}
		if !bytes.Equal(body[frameHeaderLen:], payload) {
			t.Errorf("payload mismatch over the wire")
			return
		}
		// Echo back server-side: length prefix + payload, no intro header.
		if err := ws.WriteMessage(websocket.BinaryMessage, appendFrame(nil, payload)); err != nil {
			t.Errorf("server echo: %v", err)
			return
		}
		drainUntilClose(ws)
	})

	fc := dialTestConn(context.Background(), t, srv)
	ctx := context.Background()

	if err := fc.WriteFrame(ctx, payload); err != nil {
		t.Fatalf("WriteFrame 1MB: %v", err)
	}
	got, err := fc.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("ReadFrame 1MB echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch (%d bytes)", len(got))
	}

	oversize := make([]byte, FrameMaxSize)
	err = fc.WriteFrame(ctx, oversize)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized WriteFrame: want ErrFrameTooLarge, got %v", err)
	}
}

// TestConcurrentReadWrite: one goroutine writes N frames while the main
// goroutine reads N server echoes off the same connection; the race detector
// must stay clean (FrameConn contract: one reader + one writer).
func TestConcurrentReadWrite(t *testing.T) {
	const n = 200
	frames := make([][]byte, n)
	for i := range frames {
		frames[i] = make([]byte, 1+i%1024)
		fillPseudoRandom(frames[i], uint64(i)+1000)
	}

	// Server: strip the intro header from the first message, then echo every
	// frame back as its own binary message.
	srv := newTestWSServer(t, func(t *testing.T, ws *websocket.Conn) {
		stripped := false
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			if !stripped {
				stripped = true
				data = bytes.TrimPrefix(data, IntroHeader)
			}
			if len(data) < frameHeaderLen {
				t.Errorf("server: message shorter than a length prefix")
				return
			}
			length := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
			if len(data) < frameHeaderLen+length {
				t.Errorf("server: truncated frame")
				return
			}
			echo := appendFrame(nil, data[frameHeaderLen:frameHeaderLen+length])
			if err := ws.WriteMessage(websocket.BinaryMessage, echo); err != nil {
				return
			}
		}
	})

	fc := dialTestConn(context.Background(), t, srv)
	ctx := context.Background()

	writeErr := make(chan error, 1)
	go func() {
		defer close(writeErr)
		for i := 0; i < n; i++ {
			if err := fc.WriteFrame(ctx, frames[i]); err != nil {
				writeErr <- fmt.Errorf("write frame %d: %w", i, err)
				return
			}
		}
	}()

	for i := 0; i < n; i++ {
		got, err := fc.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if !bytes.Equal(got, frames[i]) {
			t.Fatalf("frame %d mismatch: got %d bytes, want %d", i, len(got), len(frames[i]))
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("writer: %v", err)
	}
}

// TestCloseSemantics: Close is idempotent and afterwards ReadFrame and
// WriteFrame return errors wrapping ErrClosed.
func TestCloseSemantics(t *testing.T) {
	srv := newTestWSServer(t, func(_ *testing.T, ws *websocket.Conn) {
		drainUntilClose(ws)
	})

	fc := dialTestConn(context.Background(), t, srv)

	if err := fc.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := fc.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}

	_, err := fc.ReadFrame(context.Background())
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("ReadFrame after Close: want ErrClosed-wrapped, got %v", err)
	}
	err = fc.WriteFrame(context.Background(), []byte("x"))
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("WriteFrame after Close: want ErrClosed-wrapped, got %v", err)
	}
}

// TestReadFrameContextCancellation: cancelling the dial context while
// ReadFrame is parked must unblock it promptly with an ErrClosed-wrapped error.
func TestReadFrameContextCancellation(t *testing.T) {
	srv := newTestWSServer(t, func(_ *testing.T, ws *websocket.Conn) {
		drainUntilClose(ws)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := &WebSocketDialer{}
	fc, err := d.Dial(ctx, Endpoint{URL: wsURL(srv.URL), HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = fc.Close() }()

	errCh := make(chan error, 1)
	go func() {
		_, err := fc.ReadFrame(ctx)
		errCh <- err
	}()

	time.Sleep(100 * time.Millisecond) // let ReadFrame park on the socket
	start := time.Now()
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("ReadFrame after cancel: want ErrClosed-wrapped, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("ReadFrame took %v to unblock after cancellation", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadFrame did not return within 3s of context cancellation")
	}
}

// TestServerSideFramingRoundTrip: a server-side FrameConn built with
// NewWebSocketConn(ws, nil) (no intro header) round-trips frames with the
// client-side FrameConn (PF-003).
func TestServerSideFramingRoundTrip(t *testing.T) {
	done := make(chan error, 1)
	srv := newTestWSServer(t, func(_ *testing.T, ws *websocket.Conn) {
		sfc := NewWebSocketConn(ws, nil)
		defer func() { _ = sfc.Close() }()

		ctx := context.Background()
		msg, err := sfc.ReadFrame(ctx)
		if err != nil {
			done <- fmt.Errorf("server read: %w", err)
			return
		}
		if string(msg) != "ping" {
			done <- fmt.Errorf("server got %q, want %q", msg, "ping")
			return
		}
		if err := sfc.WriteFrame(ctx, []byte("pong")); err != nil {
			done <- fmt.Errorf("server write: %w", err)
			return
		}
		done <- nil
		drainUntilClose(ws)
	})

	fc := dialTestConn(context.Background(), t, srv)
	ctx := context.Background()

	if err := fc.WriteFrame(ctx, []byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	pong, err := fc.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(pong) != "pong" {
		t.Fatalf("client got %q, want %q", pong, "pong")
	}
	if err := <-done; err != nil {
		t.Fatalf("server side: %v", err)
	}
}
