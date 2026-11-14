package transport

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestDialSendsIntroHeaderOnce: dialing through WebSocketDialer with the
// PF-002 endpoint headers, the FIRST binary message the server receives must
// start with the PF-003 intro header followed by the 3-byte length prefix and
// the payload, and the second message must not repeat the header.
func TestDialSendsIntroHeaderOnce(t *testing.T) {
	type received struct{ data []byte }
	got := make(chan received, 4)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// PF-002 dial headers, carried by DefaultEndpoint.
		if v := r.Header.Get("Origin"); v != "https://web.whatsapp.com" {
			t.Errorf("Origin header = %q, want %q (PF-002)", v, "https://web.whatsapp.com")
		}
		if v := r.Header.Get("Cache-Control"); v != "no-cache" {
			t.Errorf("Cache-Control header = %q, want %q (PF-002)", v, "no-cache")
		}
		if v := r.Header.Get("Pragma"); v != "no-cache" {
			t.Errorf("Pragma header = %q, want %q (PF-002)", v, "no-cache")
		}

		upgrader := websocket.Upgrader{
			CheckOrigin: func(*http.Request) bool { return true },
		}
		ws, err := upgrader.Upgrade(w, r, http.Header(nil))
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer func() { _ = ws.Close() }()

		for i := 0; i < 2; i++ {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				t.Errorf("server read %d: %v", i, err)
				return
			}
			if mt != websocket.BinaryMessage {
				t.Errorf("server read %d: not binary", i)
				return
			}
			got <- received{data: data}
		}
		drainUntilClose(ws)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(srv.CloseClientConnections)

	// DefaultEndpoint supplies the PF-002 URL/headers; only the URL and the
	// handshake timeout are overridden for the local test server.
	ep := DefaultEndpoint()
	ep.URL = wsURL(srv.URL)
	ep.HandshakeTimeout = 5 * time.Second

	fc, err := (&WebSocketDialer{}).Dial(context.Background(), ep)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = fc.Close() }()

	ctx := context.Background()
	firstPayload := []byte("first frame after intro")
	secondPayload := []byte("second")

	if err := fc.WriteFrame(ctx, firstPayload); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := fc.WriteFrame(ctx, secondPayload); err != nil {
		t.Fatalf("write second: %v", err)
	}

	first := <-got
	if !bytes.HasPrefix(first.data, IntroHeader) {
		t.Fatalf("first message lacks intro header (PF-003): % x", first.data)
	}
	body := first.data[len(IntroHeader):]
	if len(body) < frameHeaderLen {
		t.Fatalf("first message too short for length prefix: % x", first)
	}
	n := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	if n != len(firstPayload) {
		t.Fatalf("first length prefix = %d, want %d", n, len(firstPayload))
	}
	if !bytes.Equal(body[frameHeaderLen:], firstPayload) {
		t.Fatalf("first payload mismatch: %q", body[frameHeaderLen:])
	}

	second := <-got
	if bytes.HasPrefix(second.data, IntroHeader) {
		t.Fatalf("second message must not repeat the intro header (PF-003): % x", second.data)
	}
	n2 := int(second.data[0])<<16 | int(second.data[1])<<8 | int(second.data[2])
	if n2 != len(secondPayload) || !bytes.Equal(second.data[frameHeaderLen:], secondPayload) {
		t.Fatalf("second frame mismatch: % x", second.data)
	}
}

// TestDialFailureWrapsErrDialFailed: a failed handshake must surface as an
// error wrapping ErrDialFailed.
func TestDialFailureWrapsErrDialFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens on the address anymore

	d := &WebSocketDialer{}
	_, err := d.Dial(context.Background(), Endpoint{URL: wsURL(url), HandshakeTimeout: 2 * time.Second})
	if err == nil {
		t.Fatal("dial to a closed server must fail")
	}
	if !errors.Is(err, ErrDialFailed) {
		t.Fatalf("want ErrDialFailed-wrapped error, got %v", err)
	}
}
