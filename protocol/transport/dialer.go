package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// ErrDialFailed wraps every failure reported by WebSocketDialer.Dial: callers
// can use errors.Is to distinguish "could not establish the transport" from
// other transport errors. The underlying handshake error (and, when the
// server answered, the HTTP status) is wrapped inside.
//
// See PF-002 for the endpoint and dial headers this dialer uses.
var ErrDialFailed = errors.New("transport: dial failed")

// WebSocketDialer implements Dialer over the gorilla WebSocket client,
// speaking the WhatsApp wire format of PF-002 (endpoint URL and dial headers)
// and PF-003 (intro header and frame format).
//
// The zero value is usable: TLSClientConfig is nil (system defaults) and
// HandshakeTimeoutOverride is unset (Endpoint.HandshakeTimeout applies).
type WebSocketDialer struct {
	// TLSClientConfig is passed to the underlying WebSocket dialer for wss
	// endpoints. nil means Go's default TLS configuration.
	TLSClientConfig *tls.Config

	// HandshakeTimeoutOverride, when positive, replaces
	// Endpoint.HandshakeTimeout for dials made through this dialer.
	HandshakeTimeoutOverride time.Duration
}

var _ Dialer = (*WebSocketDialer)(nil)

// Dial establishes a WebSocket connection to endpoint.URL and returns it
// wrapped in the WhatsApp framing layer (PF-003) with the intro header
// enabled, ready for frame I/O.
//
// Behavior:
//
//   - The handshake timeout is endpoint.HandshakeTimeout, or
//     d.HandshakeTimeoutOverride when set; the dial also respects ctx
//     cancellation.
//   - endpoint.ExtraHeaders are sent verbatim with the upgrade request —
//     DefaultEndpoint already carries the PF-002 headers (Origin,
//     Cache-Control, Pragma).
//   - On success a watchdog shuts the connection down when ctx is done, so
//     cancelling the dial context (or any context later derived from the
//     caller's choice to store) unblocks reads with errors wrapping ErrClosed.
//   - On failure the error wraps ErrDialFailed.
func (d *WebSocketDialer) Dial(ctx context.Context, endpoint Endpoint) (FrameConn, error) {
	timeout := endpoint.HandshakeTimeout
	if d.HandshakeTimeoutOverride > 0 {
		timeout = d.HandshakeTimeoutOverride
	}

	header := make(http.Header, len(endpoint.ExtraHeaders))
	for k, v := range endpoint.ExtraHeaders {
		header.Set(k, v)
	}

	wsDialer := &websocket.Dialer{
		HandshakeTimeout: timeout,
		TLSClientConfig:  d.TLSClientConfig,
	}

	ws, resp, err := wsDialer.DialContext(ctx, endpoint.URL, header)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if resp != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrDialFailed, resp.Status, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrDialFailed, err)
	}

	conn := NewWebSocketConn(ws, IntroHeader)
	conn.(*wsFrameConn).startContextWatchdog(ctx)
	return conn, nil
}
