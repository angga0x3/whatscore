// Package transport owns the outermost wire layer of the WhatsApp protocol
// engine: establishing the WebSocket connection, reading and writing framed
// messages, and recovering from disconnects.
//
// The package depends on the Go standard library plus github.com/gorilla/
// websocket for the WebSocket wire layer. It must never import core, server,
// storage, or config packages — see the dependency rules in
// docs/architecture/technical-specification.md.
//
// Status: WebSocket transport implemented (Phase 1); contract types below
// are stable and consumed by protocol/noise and the test fake server.
package transport

import (
	"context"
	"errors"
	"time"
)

// ErrClosed is returned by FrameConn operations after Close has been called.
var ErrClosed = errors.New("transport: connection closed")

// FrameConn is a bidirectional stream of opaque binary frames. Higher
// layers (noise, binary) never see sockets, only frames.
//
// Implementations must support one concurrent reader and one concurrent
// writer; simultaneous ReadFrame and WriteFrame calls are safe, but two
// concurrent reads (or two concurrent writes) are not.
type FrameConn interface {
	// ReadFrame blocks until a full frame is available or ctx is cancelled.
	ReadFrame(ctx context.Context) ([]byte, error)

	// WriteFrame writes one full frame atomically; partial writes are never
	// surfaced to callers.
	WriteFrame(ctx context.Context, frame []byte) error

	// Close releases underlying resources. It must be idempotent.
	Close() error
}

// Endpoint describes where and how to connect. Protocol findings that fix
// concrete values (URL, headers, timeouts) live in docs/protocol with
// provenance; this struct only defines the shape.
type Endpoint struct {
	// URL is the WebSocket endpoint to dial.
	URL string

	// HandshakeTimeout bounds the WebSocket handshake.
	HandshakeTimeout time.Duration

	// ExtraHeaders are sent verbatim with the upgrade request.
	ExtraHeaders map[string]string
}

// Dialer opens new transport connections. Phase 1 provides a WebSocket
// implementation; tests inject in-memory FrameConn pairs instead.
type Dialer interface {
	// Dial establishes a connection and returns it ready for frame I/O.
	Dial(ctx context.Context, endpoint Endpoint) (FrameConn, error)
}

// ReconnectPolicy decides whether and when a dropped connection is retried.
// Implementations own their backoff state.
type ReconnectPolicy interface {
	// Next returns the delay before the next attempt, or false to give up.
	Next(attempt int) (time.Duration, bool)

	// Reset clears backoff state after a healthy connection period.
	Reset()
}
