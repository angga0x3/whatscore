package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// frameHeaderLen is the size of the frame length prefix: one 24-bit
// big-endian integer (PF-003).
const frameHeaderLen = 3

// closeWriteWait bounds the best-effort WebSocket close handshake performed
// by shutdown: the close control frame gets this long to go out before the
// underlying connection is force-closed.
const closeWriteWait = 2 * time.Second

// ErrFrameTooLarge is returned by WriteFrame when a frame payload is
// FrameMaxSize bytes or larger (it cannot be encoded in the 24-bit length
// prefix), and by ReadFrame when a peer frame length exceeds FrameMaxSize.
//
// Provenance: PF-003 (Probable / Observed-only) — maximum frame size is 2^24
// bytes; larger frames are rejected (whatsmeow additionally forces a close on
// oversized reads, which ReadFrame mirrors by shutting the connection down).
var ErrFrameTooLarge = errors.New("transport: frame too large")

var _ FrameConn = (*wsFrameConn)(nil)

// NewWebSocketConn wraps a raw gorilla WebSocket connection with the
// WhatsApp framing layer (PF-003) and returns it as a FrameConn.
//
// Semantics (all per PF-003):
//
//   - WriteFrame emits [3-byte big-endian length][payload] as exactly one
//     WebSocket binary message. If header is non-empty it is copied and
//     prepended to the FIRST written message only (IntroHeader +
//     length + payload in a single binary message, as whatsmeow does).
//     Pass header=nil for a server-side connection that does not send an
//     intro header.
//   - ReadFrame reassembles the byte stream carried across WebSocket binary
//     messages: a frame may span multiple WebSocket messages and one
//     WebSocket message may carry multiple frames. It returns a copy of each
//     frame payload; leftover bytes stay buffered for the next call.
//   - Receive-side intro handling mirrors the send side, so that the two
//     endpoints of one connection are complementary: a connection that sends
//     no intro header (server side, header=nil) skips a leading IntroHeader
//     if the byte stream opens with one — which is what the header-sending
//     peer produces (PF-003). A connection that sends a header never skips
//     one on read, since its peer does not send one back. The check looks at
//     the first bytes of the stream only; a first frame whose length prefix
//     happens to spell the header bytes would be misread, which the reference
//     implementations accept as a protocol-level constant.
//   - Non-binary WebSocket messages are skipped (whatsmeow warns and
//     continues on non-binary messages; gorilla handles control frames
//     internally, so in practice only text messages reach this path).
//
// Concurrency: at most one concurrent ReadFrame and one concurrent WriteFrame
// are supported, per the FrameConn contract. Cancelling the context passed to
// a blocked ReadFrame (or its deadline expiring) aborts the read by closing
// the connection — a partially reassembled frame leaves the byte stream
// unrecoverable, so the error wraps ErrClosed. After Close (or a context-
// triggered shutdown), ReadFrame and WriteFrame return errors wrapping
// ErrClosed.
//
// The returned connection is not tied to any context by this constructor;
// WebSocketDialer.Dial starts a watchdog on the dial context for connections
// it creates.
//
// Provenance: PF-003 (Probable / Observed-only).
func NewWebSocketConn(ws *websocket.Conn, header []byte) FrameConn {
	var hdr []byte
	if len(header) > 0 {
		hdr = make([]byte, len(header))
		copy(hdr, header)
	}
	return &wsFrameConn{
		ws:         ws,
		hdr:        hdr,
		stripIntro: len(hdr) == 0,
		done:       make(chan struct{}),
	}
}

// wsFrameConn implements FrameConn on top of a gorilla WebSocket connection
// using the WhatsApp frame format (PF-003).
type wsFrameConn struct {
	ws  *websocket.Conn
	hdr []byte // intro header prepended to the first write; nil if none

	writeMu   sync.Mutex // guards sentIntro and the single-writer rule
	sentIntro bool

	readMu        sync.Mutex // guards the read fields below and the single-reader rule
	buf           []byte     // bytes received but not yet consumed as frames
	stripIntro    bool       // server side: skip a peer intro header at stream start
	peerIntroDone bool       // whether the leading-intro-header check has run

	closeMu sync.Mutex
	closed  bool // set before any local teardown, first caller wins
	done    chan struct{}
}

// ReadFrame blocks until one full frame has been reassembled from the
// WebSocket byte stream (PF-003) or the context is done.
//
// Context handling:
//
//   - If ctx carries a deadline, it is applied to the WebSocket read deadline
//     so a stalled peer unblocks the reader; calls without a deadline clear
//     any deadline left by a previous call.
//   - If ctx is cancelled while ReadFrame is parked in the WebSocket read,
//     a watchdog closes the connection to unblock it (gorilla reads cannot
//     be interrupted any other way), and the returned error wraps ErrClosed.
//     Because a partially reassembled frame leaves the stream unrecoverable
//     (PF-003), cancellation also ends the connection for subsequent calls.
func (c *wsFrameConn) ReadFrame(ctx context.Context) ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: read frame: %w", ErrClosed, err)
	}
	if c.isClosed() {
		return nil, fmt.Errorf("%w: read frame", ErrClosed)
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := c.ws.SetReadDeadline(deadline); err != nil {
			return nil, fmt.Errorf("transport: read frame: set read deadline: %w", err)
		}
	} else {
		_ = c.ws.SetReadDeadline(time.Time{}) // clear a stale deadline
	}

	if ctx.Done() != nil {
		stop := make(chan struct{})
		defer close(stop)
		go c.cancelReadWatchdog(ctx, stop)
	}

	for {
		if c.stripIntro && !c.peerIntroDone && len(c.buf) >= len(IntroHeader) {
			// Decide once, at stream start, whether the peer opened with an
			// intro header (PF-003) and skip it if so. Four stream bytes are
			// needed to tell the header apart from the first frame, so the
			// check waits until they are buffered.
			if bytes.Equal(c.buf[:len(IntroHeader)], IntroHeader) {
				rest := copy(c.buf, c.buf[len(IntroHeader):])
				c.buf = c.buf[:rest]
			}
			c.peerIntroDone = true
		}

		if (!c.stripIntro || c.peerIntroDone) && len(c.buf) >= frameHeaderLen {
			n := int(c.buf[0])<<16 | int(c.buf[1])<<8 | int(c.buf[2])
			if n > FrameMaxSize {
				// Unreachable with a strict 24-bit parse but kept as the
				// documented guard for the FrameMaxSize invariant. Like
				// whatsmeow's oversized-read handling, the connection is
				// torn down: the stream cannot be resynchronized.
				c.shutdown()
				return nil, fmt.Errorf(
					"%w: peer frame length %d exceeds maximum %d (PF-003)",
					ErrFrameTooLarge, n, FrameMaxSize)
			}
			if total := frameHeaderLen + n; len(c.buf) >= total {
				frame := make([]byte, n)
				copy(frame, c.buf[frameHeaderLen:total])
				rest := copy(c.buf, c.buf[total:]) // keep leftover bytes
				c.buf = c.buf[:rest]
				return frame, nil
			}
		}

		msgType, data, err := c.ws.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%w: read frame: %w", ErrClosed, err)
			}
			if c.isClosed() {
				return nil, fmt.Errorf("%w: read frame: %w", ErrClosed, err)
			}
			return nil, fmt.Errorf("transport: read frame: %w", err)
		}
		if msgType != websocket.BinaryMessage {
			// PF-003: only binary messages carry frames; whatsmeow warns and
			// continues on other message types. Control frames never reach
			// this path (gorilla answers them internally).
			continue
		}
		c.buf = append(c.buf, data...)
	}
}

// WriteFrame writes one frame atomically as a single WebSocket binary
// message: [3-byte big-endian length][payload], prefixed by the intro header
// on the first write of the connection when one was configured (PF-003).
//
// Payloads of FrameMaxSize bytes or larger are rejected with ErrFrameTooLarge
// before anything is sent. If the context is already cancelled the write is
// not attempted; an in-flight write is not interrupted by ctx (gorilla writes
// cannot be cancelled), and the connection stays usable afterwards.
func (c *wsFrameConn) WriteFrame(ctx context.Context, frame []byte) error {
	if len(frame) >= FrameMaxSize {
		return fmt.Errorf(
			"%w: frame is %d bytes, maximum is %d (PF-003)",
			ErrFrameTooLarge, len(frame), FrameMaxSize)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("transport: write frame: %w", err)
	}
	if c.isClosed() {
		return fmt.Errorf("%w: write frame", ErrClosed)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	first := !c.sentIntro
	c.sentIntro = true

	var msg []byte
	if first && len(c.hdr) > 0 {
		msg = make([]byte, 0, len(c.hdr)+frameHeaderLen+len(frame))
		msg = append(msg, c.hdr...)
	}
	n := len(frame)
	msg = append(msg, byte(n>>16), byte(n>>8), byte(n))
	msg = append(msg, frame...)

	if err := c.ws.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		if c.isClosed() {
			return fmt.Errorf("%w: write frame: %w", ErrClosed, err)
		}
		return fmt.Errorf("transport: write frame: %w", err)
	}
	return nil
}

// Close releases the connection. It is idempotent: calls after the first
// return nil. The teardown is best-effort — a WebSocket close message is
// sent with a short deadline, then the WebSocket and its underlying network
// connection are closed unconditionally. ReadFrame and WriteFrame return
// errors wrapping ErrClosed afterwards.
func (c *wsFrameConn) Close() error {
	c.closeMu.Lock()
	already := c.closed
	c.closeMu.Unlock()
	if already {
		return nil
	}
	c.shutdown()
	return nil
}

// shutdown tears the connection down exactly once: it marks the connection
// closed (which makes later FrameConn calls report ErrClosed), then
// best-effort sends a WebSocket close message and closes the WebSocket and
// its underlying net.Conn, which also unblocks any reader or writer parked on
// the socket.
func (c *wsFrameConn) shutdown() {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return
	}
	c.closed = true
	close(c.done)
	c.closeMu.Unlock()

	_ = c.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(closeWriteWait))
	_ = c.ws.Close()
	_ = c.ws.UnderlyingConn().Close()
}

// isClosed reports whether shutdown has been initiated locally.
func (c *wsFrameConn) isClosed() bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.closed
}

// startContextWatchdog shuts the connection down when ctx is done. It is
// used by WebSocketDialer.Dial to tie connections to their dial context.
// Watchdogs spawned by this method exit once shutdown has run (via done), so
// they do not leak when Close is called first.
func (c *wsFrameConn) startContextWatchdog(ctx context.Context) {
	if ctx == nil || ctx.Done() == nil {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			c.shutdown()
		case <-c.done:
		}
	}()
}

// cancelReadWatchdog unblocks a ReadFrame parked in the WebSocket read when
// its context is done: gorilla reads cannot be interrupted except by closing
// the connection, and a partially reassembled frame is unrecoverable (PF-003),
// so cancellation shuts the whole transport down. It exits once stop is
// closed (the read returned) or the context is done.
func (c *wsFrameConn) cancelReadWatchdog(ctx context.Context, stop <-chan struct{}) {
	select {
	case <-ctx.Done():
		c.shutdown()
	case <-stop:
	}
}
