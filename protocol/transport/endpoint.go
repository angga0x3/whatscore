package transport

import "time"

// IntroHeader is the one-time connection intro header a client sends before
// any frame data: [0x57 0x41 0x06 0x03] — the ASCII bytes "WA" (0x57 0x41)
// followed by the magic value 0x06 and the token dictionary version 0x03
// (PF-003).
//
// It is sent exactly once per connection, prefixed to the payload of the
// FIRST frame write so that the header, the frame length prefix, and the
// payload travel together in a single WebSocket binary message. NewWebSocketConn
// copies the header it is given, so later mutation of this slice does not
// affect established connections.
//
// Provenance: PF-003 (Probable / Observed-only) — identical constants in
// whatsmeow (WAConnHeader) and Baileys (NOISE_WA_HEADER with DICT_VERSION 3);
// live-server confirmation pending.
var IntroHeader = []byte{0x57, 0x41, 0x06, 0x03}

// FrameMaxSize is the maximum frame payload size in bytes: 2^24 (PF-003).
//
// Frame lengths are carried in a 24-bit big-endian prefix, so payloads of
// FrameMaxSize bytes and larger cannot be encoded; WriteFrame rejects them
// with ErrFrameTooLarge and ReadFrame rejects oversized peer frames the same
// way (matching whatsmeow, which forces a close on oversized reads).
//
// Provenance: PF-003 (Probable / Observed-only).
const FrameMaxSize = 1 << 24

// DefaultURL is the default WebSocket endpoint of the WhatsApp web client:
// wss://web.whatsapp.com/ws/chat (PF-002).
//
// Provenance: PF-002 (Probable / Observed-only) — identical constants in
// whatsmeow (socket/framesocket.go) and Baileys (src/Socket/socket.ts) as of
// 2026-11-15; live-server confirmation is pending manual interop, so this
// value may still change.
const DefaultURL = "wss://web.whatsapp.com/ws/chat"

// DefaultHandshakeTimeout is the handshake timeout applied by DefaultEndpoint
// (15 seconds).
const DefaultHandshakeTimeout = 15 * time.Second

// DefaultEndpoint returns the endpoint used to reach the WhatsApp web
// WebSocket service: DefaultURL, a 15 second handshake timeout, and the dial
// headers observed on the WhatsApp web client (PF-002):
//
//	Origin: https://web.whatsapp.com
//	Cache-Control: no-cache
//	Pragma: no-cache
//
// The returned Endpoint is a fresh value with a fresh headers map on every
// call; callers may mutate both freely (e.g. to swap the URL for tests).
//
// Provenance: PF-002 (Probable / Observed-only) — live-server confirmation
// pending; see DefaultURL for the caveat.
func DefaultEndpoint() Endpoint {
	return Endpoint{
		URL:              DefaultURL,
		HandshakeTimeout: DefaultHandshakeTimeout,
		ExtraHeaders: map[string]string{
			"Origin":        "https://web.whatsapp.com",
			"Cache-Control": "no-cache",
			"Pragma":        "no-cache",
		},
	}
}
