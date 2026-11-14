// Package noise implements the client side of WhatsApp transport
// encryption: a Noise_XX_25519_AESGCM_SHA256 handshake (see
// https://noiseprotocol.org/noise.html) carried over transport frames,
// followed by AEAD-encrypted frame exchange.
//
// Noise secures the transport only. End-to-end message encryption is
// Signal (protocol/signal, Phase 4). The two layers must never share key
// material.
//
// Protocol specifics (frame headers, key roles, server certificate
// verification) are recorded in docs/protocol with provenance and must be
// proven by tests in tests/protocol before this package leaves draft
// status.
//
// Status: contract skeleton (Phase 1 implements it).
package noise

import (
	"context"

	"github.com/angga0x3/whatscore/protocol/transport"
)

// SecureConn is a FrameConn whose frames are encrypted and authenticated
// with the session keys established by a completed handshake.
type SecureConn interface {
	transport.FrameConn

	// CipherSuiteName returns the negotiated suite, e.g.
	// "Noise_XX_25519_AESGCM_SHA256", for logging and diagnostics.
	CipherSuiteName() string
}

// Handshaker performs the client role of the Noise handshake.
type Handshaker interface {
	// Handshake consumes handshake frames from fr and produces handshake
	// frames on fr, then returns a SecureConn. On failure the
	// implementation must close fr before returning the error.
	Handshake(ctx context.Context, fr transport.FrameConn) (SecureConn, error)
}
