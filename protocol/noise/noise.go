// Package noise implements the client side of WhatsApp transport
// encryption: a Noise_XX_25519_AESGCM_SHA256 handshake (see
// https://noiseprotocol.org/noise.html) carried over transport frames,
// followed by AEAD-encrypted frame exchange.
//
// The handshake deviates from the standard Noise cipherstate: the
// handshake AEAD key is derived from the running hash rather than a
// MixKey chain. All algorithm-internal behavior is recorded in
// docs/protocol/noise.md as findings PF-004..PF-009 and proven by
// deterministic vector tests generated from the finding text (see
// tests/fixtures/generate_noise_vectors.py).
//
// Noise secures the transport only. End-to-end message encryption is
// Signal (protocol/signal, Phase 4). The two layers must never share key
// material.
//
// Package layout:
//   - state.go: KeyPair/GenerateKeyPair and the Handshake state machine
//     (PF-004, PF-005, PF-006, PF-008)
//   - client.go: DoClientHandshake orchestrator (PF-007)
//   - conn.go: secureConn, the SecureConn implementation (PF-008)
//   - cert.go: server certificate chain verification (PF-009)
//
// Status: Phase 1 implementation, proven by protocol/noise tests.
package noise

import (
	"context"
	"errors"
	"fmt"

	"github.com/angga0x3/whatscore/protocol/transport"
)

// CipherSuite is the canonical name of the only suite this package
// implements (PF-004: protocol name "Noise_XX_25519_AESGCM_SHA256",
// zero-padded to 32 bytes for the handshake hash chain).
const CipherSuite = "Noise_XX_25519_AESGCM_SHA256"

// SecureConn is a FrameConn whose frames are encrypted and authenticated
// with the session keys established by a completed handshake (PF-008:
// per-direction AES-256-GCM keys and counters, empty AAD).
type SecureConn interface {
	transport.FrameConn

	// CipherSuiteName returns the negotiated suite
	// ("Noise_XX_25519_AESGCM_SHA256"), for logging and diagnostics.
	CipherSuiteName() string
}

// Handshaker performs the client role of the Noise handshake (PF-007).
type Handshaker interface {
	// Handshake consumes handshake frames from fr and produces handshake
	// frames on fr, then returns a SecureConn. On failure the
	// implementation must close fr before returning the error.
	Handshake(ctx context.Context, fr transport.FrameConn) (SecureConn, error)
}

// Sentinel errors for the noise layer
// (docs/architecture/technical-specification.md §8.1). Callers match with
// errors.Is; every returned error wraps one of these with %w plus context.
var (
	// ErrHandshakeFailed is returned when the handshake cannot be
	// completed: I/O failure on a handshake frame, a malformed or missing
	// handshake message, a failed DH operation, or a failed certificate
	// verification.
	ErrHandshakeFailed = errors.New("noise: handshake failed")

	// ErrDecryptFailed is returned when an AES-256-GCM Open fails, either
	// inside the handshake (PF-005) or on a post-handshake transport frame
	// (PF-008). Decryption failures abort the handshake.
	ErrDecryptFailed = errors.New("noise: decrypt failed")

	// ErrBadPayload is returned when a decrypted payload is present but
	// cannot be parsed as the expected protobuf message (PF-009
	// certificate chain).
	ErrBadPayload = errors.New("noise: bad payload")
)

// ErrInvalidServerHello is wrapped around ErrHandshakeFailed and returned
// by DoClientHandshake when the msg2 serverHello violates the message
// contract of PF-007 (missing message, wrong field lengths, missing
// static/payload fields).
var ErrInvalidServerHello = fmt.Errorf("%w: invalid server hello", ErrHandshakeFailed)

// ErrCertificateInvalid is wrapped by every *CertError returned from
// VerifyServerCert (PF-009).
var ErrCertificateInvalid = errors.New("noise: server certificate invalid")
