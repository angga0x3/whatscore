package noise

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/angga0x3/whatscore/protocol/transport"
)

// secureConn implements SecureConn on top of a transport.FrameConn
// (PF-008): every frame payload received is a full AES-256-GCM
// ciphertext, and every payload written is sealed with the session write
// key. Framing itself (the PF-003 3-byte length prefix) stays with the
// transport; this type only transforms frame payloads.
type secureConn struct {
	fr transport.FrameConn

	writeKey  [32]byte
	readKey   [32]byte
	writeAEAD cipher.AEAD
	readAEAD  cipher.AEAD

	// writeCounter and readCounter are the independent per-direction
	// nonce counters, starting at 0 after the handshake (PF-008).
	//
	// They are uint32, matching the wire encoding: the nonce places the
	// counter as a big-endian uint32 in bytes 8-11 of the 12-byte IV
	// (same layout as the handshake IV, PF-005). After 2^32 frames in one
	// direction the counter wraps and IVs would repeat; real sessions
	// replace the connection long before that, mirroring the 32-bit
	// wraparound semantics of the reference implementations.
	writeCounter uint32
	readCounter  uint32

	writeMu   sync.Mutex // serializes writes; WriteFrame is atomic
	readMu    sync.Mutex // serializes reads
	closeOnce sync.Once
}

// newSecureConn builds a SecureConn from the handshake's final keys
// (PF-008): the owner writes with writeKey and reads with readKey (the
// server side swaps them).
func newSecureConn(fr transport.FrameConn, writeKey, readKey [32]byte) (*secureConn, error) {
	writeAEAD, err := newAEAD(writeKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: write key: %w", ErrHandshakeFailed, err)
	}
	readAEAD, err := newAEAD(readKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: read key: %w", ErrHandshakeFailed, err)
	}
	return &secureConn{
		fr:        fr,
		writeKey:  writeKey,
		readKey:   readKey,
		writeAEAD: writeAEAD,
		readAEAD:  readAEAD,
	}, nil
}

// ReadFrame reads one encrypted frame payload from the transport and
// opens it with the session read key: AES-256-GCM, nonce = counter IV
// (big-endian uint32 in bytes 8-11), empty AAD (PF-008). On success the
// read counter is incremented. A failed Open wraps ErrDecryptFailed and
// leaves the counter untouched; the caller must treat the connection as
// unusable after an authentication failure.
func (c *secureConn) ReadFrame(ctx context.Context) ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	ct, err := c.fr.ReadFrame(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := c.readAEAD.Open(nil, frameIV(c.readCounter), ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: transport frame %d failed authentication: %w", ErrDecryptFailed, c.readCounter, err)
	}
	c.readCounter++
	return pt, nil
}

// WriteFrame seals plaintext with the session write key (PF-008: same
// cipher, counter nonce, empty AAD) and writes exactly one ciphertext
// frame to the transport. On success the write counter is incremented.
// Concurrent writers are serialized; the frame is atomic at the transport.
func (c *secureConn) WriteFrame(ctx context.Context, plaintext []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	ct := c.writeAEAD.Seal(nil, frameIV(c.writeCounter), plaintext, nil)
	c.writeCounter++
	return c.fr.WriteFrame(ctx, ct)
}

// Close closes the underlying transport. It is idempotent; the first
// call's error is returned and repeated calls return nil.
func (c *secureConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.fr.Close()
	})
	return err
}

// CipherSuiteName returns the negotiated suite (PF-004).
func (c *secureConn) CipherSuiteName() string {
	return CipherSuite
}

// frameIV builds the 12-byte transport nonce (PF-008): bytes 0-7 zero,
// bytes 8-11 the big-endian frame counter. The counter is uint32, so it
// wraps at 2^32 exactly like the reference implementations (see
// secureConn's counter field documentation).
func frameIV(counter uint32) []byte {
	iv := make([]byte, 12)
	binary.BigEndian.PutUint32(iv[8:12], counter)
	return iv
}
