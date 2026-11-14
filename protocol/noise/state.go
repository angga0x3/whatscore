package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// noiseProtocolName is the Noise protocol name per PF-004: the 28 ASCII
// characters of "Noise_XX_25519_AESGCM_SHA256" followed by four NUL bytes,
// used RAW as the initial hash h0 (not hashed again), matching the Noise
// spec rule of zero-padding a protocol name shorter than 32 bytes.
//
// Provenance: docs/protocol/noise.md PF-004 (whatsmeow NoiseStartPattern,
// Baileys NOISE_MODE — identical in both references).
var noiseProtocolName = []byte("Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00")

// KeyPair is a Curve25519 (X25519, RFC 7748) key pair.
type KeyPair struct {
	// Priv is the clamped X25519 scalar (little-endian).
	Priv [32]byte

	// Pub is the public key X25519(Priv, basepoint).
	Pub [32]byte
}

// GenerateKeyPair returns a fresh Curve25519 key pair drawn from
// crypto/rand. The scalar is clamped per RFC 7748 §5 (priv[0]&=248;
// priv[31]&=127; priv[31]|=64) and the public key is
// X25519(priv, basepoint).
func GenerateKeyPair() (KeyPair, error) {
	var kp KeyPair
	if _, err := rand.Read(kp.Priv[:]); err != nil {
		return KeyPair{}, fmt.Errorf("noise: reading key material: %w", err)
	}
	clampScalar(&kp.Priv)
	pub, err := curve25519.X25519(kp.Priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("noise: deriving public key: %w", err)
	}
	copy(kp.Pub[:], pub)
	return kp, nil
}

// clampScalar applies the RFC 7748 X25519 scalar clamping in place.
func clampScalar(s *[32]byte) {
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
}

// Handshake is the WhatsApp Noise-mode handshake state machine
// (docs/protocol/noise.md PF-004..PF-006, PF-008). It is not safe for
// concurrent use; each connection runs exactly one instance.
//
// The handshake AEAD key is a single symmetric key shared by both peers
// (unlike standard Noise cipherstates): encrypt and decrypt use the same
// key and one shared operation counter (PF-005), because each handshake
// message carries at most one AEAD-protected field per peer turn.
type Handshake struct {
	// hash is the running hash chain h = SHA256(h ‖ data) over the conn
	// header, both ephemerals, and every handshake ciphertext (PF-004).
	hash [32]byte

	// salt is the current HKDF salt for key mixing (PF-006); it starts as
	// h0 and is replaced by the write half after every MixIntoKey.
	salt [32]byte

	// key is the current handshake AEAD key, AES-256-GCM (PF-005). It
	// starts as AES-256-GCM(h0).
	key cipher.AEAD

	// counter is the shared handshake encrypt/decrypt nonce counter
	// (PF-005); it resets to 0 on every MixIntoKey.
	counter uint32

	// err is a sticky initialization error from Start; surfaced by the
	// first operation that needs the AEAD.
	err error
}

// NewHandshake returns a zeroed handshake state machine. Call Start
// before any other method.
func NewHandshake() *Handshake {
	return &Handshake{}
}

// Start initializes the handshake (PF-004): the running hash is set to
// the raw 32-byte protocol name, the header (connection header sent by
// the transport before any frame) is authenticated into the chain, the
// HKDF salt is set to the protocol name, and the handshake AEAD key is
// AES-256-GCM over the same 32 bytes. The operation counter starts at 0.
func (h *Handshake) Start(header []byte) {
	var h0 [32]byte
	copy(h0[:], noiseProtocolName) // raw 32 bytes, never re-hashed (PF-004)
	h.hash = h0
	h.Authenticate(header)
	h.salt = h0
	h.key, h.err = newAEAD(h0[:])
	h.counter = 0
}

// Authenticate folds data into the running hash chain:
// hash = SHA256(hash ‖ data) (PF-004). The chain covers, in order, the
// connection header, the client ephemeral, the server ephemeral, and
// every handshake ciphertext.
func (h *Handshake) Authenticate(data []byte) {
	buf := make([]byte, 0, len(h.hash)+len(data))
	buf = append(buf, h.hash[:]...)
	buf = append(buf, data...)
	h.hash = sha256.Sum256(buf)
}

// Encrypt seals plaintext with the current handshake key (PF-005):
// AES-256-GCM, nonce = 12 bytes with bytes 0-7 zero and bytes 8-11 the
// big-endian operation counter, AAD = the current running hash. On
// success the ciphertext is authenticated into the hash chain (PF-004)
// and the shared counter is incremented.
func (h *Handshake) Encrypt(plaintext []byte) ([]byte, error) {
	if h.err != nil || h.key == nil {
		return nil, fmt.Errorf("%w: handshake state not initialized: %w", ErrHandshakeFailed, initStateErr(h.err))
	}
	ct := h.key.Seal(nil, handshakeIV(h.counter), plaintext, h.hash[:])
	h.Authenticate(ct)
	h.counter++
	return ct, nil
}

// Decrypt opens ciphertext sealed per Encrypt's conventions (PF-005):
// same key, counter-derived nonce, AAD = current running hash. On success
// the ciphertext is authenticated into the hash chain (PF-004) and the
// shared counter is incremented. A failed Open leaves the state untouched
// and returns an error wrapping ErrDecryptFailed; decryption failures
// abort the handshake.
func (h *Handshake) Decrypt(ciphertext []byte) ([]byte, error) {
	if h.err != nil || h.key == nil {
		return nil, fmt.Errorf("%w: handshake state not initialized: %w", ErrHandshakeFailed, initStateErr(h.err))
	}
	pt, err := h.key.Open(nil, handshakeIV(h.counter), ciphertext, h.hash[:])
	if err != nil {
		return nil, fmt.Errorf("%w: handshake AEAD open failed at counter %d: %w", ErrDecryptFailed, h.counter, err)
	}
	h.Authenticate(ciphertext)
	h.counter++
	return pt, nil
}

// MixSharedSecretIntoKey performs a DH step (PF-006): it computes
// d = X25519(priv, pub) and feeds d through MixIntoKey.
func (h *Handshake) MixSharedSecretIntoKey(priv, pub [32]byte) error {
	d, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return fmt.Errorf("%w: x25519: %w", ErrHandshakeFailed, err)
	}
	return h.MixIntoKey(d)
}

// MixIntoKey rotates the handshake key material (PF-006):
// (write, read) = HKDF-SHA256(ikm=dhSecret, salt=current salt, info=∅,
// L=64); the salt becomes write, the handshake key becomes
// AES-256-GCM(read), and the operation counter resets to 0. The write
// half is consumed as the next salt; both halves are only revealed again
// through the final Finish call.
func (h *Handshake) MixIntoKey(dhSecret []byte) error {
	write, read, err := hkdfSHA256(dhSecret, h.salt[:])
	if err != nil {
		return err
	}
	key, err := newAEAD(read[:])
	if err != nil {
		return fmt.Errorf("%w: handshake key: %w", ErrHandshakeFailed, err)
	}
	h.salt = write
	h.key = key
	h.counter = 0
	return nil
}

// Finish derives the final transport keys (PF-008):
// (write, read) = HKDF-SHA256(ikm=∅, salt=current salt, info=∅, L=64).
// The client writes with write and reads with read; the server swaps
// them. It does not mutate the handshake state.
func (h *Handshake) Finish() (writeKey [32]byte, readKey [32]byte, err error) {
	if h.err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%w: handshake state not initialized: %w", ErrHandshakeFailed, h.err)
	}
	write, read, err := hkdfSHA256(nil, h.salt[:])
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	return write, read, nil
}

// hkdfSHA256 runs HKDF-SHA256 (RFC 5869) with the given ikm and salt and
// empty info, returning the first 64 output bytes as two 32-byte blocks:
// first = write/salt, second = read/key (PF-006, PF-008 — output order
// confirmed identical in both reference implementations).
func hkdfSHA256(ikm, salt []byte) ([32]byte, [32]byte, error) {
	var write, read [32]byte
	r := hkdf.New(sha256.New, ikm, salt, nil)
	var out [64]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return write, read, fmt.Errorf("%w: hkdf-sha256: %w", ErrHandshakeFailed, err)
	}
	copy(write[:], out[:32])
	copy(read[:], out[32:])
	return write, read, nil
}

// handshakeIV builds the 12-byte handshake nonce (PF-005): bytes 0-7 are
// zero and bytes 8-11 hold the big-endian operation counter.
func handshakeIV(counter uint32) []byte {
	iv := make([]byte, 12)
	binary.BigEndian.PutUint32(iv[8:12], counter)
	return iv
}

// initStateErr normalizes the sticky-state error for callers that used a
// Handshake before Start (or after a failed Start).
func initStateErr(sticky error) error {
	if sticky != nil {
		return sticky
	}
	return fmt.Errorf("missing Start call")
}

// newAEAD constructs an AES-256-GCM AEAD for a 32-byte key (PF-005,
// PF-008).
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("noise: aes-256: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("noise: aes-256-gcm: %w", err)
	}
	return aead, nil
}
