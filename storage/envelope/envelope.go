// Package envelope encrypts credential blobs at rest with AES-256-GCM.
//
// The key is parsed from the base64-encoded ENCRYPTION_KEY (32 bytes). Every
// record gets a random 96-bit nonce, and the caller binds the ciphertext to
// its record with associated data. Format:
//
//	version(1) || nonce(12) || ciphertext || tag(16)
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	// Version is the current envelope format version.
	Version byte = 1
	// KeySize is the AES-256 key length.
	KeySize = 32
	// NonceSize is the GCM nonce length.
	NonceSize = 12
	// HeaderSize is version plus nonce.
	HeaderSize = 1 + NonceSize
	// TagSize is the GCM authentication tag length.
	TagSize = 16
)

// Sentinel errors.
var (
	ErrInvalidKey      = errors.New("envelope: invalid key")
	ErrInvalidEnvelope = errors.New("envelope: invalid envelope")
	ErrDecryptFailed   = errors.New("envelope: decrypt failed")
)

// Key is a 256-bit encryption key. It has no String or MarshalJSON method.
type Key struct {
	material [32]byte
}

// NewKey copies a raw 32-byte key.
func NewKey(raw []byte) (*Key, error) {
	if len(raw) != KeySize {
		return nil, fmt.Errorf("%w: key is %d bytes, want %d", ErrInvalidKey, len(raw), KeySize)
	}
	key := &Key{}
	copy(key.material[:], raw)
	return key, nil
}

// ParseKey decodes a base64 key (standard alphabet, with or without
// padding), as produced by `openssl rand -base64 32`.
func ParseKey(encoded string) (*Key, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidKey)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: not base64: %w", ErrInvalidKey, err)
	}
	return NewKey(raw)
}

// Clear zeroes the key material. The Key must not be used afterwards.
func (k *Key) Clear() {
	for i := range k.material {
		k.material[i] = 0
	}
}

// Seal encrypts plaintext and binds it to aad.
func (k *Key) Seal(plaintext, aad []byte) ([]byte, error) {
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("envelope: nonce: %w", err)
	}
	out := make([]byte, 0, HeaderSize+len(plaintext)+TagSize)
	out = append(out, Version)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, aad)
	return out, nil
}

// Open decrypts a sealed record and verifies that aad matches.
func (k *Key) Open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < HeaderSize+TagSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrInvalidEnvelope, len(sealed))
	}
	if sealed[0] != Version {
		return nil, fmt.Errorf("%w: version %d", ErrInvalidEnvelope, sealed[0])
	}
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, sealed[1:HeaderSize], sealed[HeaderSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}
	return plaintext, nil
}

func (k *Key) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.material[:])
	if err != nil {
		return nil, fmt.Errorf("envelope: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: gcm: %w", err)
	}
	return aead, nil
}
