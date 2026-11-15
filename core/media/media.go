// Package media orchestrates the encrypted-media byte envelope: it generates
// the per-upload media key, derives keys with protocol/media, encrypts or
// decrypts the payload, and carries the companion hashes that travel beside
// the bytes in the message protobuf (PF-040..PF-045).
//
// Keys stay inside this package's calls: callers hand over plaintext and get
// a descriptor plus an encrypted blob, never key material. Descriptor
// metadata that is not covered by the envelope (file name, MIME type,
// dimensions, duration, direct path, URL) is filled by the caller around the
// upload/download; only MediaKey, MediaType and the hashes are load-bearing
// for decryption.
//
// The sidecar SHA-256 values are corroboration, not authentication: an
// attacker can recompute them over a mangled blob. The truncated HMAC inside
// the envelope is the authenticator (PF-043), so a changed MediaKey or
// MediaType fails closed even when the descriptor hashes match.
package media

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	protocolmedia "github.com/angga0x3/whatscore/protocol/media"
)

// MaxMediaSize is the largest payload, in bytes, this package will process.
// The cap is checked before any key derivation, hashing or encryption so a
// hostile descriptor cannot drive unbounded work.
const MaxMediaSize = 64 << 20 // 64 MiB

// maxEnvelopeOverhead bounds how much the envelope adds to a payload: one
// PKCS#7 padding block plus the truncated MAC (PF-042, PF-043). An encrypted
// blob longer than MaxMediaSize plus this overhead cannot decrypt to a
// permitted plaintext.
const maxEnvelopeOverhead = 16 + protocolmedia.MACSize

// Sentinel errors (docs/architecture/technical-specification.md §8.1).
// Callers match with errors.Is; every returned error wraps one of these
// with %w, or the protocol/media sentinel it originates from.
var (
	// ErrInvalidDescriptor is returned when a descriptor cannot be used:
	// nil, a negative or inconsistent size, or a media type outside the
	// PF-041 table.
	ErrInvalidDescriptor = errors.New("core/media: invalid descriptor")

	// ErrHashMismatch is returned when an integrity check fails: either
	// sidecar SHA-256 disagrees with the bytes, or the envelope MAC does
	// not verify under the descriptor's media key and media type.
	ErrHashMismatch = errors.New("core/media: hash mismatch")

	// ErrPayloadTooLarge is returned when the plaintext, or the encrypted
	// blob the descriptor implies, exceeds MaxMediaSize.
	ErrPayloadTooLarge = errors.New("core/media: payload too large")
)

// Descriptor is the metadata that accompanies an encrypted media blob. The
// key and hashes are produced by Encrypt; FileName is supplied by the caller
// and the remaining fields are filled in around transport (MimeType,
// Width, Height, Seconds, DirectPath, URL).
type Descriptor struct {
	// MediaKey is the random 32-byte key the envelope is derived from
	// (PF-045). It is secret and must never leave the session.
	MediaKey [32]byte
	// MediaType is the HKDF info string, one of the protocol/media Type*
	// constants (PF-041).
	MediaType string
	// FileName is the caller-visible name of the media object.
	FileName string
	// MimeType is the payload's MIME type as reported to the recipient.
	MimeType string
	// Size is the plaintext length in bytes.
	Size int
	// SHA256 is SHA-256(plaintext) (PF-045).
	SHA256 [32]byte
	// EncSHA256 is SHA-256(ciphertext ‖ mac), i.e. the hash of the
	// encrypted blob as transmitted (PF-045).
	EncSHA256 [32]byte
	// Width, Height and Seconds describe audio/video payloads and are
	// zero for other media.
	Width   uint32
	Height  uint32
	Seconds uint32
	// DirectPath and URL are the transport hints returned by the upload.
	DirectPath string
	URL        string
}

// Encrypt generates a fresh media key, derives its key set, encrypts
// plaintext, and returns the descriptor plus the encrypted blob
// (ciphertext ‖ mac, PF-043).
//
// mediaType must be one of the protocol/media Type* constants; anything else
// returns that package's ErrUnknownMediaType. MimeType, Width, Height,
// Seconds, DirectPath and URL are left zero and belong to the caller.
func Encrypt(plaintext []byte, mediaType, fileName string) (*Descriptor, []byte, error) {
	if len(plaintext) > MaxMediaSize {
		return nil, nil, fmt.Errorf("%w: %d bytes exceeds %d", ErrPayloadTooLarge, len(plaintext), MaxMediaSize)
	}

	var mediaKey [32]byte
	if _, err := rand.Read(mediaKey[:]); err != nil {
		return nil, nil, fmt.Errorf("core/media: media key: %w", err)
	}
	keys, err := protocolmedia.DeriveKeys(mediaKey, mediaType, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("core/media: encrypt: %w", err)
	}
	encrypted, err := protocolmedia.Encrypt(plaintext, keys)
	if err != nil {
		return nil, nil, fmt.Errorf("core/media: encrypt: %w", err)
	}

	d := &Descriptor{
		MediaKey:  mediaKey,
		MediaType: mediaType,
		FileName:  fileName,
		Size:      len(plaintext),
		SHA256:    sha256.Sum256(plaintext),
		EncSHA256: sha256.Sum256(encrypted),
	}
	return d, encrypted, nil
}

// Decrypt verifies and decrypts one blob produced by Encrypt. The descriptor
// supplies the media key and media type; the payload is authenticated by the
// envelope MAC and cross-checked against both sidecar hashes (PF-044).
//
// Verification order: descriptor validity, size policy, EncSHA256 over the
// blob, envelope MAC and padding, plaintext length, SHA256 over the
// plaintext. A blob that fails the envelope MAC surfaces as ErrHashMismatch
// because that is the descriptor-dependent check; a structurally malformed
// but self-consistent blob surfaces the protocol/media error for bad
// ciphertext. Decrypt never modifies encrypted, and the returned plaintext is
// freshly allocated.
func Decrypt(encrypted []byte, d *Descriptor) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: nil", ErrInvalidDescriptor)
	}
	if d.Size < 0 {
		return nil, fmt.Errorf("%w: negative size %d", ErrInvalidDescriptor, d.Size)
	}
	if d.Size > MaxMediaSize {
		return nil, fmt.Errorf("%w: descriptor size %d exceeds %d", ErrPayloadTooLarge, d.Size, MaxMediaSize)
	}
	if len(encrypted) > MaxMediaSize+maxEnvelopeOverhead {
		return nil, fmt.Errorf("%w: %d encrypted bytes exceeds %d", ErrPayloadTooLarge,
			len(encrypted), MaxMediaSize+maxEnvelopeOverhead)
	}

	keys, err := protocolmedia.DeriveKeys(d.MediaKey, d.MediaType, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDescriptor, err)
	}

	if sum := sha256.Sum256(encrypted); subtle.ConstantTimeCompare(sum[:], d.EncSHA256[:]) != 1 {
		return nil, fmt.Errorf("%w: encrypted blob does not match EncSHA256", ErrHashMismatch)
	}

	plaintext, err := protocolmedia.Decrypt(encrypted, keys)
	if err != nil {
		if errors.Is(err, protocolmedia.ErrBadMAC) {
			return nil, fmt.Errorf("%w: %w", ErrHashMismatch, err)
		}
		return nil, fmt.Errorf("core/media: decrypt: %w", err)
	}

	if len(plaintext) != d.Size {
		return nil, fmt.Errorf("%w: plaintext is %d bytes, descriptor says %d", ErrInvalidDescriptor, len(plaintext), d.Size)
	}
	if sum := sha256.Sum256(plaintext); subtle.ConstantTimeCompare(sum[:], d.SHA256[:]) != 1 {
		return nil, fmt.Errorf("%w: plaintext does not match SHA256", ErrHashMismatch)
	}
	return plaintext, nil
}
