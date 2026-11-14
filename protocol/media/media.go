// Package media implements the WhatsApp media encryption envelope:
// HKDF-SHA256 media-key expansion, AES-256-CBC payload encryption with
// PKCS#7 padding, and a truncated HMAC-SHA256 integrity tag.
//
// The wire format is recorded in docs/protocol/media.md as findings
// PF-040..PF-045, cross-validated against two independent reference
// implementations. This package uses the standard library only and performs
// no I/O: media bytes move over injected transport interfaces in other
// packages.
//
// Layout produced by Encrypt and consumed by Decrypt:
//
//	ciphertext ‖ mac[10]
//
// where ciphertext is AES-256-CBC(plaintext padded to a 16-byte multiple)
// and mac is HMAC-SHA256(macKey, iv ‖ ciphertext) truncated to its first
// 10 bytes (PF-043). The IV travels out of band: it is the first 16 bytes
// of the expanded media key, never prepended to the payload (PF-040).
package media

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	// MediaKeySize is the size in bytes of the random per-upload media key
	// (PF-041).
	MediaKeySize = 32

	// ExpandedKeySize is the HKDF-Expand output length used by both
	// reference implementations; the first 80 bytes carry the IV, cipher
	// key and MAC key, the last 32 are unused by the upload/download path
	// (PF-040, PF-045).
	ExpandedKeySize = 112

	// IVSize is the AES-CBC initialization vector length (PF-040).
	IVSize = 16

	// CipherKeySize is the AES-256 key length (PF-040).
	CipherKeySize = 32

	// MACKeySize is the HMAC-SHA256 key length (PF-040).
	MACKeySize = 32

	// MACSize is the truncated HMAC length appended to the ciphertext
	// (PF-043).
	MACSize = 10
)

// Media types are the HKDF info strings of the supported media classes
// (PF-041). The value is used verbatim as the HKDF info; only the exact
// strings below are accepted, so a typo fails closed instead of silently
// deriving a different key set.
const (
	// TypeImage covers images, stickers and product images; both
	// references map those message classes to "Image".
	TypeImage = "WhatsApp Image Keys"
	// TypeVideo covers videos, GIFs and video notes.
	TypeVideo = "WhatsApp Video Keys"
	// TypeAudio covers audio files and voice notes.
	TypeAudio = "WhatsApp Audio Keys"
	// TypeDocument covers documents.
	TypeDocument = "WhatsApp Document Keys"
	// TypeHistory covers history-sync blobs.
	TypeHistory = "WhatsApp History Keys"
	// TypeAppState covers app-state (sync) blobs.
	TypeAppState = "WhatsApp App State Keys"

	// TypeStickerPack is observed in whatsmeow only; sticker images
	// themselves use TypeImage.
	TypeStickerPack = "WhatsApp Sticker Pack Keys"
	// TypeLinkThumbnail is observed in whatsmeow only.
	TypeLinkThumbnail = "WhatsApp Link Thumbnail Keys"
	// TypeImageThumbnail, TypeVideoThumbnail and TypeDocumentThumbnail are
	// observed in Baileys only.
	TypeImageThumbnail    = "WhatsApp Image Thumbnail Keys"
	TypeVideoThumbnail    = "WhatsApp Video Thumbnail Keys"
	TypeDocumentThumbnail = "WhatsApp Document Thumbnail Keys"
	// TypePaymentBackground is observed in Baileys only.
	TypePaymentBackground = "WhatsApp Payment Background Keys"
)

// supportedMediaTypes is the set of HKDF info strings this package accepts
// (PF-041). Unknown strings are rejected rather than expanded, because both
// references treat the media type as an opaque string and a mistyped value
// would silently produce undecryptable output.
var supportedMediaTypes = map[string]struct{}{
	TypeImage:             {},
	TypeVideo:             {},
	TypeAudio:             {},
	TypeDocument:          {},
	TypeHistory:           {},
	TypeAppState:          {},
	TypeStickerPack:       {},
	TypeLinkThumbnail:     {},
	TypeImageThumbnail:    {},
	TypeVideoThumbnail:    {},
	TypeDocumentThumbnail: {},
	TypePaymentBackground: {},
}

// Sentinel errors (docs/architecture/technical-specification.md §8.1).
// Callers match with errors.Is; every returned error wraps one of these
// with %w plus context.
var (
	// ErrInvalidKey is returned when the media key cannot be expanded:
	// a requested expansion length below the 80 bytes the key set needs
	// (or beyond the HKDF limit), or an unusable cipher key. A wrong but
	// well-formed media key is not invalid; it surfaces as ErrBadMAC on
	// decryption.
	ErrInvalidKey = errors.New("media: invalid key")

	// ErrUnknownMediaType is returned by DeriveKeys when the media type is
	// not one of the documented HKDF info strings (PF-041).
	ErrUnknownMediaType = errors.New("media: unknown media type")

	// ErrInvalidCiphertext is returned when the encrypted blob is too
	// short to hold a ciphertext block and a MAC, is not a multiple of the
	// AES block size, or carries invalid PKCS#7 padding. Padding errors
	// imply an authentic-but-malformed blob: the MAC is always verified
	// first.
	ErrInvalidCiphertext = errors.New("media: invalid ciphertext")

	// ErrBadMAC is returned when the truncated HMAC does not match, i.e.
	// the ciphertext was tampered with or the key set is wrong.
	ErrBadMAC = errors.New("media: bad MAC")
)

// Keys is one derived media key set (PF-040): the IV and AES-256 key used
// for CBC, plus the HMAC-SHA256 key for the integrity tag. The fields are
// fixed-size so a short or truncated key cannot be used by accident.
type Keys struct {
	IV        [IVSize]byte
	CipherKey [CipherKeySize]byte
	MACKey    [MACKeySize]byte
}

// DeriveKeys expands a 32-byte media key into its IV, cipher key and MAC
// key (PF-040):
//
//	expanded = HKDF-SHA256(ikm=mediaKey, salt=nil, info=mediaType, L=length)
//	iv       = expanded[0:16]
//	cipherKey= expanded[16:48]
//	macKey   = expanded[48:80]
//
// length is the HKDF-Expand output length; 0 selects ExpandedKeySize
// (112), the value both references use. Any length in [80, 8160] is
// accepted, but bytes beyond 80 are unused and do not change the returned
// key set. mediaType must be one of the Type* constants; other values
// return ErrUnknownMediaType. An out-of-range length returns ErrInvalidKey.
func DeriveKeys(mediaKey [MediaKeySize]byte, mediaType string, length int) (Keys, error) {
	if _, ok := supportedMediaTypes[mediaType]; !ok {
		return Keys{}, fmt.Errorf("%w: %q", ErrUnknownMediaType, mediaType)
	}
	if length == 0 {
		length = ExpandedKeySize
	}
	if length < IVSize+CipherKeySize+MACKeySize {
		return Keys{}, fmt.Errorf("%w: expansion length %d is below the %d bytes a key set needs",
			ErrInvalidKey, length, IVSize+CipherKeySize+MACKeySize)
	}

	expanded, err := hkdf.Key(sha256.New, mediaKey[:], nil, mediaType, length)
	if err != nil {
		return Keys{}, fmt.Errorf("%w: hkdf: %w", ErrInvalidKey, err)
	}

	var keys Keys
	copy(keys.IV[:], expanded[:IVSize])
	copy(keys.CipherKey[:], expanded[IVSize:IVSize+CipherKeySize])
	copy(keys.MACKey[:], expanded[IVSize+CipherKeySize:IVSize+CipherKeySize+MACKeySize])
	return keys, nil
}

// Encrypt pads plaintext with PKCS#7, encrypts it with AES-256-CBC under
// keys.CipherKey and keys.IV, and appends the truncated MAC (PF-042,
// PF-043):
//
//	out = AES-256-CBC(pad(plaintext)) ‖ HMAC-SHA256(keys.MACKey, keys.IV ‖ ciphertext)[:10]
//
// Padding is always added, so an empty plaintext produces one 16-byte
// block and a 26-byte result. The returned slice is freshly allocated;
// plaintext is not modified.
func Encrypt(plaintext []byte, keys Keys) ([]byte, error) {
	block, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: aes: %w", ErrInvalidKey, err)
	}

	padded := pad(plaintext)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, keys.IV[:]).CryptBlocks(ciphertext, padded)

	out := make([]byte, len(ciphertext)+MACSize)
	copy(out, ciphertext)
	copy(out[len(ciphertext):], mac(keys, ciphertext))
	return out, nil
}

// Decrypt verifies the truncated MAC and then decrypts one blob produced
// by Encrypt (PF-043, PF-044). The final 10 bytes are the MAC; the MAC is
// compared in constant time before any CBC decryption or padding handling.
//
// A blob shorter than one padded block plus the MAC (26 bytes), a
// ciphertext that is not a multiple of 16 bytes, or invalid PKCS#7 padding
// returns ErrInvalidCiphertext; a MAC mismatch returns ErrBadMAC.
func Decrypt(ciphertext []byte, keys Keys) ([]byte, error) {
	if len(ciphertext) < MACSize+aes.BlockSize {
		return nil, fmt.Errorf("%w: %d bytes, need at least %d", ErrInvalidCiphertext, len(ciphertext), MACSize+aes.BlockSize)
	}
	body, tag := ciphertext[:len(ciphertext)-MACSize], ciphertext[len(ciphertext)-MACSize:]
	if len(body)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext length %d is not a multiple of %d", ErrInvalidCiphertext, len(body), aes.BlockSize)
	}
	if !hmac.Equal(mac(keys, body), tag) {
		return nil, ErrBadMAC
	}

	block, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: aes: %w", ErrInvalidKey, err)
	}
	plaintext := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, keys.IV[:]).CryptBlocks(plaintext, body)
	return unpad(plaintext)
}

// mac computes HMAC-SHA256(macKey, iv ‖ ciphertext) truncated to MACSize
// (PF-043). The IV is authenticated even though it is not transmitted with
// the payload.
func mac(keys Keys, ciphertext []byte) []byte {
	h := hmac.New(sha256.New, keys.MACKey[:])
	h.Write(keys.IV[:])
	h.Write(ciphertext)
	return h.Sum(nil)[:MACSize]
}

// pad applies PKCS#7 padding, always adding between 1 and 16 bytes
// (PF-042).
func pad(plaintext []byte) []byte {
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// unpad removes and validates PKCS#7 padding. Every padding byte must equal
// the padding length, which is stricter than the reference helper (it only
// rejects a length larger than the buffer). Stricter is safe for authentic
// input and rejects malformed blobs outright.
func unpad(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: padded length %d is not a positive multiple of %d",
			ErrInvalidCiphertext, len(plaintext), aes.BlockSize)
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen == 0 || padLen > aes.BlockSize {
		return nil, fmt.Errorf("%w: invalid padding length %d", ErrInvalidCiphertext, padLen)
	}
	for _, b := range plaintext[len(plaintext)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("%w: inconsistent padding bytes", ErrInvalidCiphertext)
		}
	}
	return plaintext[:len(plaintext)-padLen], nil
}
