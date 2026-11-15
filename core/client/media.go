package client

// Media orchestration: encrypted attachment send and receive on top of the
// Signal text path.
//
// The SDK has no media upload endpoint yet, so the encrypted blob travels
// inline in the descriptor and the transport hints (DirectPath, URL) stay
// empty. Because the descriptor rides inside the Signal ciphertext, the media
// key never crosses the wire in cleartext: the carrier is the same
// <message><enc type="msg|pkmsg"> path as text, with the descriptor JSON as its
// plaintext. Once an upload exists, the inline payload can be dropped and
// DirectPath/URL filled in without changing the caller-facing shape.
//
// MediaKey is the one secret in a MediaResult. It is returned to the caller
// once and deliberately kept out of String so %v/%s of a result cannot log it.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/angga0x3/whatscore/core/media"
	protocolmedia "github.com/angga0x3/whatscore/protocol/media"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
)

// mediaIDPlaceholder occupies the descriptor's media_id until an upload
// assigns a real, addressable media id.
const mediaIDPlaceholder = "pending"

// maxMediaEnvelopeOverhead mirrors core/media's unexported bound: one PKCS#7
// padding block plus the truncated envelope MAC. It lets this package reject
// an oversized blob before decoding or decrypting it.
const maxMediaEnvelopeOverhead = 16 + protocolmedia.MACSize

// maxMediaFileNameBytes bounds the recorded file name, matching the REST
// media routes.
const maxMediaFileNameBytes = 255

// Sentinel errors for the media path (docs/architecture/technical-specification.md
// §8.1). Callers match with errors.Is. The first three also match the
// core/media sentinel they wrap, so a caller can handle either layer.
var (
	// ErrInvalidMediaDescriptor is returned when the descriptor JSON cannot
	// be parsed or violates the envelope contract: unknown media type,
	// negative size, malformed key or digest, unusable file name.
	ErrInvalidMediaDescriptor = fmt.Errorf("client: invalid media descriptor: %w", media.ErrInvalidDescriptor)

	// ErrMediaHashMismatch is returned when decryption fails integrity:
	// a sidecar digest disagrees with the bytes or the envelope MAC does
	// not verify under the descriptor's key and media type.
	ErrMediaHashMismatch = fmt.Errorf("client: media hash mismatch: %w", media.ErrHashMismatch)

	// ErrMediaTooLarge is returned when the plaintext or the encrypted blob
	// exceeds core/media.MaxMediaSize. It is checked before encryption,
	// hashing or decryption.
	ErrMediaTooLarge = fmt.Errorf("client: media too large: %w", media.ErrPayloadTooLarge)

	// ErrUnknownMediaKind is returned for a MediaKind outside the image and
	// document values below.
	ErrUnknownMediaKind = errors.New("client: unknown media kind")
)

// MediaKind is the caller-facing class of an attachment. It maps onto the
// protocol/media HKDF info string for the corresponding message class.
type MediaKind string

const (
	// MediaKindImage covers images (protocol/media TypeImage).
	MediaKindImage MediaKind = "image"
	// MediaKindDocument covers documents (protocol/media TypeDocument).
	MediaKindDocument MediaKind = "document"
)

// protocolMediaType maps a kind onto its PF-041 media type.
func (k MediaKind) protocolMediaType() (string, error) {
	switch k {
	case MediaKindImage:
		return protocolmedia.TypeImage, nil
	case MediaKindDocument:
		return protocolmedia.TypeDocument, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownMediaKind, string(k))
	}
}

// mediaKindForType is the inverse of protocolMediaType. Only classes this SDK
// can send are accepted, so an unexpected media type fails closed.
func mediaKindForType(mediaType string) (MediaKind, error) {
	switch mediaType {
	case protocolmedia.TypeImage:
		return MediaKindImage, nil
	case protocolmedia.TypeDocument:
		return MediaKindDocument, nil
	default:
		return "", fmt.Errorf("%w: unsupported media_type %q", ErrInvalidMediaDescriptor, mediaType)
	}
}

// MediaResult is the caller-visible outcome of a media send or receive.
//
// ID is the WhatsApp message id on send and the descriptor's media id on
// receive. SHA256 and EncSHA256 are hex digests of the plaintext and of the
// transmitted blob (ciphertext ‖ MAC). MediaKey is the base64 (standard,
// padded) form of the 32-byte key: it is written once to the caller and
// omitted from String, so logging a result never logs the key.
type MediaResult struct {
	ID        string
	Kind      MediaKind
	FileName  string
	MimeType  string
	Size      int
	SHA256    string
	EncSHA256 string
	MediaKey  string
}

// String renders the result without the media key.
func (r MediaResult) String() string {
	return fmt.Sprintf("MediaResult{ID:%q Kind:%q FileName:%q MimeType:%q Size:%d SHA256:%s EncSHA256:%s MediaKey:[REDACTED]}",
		r.ID, r.Kind, r.FileName, r.MimeType, r.Size, r.SHA256, r.EncSHA256)
}

// mediaDescriptorJSON is the Signal plaintext that describes one attachment.
// Field names are snake_case to match the REST media shapes.
type mediaDescriptorJSON struct {
	MediaID    string `json:"media_id"`
	FileName   string `json:"file_name"`
	MediaType  string `json:"media_type"`
	MimeType   string `json:"mime_type"`
	Size       int    `json:"size"`
	SHA256     string `json:"sha256"`
	EncSHA256  string `json:"enc_sha256"`
	MediaKey   string `json:"media_key"`
	DirectPath string `json:"direct_path"`
	URL        string `json:"url"`
	// Payload is base64(encrypted blob). It is present only while the SDK
	// has no upload; a receiver must treat it as ciphertext, never as
	// plaintext, and must not trust its length over Size.
	Payload string `json:"payload"`
}

// SendMedia encrypts payload with a fresh media key and sends the descriptor
// as a Signal-encrypted message, reusing SendEncrypted so the ratchet update
// and the pkmsg/msg carrier choice stay in one place.
//
// kind selects the PF-041 media type; an unknown kind is ErrUnknownMediaKind.
// A payload above core/media.MaxMediaSize is rejected before any key
// generation, hashing or encryption. fileName is caller metadata and is
// carried verbatim (trimmed) in the descriptor; the MIME type is guessed from
// its extension, falling back to the kind's default.
//
// The returned MediaResult carries the message id and the media key exactly
// once. Nothing in this path logs the key or the descriptor.
func (c *Client) SendMedia(ctx context.Context, to string, kind MediaKind, fileName string, payload []byte) (MediaResult, error) {
	if err := ctx.Err(); err != nil {
		return MediaResult{}, err
	}
	mediaType, err := kind.protocolMediaType()
	if err != nil {
		return MediaResult{}, err
	}
	if len(payload) > media.MaxMediaSize {
		return MediaResult{}, fmt.Errorf("%w: %d bytes exceeds %d", ErrMediaTooLarge, len(payload), media.MaxMediaSize)
	}
	name, err := normalizeMediaFileName(fileName)
	if err != nil {
		return MediaResult{}, err
	}
	// Fail before encryption when the client cannot send at all.
	if c.sessions == nil {
		return MediaResult{}, fmt.Errorf("%w: no session store", ErrInvalidConfig)
	}

	descriptor, encrypted, err := media.Encrypt(payload, mediaType, name)
	if err != nil {
		return MediaResult{}, mapMediaError(err)
	}
	mimeType := mediaMimeType(name, kind)
	descriptor.MimeType = mimeType

	plaintext, err := json.Marshal(mediaDescriptorJSON{
		MediaID:    mediaIDPlaceholder,
		FileName:   name,
		MediaType:  descriptor.MediaType,
		MimeType:   mimeType,
		Size:       descriptor.Size,
		SHA256:     hex.EncodeToString(descriptor.SHA256[:]),
		EncSHA256:  hex.EncodeToString(descriptor.EncSHA256[:]),
		MediaKey:   base64.StdEncoding.EncodeToString(descriptor.MediaKey[:]),
		DirectPath: "",
		URL:        "",
		Payload:    base64.StdEncoding.EncodeToString(encrypted),
	})
	if err != nil {
		return MediaResult{}, fmt.Errorf("client: marshal media descriptor: %w", err)
	}

	id, err := c.SendEncrypted(ctx, Message{To: to, Text: string(plaintext)})
	if err != nil {
		return MediaResult{}, err
	}
	return MediaResult{
		ID:        id,
		Kind:      kind,
		FileName:  name,
		MimeType:  mimeType,
		Size:      descriptor.Size,
		SHA256:    hex.EncodeToString(descriptor.SHA256[:]),
		EncSHA256: hex.EncodeToString(descriptor.EncSHA256[:]),
		MediaKey:  base64.StdEncoding.EncodeToString(descriptor.MediaKey[:]),
	}, nil
}

// ReceiveMedia parses a descriptor plaintext produced by SendMedia, decrypts
// the inline blob with core/media, and verifies both digests. It returns the
// result and the plaintext payload.
//
// from attributes the descriptor to a peer and must be a user JID; the caller
// is responsible for having decrypted the descriptor from that peer's session.
// A descriptor that cannot be parsed or violates the contract is
// ErrInvalidMediaDescriptor, an oversized one is ErrMediaTooLarge, and any
// integrity failure is ErrMediaHashMismatch.
func (c *Client) ReceiveMedia(ctx context.Context, from string, plaintext []byte) (MediaResult, []byte, error) {
	if err := ctx.Err(); err != nil {
		return MediaResult{}, nil, err
	}
	jid, err := stanza.ParseJID(strings.TrimSpace(from))
	if err != nil {
		return MediaResult{}, nil, fmt.Errorf("client: receive media: from: %w", err)
	}
	if jid.User == "" {
		return MediaResult{}, nil, fmt.Errorf("client: receive media: from %q has no user", from)
	}

	var wire mediaDescriptorJSON
	if err := json.Unmarshal(plaintext, &wire); err != nil {
		return MediaResult{}, nil, fmt.Errorf("%w: %w", ErrInvalidMediaDescriptor, err)
	}
	kind, err := mediaKindForType(wire.MediaType)
	if err != nil {
		return MediaResult{}, nil, err
	}
	if wire.Size < 0 {
		return MediaResult{}, nil, fmt.Errorf("%w: negative size %d", ErrInvalidMediaDescriptor, wire.Size)
	}
	if wire.Size > media.MaxMediaSize {
		return MediaResult{}, nil, fmt.Errorf("%w: descriptor size %d exceeds %d",
			ErrMediaTooLarge, wire.Size, media.MaxMediaSize)
	}
	name, err := normalizeMediaFileName(wire.FileName)
	if err != nil {
		return MediaResult{}, nil, err
	}
	if len(wire.Payload) > base64.StdEncoding.EncodedLen(media.MaxMediaSize+maxMediaEnvelopeOverhead) {
		return MediaResult{}, nil, fmt.Errorf("%w: encoded blob exceeds %d bytes",
			ErrMediaTooLarge, media.MaxMediaSize+maxMediaEnvelopeOverhead)
	}
	encrypted, err := base64.StdEncoding.DecodeString(wire.Payload)
	if err != nil {
		return MediaResult{}, nil, fmt.Errorf("%w: payload: %w", ErrInvalidMediaDescriptor, err)
	}
	if len(encrypted) > media.MaxMediaSize+maxMediaEnvelopeOverhead {
		return MediaResult{}, nil, fmt.Errorf("%w: %d encrypted bytes exceeds %d",
			ErrMediaTooLarge, len(encrypted), media.MaxMediaSize+maxMediaEnvelopeOverhead)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(wire.MediaKey)
	if err != nil {
		return MediaResult{}, nil, fmt.Errorf("%w: media_key: %w", ErrInvalidMediaDescriptor, err)
	}
	var mediaKey [32]byte
	if len(keyBytes) != len(mediaKey) {
		return MediaResult{}, nil, fmt.Errorf("%w: media_key is %d bytes, want 32",
			ErrInvalidMediaDescriptor, len(keyBytes))
	}
	copy(mediaKey[:], keyBytes)

	plainSum, err := decodeMediaDigest("sha256", wire.SHA256)
	if err != nil {
		return MediaResult{}, nil, err
	}
	encSum, err := decodeMediaDigest("enc_sha256", wire.EncSHA256)
	if err != nil {
		return MediaResult{}, nil, err
	}

	payload, err := media.Decrypt(encrypted, &media.Descriptor{
		MediaKey:  mediaKey,
		MediaType: wire.MediaType,
		FileName:  name,
		MimeType:  wire.MimeType,
		Size:      wire.Size,
		SHA256:    plainSum,
		EncSHA256: encSum,
	})
	if err != nil {
		return MediaResult{}, nil, mapMediaError(err)
	}

	mimeType := wire.MimeType
	if mimeType == "" {
		mimeType = mediaMimeType(name, kind)
	}
	return MediaResult{
		ID:        wire.MediaID,
		Kind:      kind,
		FileName:  name,
		MimeType:  mimeType,
		Size:      len(payload),
		SHA256:    hex.EncodeToString(plainSum[:]),
		EncSHA256: hex.EncodeToString(encSum[:]),
		MediaKey:  wire.MediaKey,
	}, payload, nil
}

// normalizeMediaFileName validates the descriptor's file name: non-empty after
// trimming, no control characters, and bounded in bytes. Surrounding
// whitespace is dropped so a padded name is not stored twice.
func normalizeMediaFileName(fileName string) (string, error) {
	name := strings.TrimSpace(fileName)
	if name == "" {
		return "", fmt.Errorf("%w: empty file name", ErrInvalidMediaDescriptor)
	}
	if len(name) > maxMediaFileNameBytes {
		return "", fmt.Errorf("%w: file name is %d bytes, want at most %d",
			ErrInvalidMediaDescriptor, len(name), maxMediaFileNameBytes)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: file name contains a control character", ErrInvalidMediaDescriptor)
		}
	}
	return name, nil
}

// mediaMimeType guesses the MIME type from the file extension, dropping any
// charset parameter, and falls back to the kind's default.
func mediaMimeType(fileName string, kind MediaKind) string {
	if ext := filepath.Ext(fileName); ext != "" {
		if guessed := mime.TypeByExtension(ext); guessed != "" {
			if base, _, ok := strings.Cut(guessed, ";"); ok {
				guessed = base
			}
			return strings.TrimSpace(guessed)
		}
	}
	if kind == MediaKindImage {
		return "image/jpeg"
	}
	return "application/octet-stream"
}

// decodeMediaDigest parses one hex SHA-256 sidecar field.
func decodeMediaDigest(field, raw string) ([32]byte, error) {
	var sum [32]byte
	if len(raw) != hex.EncodedLen(len(sum)) {
		return sum, fmt.Errorf("%w: %s must be %d hex characters, got %d",
			ErrInvalidMediaDescriptor, field, hex.EncodedLen(len(sum)), len(raw))
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return sum, fmt.Errorf("%w: %s: %w", ErrInvalidMediaDescriptor, field, err)
	}
	copy(sum[:], decoded)
	return sum, nil
}

// mapMediaError narrows a core/media error onto this package's sentinels while
// preserving the original for errors.Is.
func mapMediaError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, media.ErrHashMismatch):
		return fmt.Errorf("%w: %w", ErrMediaHashMismatch, err)
	case errors.Is(err, media.ErrPayloadTooLarge):
		return fmt.Errorf("%w: %w", ErrMediaTooLarge, err)
	case errors.Is(err, media.ErrInvalidDescriptor):
		return fmt.Errorf("%w: %w", ErrInvalidMediaDescriptor, err)
	default:
		return err
	}
}
