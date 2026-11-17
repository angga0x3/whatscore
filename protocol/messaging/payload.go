package messaging

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/media"
	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// EncodeTextMessage builds the application payload a text message carries
// (PF-083): protobuf Message.conversation, which is what the receiver decrypts
// and renders.
//
// This is the half the earlier "text carrier" placeholder was missing. That
// carrier put raw bytes in a <body> child, which no reference does; the bytes
// inside a <enc> are a protobuf Message.
func EncodeTextMessage(text string) ([]byte, error) {
	if text == "" {
		return nil, fmt.Errorf("%w: empty text", ErrInvalidMessagePayload)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protobuf.Message{
		Conversation: proto.String(text),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling: %w", ErrInvalidMessagePayload, err)
	}
	return raw, nil
}

// DecodeTextMessage extracts the text from a decrypted application payload.
// Both carriers a text can arrive in are handled: bare conversation, and
// extendedTextMessage.text. A device-sent copy is unwrapped first: that is the
// shape the account's own devices receive when another device sends.
func DecodeTextMessage(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("%w: empty payload", ErrInvalidMessagePayload)
	}
	var message protobuf.Message
	if err := proto.Unmarshal(raw, &message); err != nil {
		return "", fmt.Errorf("%w: unmarshaling: %w", ErrInvalidMessagePayload, err)
	}
	inner, _ := unwrapDeviceSent(&message)
	if text := inner.GetConversation(); text != "" {
		return text, nil
	}
	if text := inner.GetExtendedTextMessage().GetText(); text != "" {
		return text, nil
	}
	return "", fmt.Errorf("%w: payload carries no text (unsupported message type)", ErrInvalidMessagePayload)
}

// ErrInvalidMessagePayload is returned for unusable application payloads.
var ErrInvalidMessagePayload = fmt.Errorf("%w: invalid payload", ErrInvalidMessage)

// PadMessage adds the padding the service expects around a v2 plaintext: one
// to fifteen copies of a byte holding that same count. A compliant receiver
// (whatsmeow's unpadMessage) strips it and refuses plaintexts that do not
// carry valid padding, so sending unpadded bytes is how a message that "was
// accepted by the server" still fails on the phone.
func PadMessage(plaintext []byte) []byte {
	pad := make([]byte, 1)
	if _, err := rand.Read(pad); err != nil {
		// Randomness is cosmetic here; the count is what matters, and any
		// constant is a legal pad.
		pad[0] = 0x0f
	}
	pad[0] &= 0x0f
	if pad[0] == 0 {
		pad[0] = 0x0f
	}
	return append(plaintext, bytes.Repeat(pad, int(pad[0]))...)
}

// UnpadMessage strips that padding after decryption. Version 3 plaintexts are
// carried unpadded. The live queue replay decrypted to wire-format errors and
// "no text" verdicts for exactly this reason: the trailing padding is not
// protobuf.
func UnpadMessage(plaintext []byte, version string) ([]byte, error) {
	if version == "3" {
		return plaintext, nil
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%w: empty plaintext", ErrInvalidMessagePayload)
	}
	last := plaintext[len(plaintext)-1]
	if !bytes.HasSuffix(plaintext, bytes.Repeat([]byte{last}, int(last))) {
		return nil, fmt.Errorf("%w: plaintext does not carry valid padding", ErrInvalidMessagePayload)
	}
	return plaintext[:len(plaintext)-int(last)], nil
}

// PayloadKind names the content a decrypted Message carries.
type PayloadKind string

// The kinds DecodePayload can classify. PayloadUnknown is "valid but not
// rendered here"; the rest name a renderable payload.
const (
	PayloadText     PayloadKind = "text"
	PayloadImage    PayloadKind = "image"
	PayloadSticker  PayloadKind = "sticker"
	PayloadVideo    PayloadKind = "video"
	PayloadAudio    PayloadKind = "audio"
	PayloadDocument PayloadKind = "document"
	PayloadProtocol PayloadKind = "protocol"
	// PayloadSenderKey carries a group sender key distribution: no user
	// content, but the state that makes later group messages readable.
	PayloadSenderKey PayloadKind = "sender-key"
	PayloadUnknown   PayloadKind = "unknown"
)

// ProtocolInfo describes a decrypted protocol message. History sync
// notifications are the ones a client must acknowledge with a hist_sync
// receipt — that ack is what the phone's "keep both apps open" phase waits
// for — and carry the CDN metadata to download the chunk later.
type ProtocolInfo struct {
	Type        string
	HistorySync *MediaAttachment
	// AppKeys carries the app state sync keys from a key share, keyed by the
	// hex of the key id. Patches reference these ids in their MACs.
	AppKeys map[string][]byte
}

// MediaAttachment is the download metadata one media payload carries. KeysType
// is the HKDF info string the media key expands under; stickers expand under
// the image keys (whatsmeow classToMediaType), everything else under its own.
type MediaAttachment struct {
	Kind              PayloadKind
	MimeType          string
	Caption           string
	FileName          string
	FileLength        uint64
	MediaKey          []byte
	FileSHA256        []byte
	FileEncSHA256     []byte
	DirectPath        string
	MediaKeyTimestamp int64
	KeysType          string
}

// SenderKeyShare is one member's group sender key as it arrives: the group
// it belongs to plus the opaque libsignal SenderKeyDistributionMessage bytes.
// Parsing those is protocol/signal's job; this layer only carries them.
type SenderKeyShare struct {
	GroupID string
	Raw     []byte
}

// Payload is the decoded content of one decrypted Message: either text or one
// media attachment. A payload with neither — protocol messages, reactions,
// ephemeral settings — decodes to PayloadUnknown without error, because
// "unsupported but valid" is a normal thing to receive.
type Payload struct {
	Kind      PayloadKind
	Text      string
	Media     *MediaAttachment
	Protocol  *ProtocolInfo
	SenderKey *SenderKeyShare
	// Destination is the chat a device-sent copy belongs to. The account's own
	// devices receive the wrapped form, whose outer message carries no chat of
	// its own; an empty Destination means the payload was not wrapped and the
	// sender is the chat.
	Destination string
}

// DecodePayload reads a decrypted application payload and classifies it: text
// in either carrier, or one of the five media kinds. Unknown payloads return
// PayloadUnknown, not an error — the earlier "carries no text (unsupported
// message type)" error conflated a full inbox of legitimate non-text content
// with a failure.
//
// A device-sent copy is unwrapped first and its destinationJID reported, so a
// message another of the account's devices sent lands in the chat it was
// addressed to rather than in a chat with the sending device.
func DecodePayload(raw []byte) (*Payload, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidMessagePayload)
	}
	var message protobuf.Message
	if err := proto.Unmarshal(raw, &message); err != nil {
		return nil, fmt.Errorf("%w: unmarshaling: %w", ErrInvalidMessagePayload, err)
	}
	inner, destination := unwrapDeviceSent(&message)
	payload := decodeInner(inner)
	payload.Destination = destination
	// A sender key distribution can ride inside a payload that also carries
	// content (some clients bundle it), so it is lifted out before the kind
	// decides what to render. A payload that is only a distribution is its
	// own kind: state, not a message.
	if skdm := inner.GetSenderKeyDistributionMessage(); skdm != nil {
		payload.SenderKey = &SenderKeyShare{
			GroupID: skdm.GetGroupID(),
			Raw:     append([]byte(nil), skdm.GetAxolotlSenderKeyDistributionMessage()...),
		}
		if payload.Kind == PayloadUnknown {
			payload.Kind = PayloadSenderKey
		}
	}
	return payload, nil
}

// decodeInner classifies an already-unwrapped message.
func decodeInner(message *protobuf.Message) *Payload {
	switch {
	case message.GetProtocolMessage() != nil:
		pm := message.GetProtocolMessage()
		info := &ProtocolInfo{Type: pm.GetType().String()}
		if hs := pm.GetHistorySyncNotification(); hs != nil {
			info.HistorySync = mediaFrom(hs.GetDirectPath(), "", "", "history-chunk-"+strconv.FormatUint(uint64(hs.GetChunkOrder()), 10),
				hs.GetFileLength(), hs.GetMediaKey(), hs.GetFileSHA256(), hs.GetFileEncSHA256(), 0, media.TypeHistory)
		}
		if share := pm.GetAppStateSyncKeyShare(); share != nil {
			info.AppKeys = make(map[string][]byte, len(share.GetKeys()))
			for _, key := range share.GetKeys() {
				if key.GetKeyID() == nil {
					continue
				}
				info.AppKeys[hex.EncodeToString(key.GetKeyID().GetID())] = append([]byte(nil), key.GetKeyData().GetKeyData()...)
			}
		}
		return &Payload{Kind: PayloadProtocol, Protocol: info}
	case message.GetConversation() != "":
		return &Payload{Kind: PayloadText, Text: message.GetConversation()}
	case message.GetExtendedTextMessage() != nil:
		return &Payload{Kind: PayloadText, Text: message.GetExtendedTextMessage().GetText()}
	case message.GetImageMessage() != nil:
		m := message.GetImageMessage()
		return &Payload{Kind: PayloadImage, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), m.GetCaption(), "",
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeImage)}
	case message.GetStickerMessage() != nil:
		m := message.GetStickerMessage()
		return &Payload{Kind: PayloadSticker, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), "", "",
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeImage)}
	case message.GetVideoMessage() != nil:
		m := message.GetVideoMessage()
		return &Payload{Kind: PayloadVideo, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), m.GetCaption(), "",
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeVideo)}
	case message.GetAudioMessage() != nil:
		m := message.GetAudioMessage()
		return &Payload{Kind: PayloadAudio, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), "", "",
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeAudio)}
	case message.GetDocumentMessage() != nil:
		m := message.GetDocumentMessage()
		return &Payload{Kind: PayloadDocument, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), "", m.GetFileName(),
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeDocument)}
	default:
		return &Payload{Kind: PayloadUnknown}
	}
}

// unwrapDeviceSent returns the message a device-sent wrapper carries and the
// chat it belongs to. An unwrapped message returns itself and no destination.
// Nested wrappers are unwrapped too: nothing forbids a copy of a copy, and
// stopping at one level would surface an empty message.
func unwrapDeviceSent(message *protobuf.Message) (*protobuf.Message, string) {
	destination := ""
	for depth := 0; depth < 8; depth++ {
		dsm := message.GetDeviceSentMessage()
		if dsm == nil || dsm.GetMessage() == nil {
			return message, destination
		}
		if destination == "" {
			destination = dsm.GetDestinationJID()
		}
		message = dsm.GetMessage()
	}
	return message, destination
}

func mediaFrom(directPath, mimetype, caption, fileName string, fileLength uint64,
	mediaKey, fileSHA256, fileEncSHA256 []byte, mediaKeyTimestamp int64, keysType string) *MediaAttachment {
	return &MediaAttachment{
		MimeType:          mimetype,
		Caption:           caption,
		FileName:          fileName,
		FileLength:        fileLength,
		MediaKey:          append([]byte(nil), mediaKey...),
		FileSHA256:        append([]byte(nil), fileSHA256...),
		FileEncSHA256:     append([]byte(nil), fileEncSHA256...),
		DirectPath:        directPath,
		MediaKeyTimestamp: mediaKeyTimestamp,
		KeysType:          keysType,
	}
}

// EncodeDeviceSentMessage wraps a text message in the device-sent envelope
// whatsmeow's marshalMessage builds for every 1:1 send: the sender encrypts
// one copy for the recipient and one copy — this one — for the account's own
// devices. Without the own copy the message delivers to the recipient but
// never appears on the sender's phone.
//
// The copy carries the same message id as the recipient's copy: one logical
// message, two ciphertexts. A different id would make the phone show the
// message twice — once as sent, once as received from itself.
func EncodeDeviceSentMessage(destJID, text string) ([]byte, error) {
	return EncodeDeviceSentPayload(destJID, &protobuf.Message{
		Conversation: proto.String(text),
	})
}

// EncodeDeviceSentPayload wraps an already-built payload. Media and richer
// messages use this: the wrapper's inner message is whatever the recipient
// copy carries.
func EncodeDeviceSentPayload(destJID string, message *protobuf.Message) ([]byte, error) {
	if destJID == "" {
		return nil, fmt.Errorf("%w: empty destination", ErrInvalidMessagePayload)
	}
	if message == nil {
		return nil, fmt.Errorf("%w: empty message", ErrInvalidMessagePayload)
	}
	return proto.Marshal(&protobuf.Message{
		DeviceSentMessage: &protobuf.DeviceSentMessage{
			DestinationJID: proto.String(destJID),
			Message:        message,
		},
	})
}

// MediaMessage is one uploaded attachment as it travels in the message
// protobuf: the CDN location, the digest and key the recipient verifies, and
// the descriptive fields a client renders.
//
// The values come from two places and both are load-bearing: FileSHA256,
// FileEncSHA256 and MediaKey from core/media's descriptor (the envelope), and
// URL/DirectPath from the upload reply. Filling one from the other's source
// produces a message the recipient downloads and cannot open.
type MediaMessage struct {
	Kind PayloadKind
	// URL and DirectPath are the upload's transport hints.
	URL        string
	DirectPath string
	MimeType   string
	Caption    string
	FileName   string
	Title      string
	// FileSHA256 is SHA-256 of the plaintext; FileEncSHA256 is SHA-256 of
	// the encrypted blob as uploaded.
	FileSHA256    []byte
	FileEncSHA256 []byte
	MediaKey      []byte
	FileLength    uint64
	Width         uint32
	Height        uint32
	Seconds       uint32
	PTT           bool
	IsAnimated    bool
}

// EncodeMediaMessage builds the protobuf Message one media kind carries.
// Field numbers are the ones already declared from the reference proto.
func EncodeMediaMessage(m MediaMessage) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	message := &protobuf.Message{}
	switch m.Kind {
	case PayloadImage:
		message.ImageMessage = &protobuf.ImageMessage{
			Url:           proto.String(m.URL),
			Mimetype:      proto.String(m.MimeType),
			Caption:       optionalString(m.Caption),
			FileSHA256:    append([]byte(nil), m.FileSHA256...),
			FileLength:    proto.Uint64(m.FileLength),
			Height:        optionalUint32(m.Height),
			Width:         optionalUint32(m.Width),
			MediaKey:      append([]byte(nil), m.MediaKey...),
			FileEncSHA256: append([]byte(nil), m.FileEncSHA256...),
			DirectPath:    proto.String(m.DirectPath),
		}
	case PayloadSticker:
		message.StickerMessage = &protobuf.StickerMessage{
			Url:           proto.String(m.URL),
			FileSHA256:    append([]byte(nil), m.FileSHA256...),
			FileEncSHA256: append([]byte(nil), m.FileEncSHA256...),
			MediaKey:      append([]byte(nil), m.MediaKey...),
			Mimetype:      proto.String(m.MimeType),
			Height:        optionalUint32(m.Height),
			Width:         optionalUint32(m.Width),
			DirectPath:    proto.String(m.DirectPath),
			FileLength:    proto.Uint64(m.FileLength),
			IsAnimated:    proto.Bool(m.IsAnimated),
		}
	case PayloadVideo:
		message.VideoMessage = &protobuf.VideoMessage{
			Url:           proto.String(m.URL),
			Mimetype:      proto.String(m.MimeType),
			FileSHA256:    append([]byte(nil), m.FileSHA256...),
			FileLength:    proto.Uint64(m.FileLength),
			Seconds:       optionalUint32(m.Seconds),
			MediaKey:      append([]byte(nil), m.MediaKey...),
			Caption:       optionalString(m.Caption),
			Height:        optionalUint32(m.Height),
			Width:         optionalUint32(m.Width),
			FileEncSHA256: append([]byte(nil), m.FileEncSHA256...),
			DirectPath:    proto.String(m.DirectPath),
		}
	case PayloadAudio:
		message.AudioMessage = &protobuf.AudioMessage{
			Url:           proto.String(m.URL),
			Mimetype:      proto.String(m.MimeType),
			FileSHA256:    append([]byte(nil), m.FileSHA256...),
			FileLength:    proto.Uint64(m.FileLength),
			Seconds:       optionalUint32(m.Seconds),
			Ptt:           proto.Bool(m.PTT),
			MediaKey:      append([]byte(nil), m.MediaKey...),
			FileEncSHA256: append([]byte(nil), m.FileEncSHA256...),
			DirectPath:    proto.String(m.DirectPath),
		}
	case PayloadDocument:
		message.DocumentMessage = &protobuf.DocumentMessage{
			Url:           proto.String(m.URL),
			Mimetype:      proto.String(m.MimeType),
			Title:         proto.String(m.Title),
			FileSHA256:    append([]byte(nil), m.FileSHA256...),
			FileLength:    proto.Uint64(m.FileLength),
			MediaKey:      append([]byte(nil), m.MediaKey...),
			FileName:      proto.String(m.FileName),
			FileEncSHA256: append([]byte(nil), m.FileEncSHA256...),
			DirectPath:    proto.String(m.DirectPath),
		}
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling: %w", ErrInvalidMessagePayload, err)
	}
	return raw, nil
}

// validate fails closed: a media message that names no blob, no key, or no
// digest downloads into nothing and is not worth sending.
func (m MediaMessage) validate() error {
	switch m.Kind {
	case PayloadImage, PayloadSticker, PayloadVideo, PayloadAudio, PayloadDocument:
	default:
		return fmt.Errorf("%w: media kind %q", ErrInvalidMessagePayload, m.Kind)
	}
	if m.URL == "" || m.DirectPath == "" {
		return fmt.Errorf("%w: media has no url or direct path", ErrInvalidMessagePayload)
	}
	if m.MimeType == "" {
		return fmt.Errorf("%w: media has no mimetype", ErrInvalidMessagePayload)
	}
	if len(m.MediaKey) != 32 {
		return fmt.Errorf("%w: media key is %d bytes, want 32", ErrInvalidMessagePayload, len(m.MediaKey))
	}
	if len(m.FileSHA256) != 32 || len(m.FileEncSHA256) != 32 {
		return fmt.Errorf("%w: media digests must be 32 bytes", ErrInvalidMessagePayload)
	}
	if m.FileLength == 0 {
		return fmt.Errorf("%w: media has no length", ErrInvalidMessagePayload)
	}
	if m.Kind == PayloadAudio && m.PTT && m.Seconds == 0 {
		return fmt.Errorf("%w: voice note has no duration", ErrInvalidMessagePayload)
	}
	return nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return proto.String(value)
}

func optionalUint32(value uint32) *uint32 {
	if value == 0 {
		return nil
	}
	return proto.Uint32(value)
}
