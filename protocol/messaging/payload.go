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
// extendedTextMessage.text.
func DecodeTextMessage(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("%w: empty payload", ErrInvalidMessagePayload)
	}
	var message protobuf.Message
	if err := proto.Unmarshal(raw, &message); err != nil {
		return "", fmt.Errorf("%w: unmarshaling: %w", ErrInvalidMessagePayload, err)
	}
	if text := message.GetConversation(); text != "" {
		return text, nil
	}
	if text := message.GetExtendedTextMessage().GetText(); text != "" {
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

const (
	PayloadText     PayloadKind = "text"
	PayloadImage    PayloadKind = "image"
	PayloadSticker  PayloadKind = "sticker"
	PayloadVideo    PayloadKind = "video"
	PayloadAudio    PayloadKind = "audio"
	PayloadDocument PayloadKind = "document"
	PayloadProtocol PayloadKind = "protocol"
	PayloadUnknown  PayloadKind = "unknown"
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

// Payload is the decoded content of one decrypted Message: either text or one
// media attachment. A payload with neither — protocol messages, reactions,
// ephemeral settings — decodes to PayloadUnknown without error, because
// "unsupported but valid" is a normal thing to receive.
type Payload struct {
	Kind     PayloadKind
	Text     string
	Media    *MediaAttachment
	Protocol *ProtocolInfo
}

// DecodePayload reads a decrypted application payload and classifies it: text
// in either carrier, or one of the five media kinds. Unknown payloads return
// PayloadUnknown, not an error — the earlier "carries no text (unsupported
// message type)" error conflated a full inbox of legitimate non-text content
// with a failure.
func DecodePayload(raw []byte) (*Payload, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidMessagePayload)
	}
	var message protobuf.Message
	if err := proto.Unmarshal(raw, &message); err != nil {
		return nil, fmt.Errorf("%w: unmarshaling: %w", ErrInvalidMessagePayload, err)
	}
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
		return &Payload{Kind: PayloadProtocol, Protocol: info}, nil
	case message.GetConversation() != "":
		return &Payload{Kind: PayloadText, Text: message.GetConversation()}, nil
	case message.GetExtendedTextMessage() != nil:
		return &Payload{Kind: PayloadText, Text: message.GetExtendedTextMessage().GetText()}, nil
	case message.GetImageMessage() != nil:
		m := message.GetImageMessage()
		return &Payload{Kind: PayloadImage, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), m.GetCaption(), "",
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeImage)}, nil
	case message.GetStickerMessage() != nil:
		m := message.GetStickerMessage()
		return &Payload{Kind: PayloadSticker, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), "", "",
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeImage)}, nil
	case message.GetVideoMessage() != nil:
		m := message.GetVideoMessage()
		return &Payload{Kind: PayloadVideo, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), m.GetCaption(), "",
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeVideo)}, nil
	case message.GetAudioMessage() != nil:
		m := message.GetAudioMessage()
		return &Payload{Kind: PayloadAudio, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), "", "",
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeAudio)}, nil
	case message.GetDocumentMessage() != nil:
		m := message.GetDocumentMessage()
		return &Payload{Kind: PayloadDocument, Media: mediaFrom(m.GetDirectPath(), m.GetMimetype(), "", m.GetFileName(),
			m.GetFileLength(), m.GetMediaKey(), m.GetFileSHA256(), m.GetFileEncSHA256(), m.GetMediaKeyTimestamp(), media.TypeDocument)}, nil
	default:
		return &Payload{Kind: PayloadUnknown}, nil
	}
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
