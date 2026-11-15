package messaging

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/media"
	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// TestDecodePayloadImage pins the media classification: an imageMessage
// payload decodes to the download metadata, with the image HKDF key type.
func TestDecodePayloadImage(t *testing.T) {
	raw, err := proto.Marshal(&protobuf.Message{
		ImageMessage: &protobuf.ImageMessage{
			Mimetype:          proto.String("image/jpeg"),
			Caption:           proto.String("lihat ini"),
			FileSHA256:        []byte("0123456789abcdef0123456789abcdef"),
			FileEncSHA256:     []byte("abcdef0123456789abcdef0123456789"),
			MediaKey:          []byte("fedcba9876543210fedcba9876543210"),
			FileLength:        proto.Uint64(4242),
			DirectPath:        proto.String("/v/t62.7118-24/x.jpg?ccb=1"),
			MediaKeyTimestamp: proto.Int64(1794752601),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePayload(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Kind != PayloadImage || got.Media == nil {
		t.Fatalf("payload = %#v", got)
	}
	m := got.Media
	if m.MimeType != "image/jpeg" || m.Caption != "lihat ini" || m.FileLength != 4242 {
		t.Fatalf("media = %#v", m)
	}
	if m.KeysType != media.TypeImage {
		t.Fatalf("keys type = %q", m.KeysType)
	}
	if m.DirectPath != "/v/t62.7118-24/x.jpg?ccb=1" || m.MediaKeyTimestamp != 1794752601 {
		t.Fatalf("download fields = %#v", m)
	}
}

// TestDecodePayloadStickerUsesImageKeys pins the sticker quirk (whatsmeow
// classToMediaType): stickers expand their media key under the image keys.
func TestDecodePayloadStickerUsesImageKeys(t *testing.T) {
	raw, err := proto.Marshal(&protobuf.Message{
		StickerMessage: &protobuf.StickerMessage{
			Mimetype:   proto.String("image/webp"),
			MediaKey:   []byte("sticker-media-key-32-bytes-xxxx"),
			FileLength: proto.Uint64(11111),
			DirectPath: proto.String("/v/t62.7118-24/st.webp?ccb=1"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePayload(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Kind != PayloadSticker || got.Media == nil || got.Media.KeysType != media.TypeImage {
		t.Fatalf("payload = %#v", got)
	}
}

// TestDecodePayloadUnknownIsNotAnError keeps the distinction honest: a
// protocol message (reaction, ephemeral setting) is valid content this layer
// has nothing to render — not a failure.
func TestDecodePayloadUnknownIsNotAnError(t *testing.T) {
	// Field 2 is senderKeyDistributionMessage, undeclared here: an undeclared
	// but well-formed field must decode as unknown content, not an error.
	raw := []byte{0x12, 0x00}
	got, err := DecodePayload(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Kind != PayloadUnknown {
		t.Fatalf("kind = %q", got.Kind)
	}
}

// TestParseEncryptedTextAcceptsMediaType pins PF-089: the live service stamps
// type="media" on encrypted media stanzas. Gating on "text" alone rejected
// every sticker, image and voice note before decryption was even attempted.
func TestParseEncryptedTextAcceptsMediaType(t *testing.T) {
	node := &binary.Node{
		Tag: tagMessage,
		Attrs: binary.Attrs{
			"id": "MEDIA1", "from": "123339465080863@lid", "type": MessageTypeMedia,
		},
		Children: []binary.Node{{
			Tag: tagEnc, Attrs: binary.Attrs{attrVersion: EncVersion2, attrCarrier: CarrierPKMsg},
			Bytes: []byte{0x07},
		}},
	}
	got, err := ParseEncryptedText(node)
	if err != nil {
		t.Fatalf("media-type stanza rejected: %v", err)
	}
	if got.Carrier != CarrierPKMsg {
		t.Fatalf("carrier = %q", got.Carrier)
	}

	// An unobserved type still fails loudly.
	node.Attrs["type"] = "invoice"
	if _, err := ParseEncryptedText(node); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("err = %v, want ErrInvalidMessage", err)
	}
}
