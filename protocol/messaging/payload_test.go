package messaging

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// TestEncodeTextMessageIsConversation pins the wire shape: text travels as
// protobuf Message.conversation (field 1). The previous carrier put raw bytes in
// a <body> child, which no reference does, so a message built that way could be
// acknowledged by the server and still not render on a phone.
func TestEncodeTextMessageIsConversation(t *testing.T) {
	raw, err := EncodeTextMessage("halo")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var message protobuf.Message
	if err := proto.Unmarshal(raw, &message); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if message.GetConversation() != "halo" {
		t.Fatalf("conversation = %q", message.GetConversation())
	}
	// Field 1, wire type 2: 0x0a, then the length.
	if len(raw) < 2 || raw[0] != 0x0a {
		t.Fatalf("payload does not start with field 1: % x", raw)
	}
}

// TestEncodeDeviceSentMessageWrapsTheDestination pins the own-device shape:
// field 31 carries a DeviceSentMessage whose destinationJID is the chat the
// message belongs to and whose message is the same payload the recipient got.
// A copy without the wrapper renders in the wrong chat — or nowhere.
func TestEncodeDeviceSentMessageWrapsTheDestination(t *testing.T) {
	raw, err := EncodeDeviceSentMessage("628123@s.whatsapp.net", "halo")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var message protobuf.Message
	if err := proto.Unmarshal(raw, &message); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	dsm := message.GetDeviceSentMessage()
	if dsm == nil {
		t.Fatal("deviceSentMessage missing")
	}
	if dsm.GetDestinationJID() != "628123@s.whatsapp.net" {
		t.Fatalf("destinationJID = %q", dsm.GetDestinationJID())
	}
	if dsm.GetMessage().GetConversation() != "halo" {
		t.Fatalf("inner conversation = %q", dsm.GetMessage().GetConversation())
	}
	// Field 31, wire type 2: 31<<3|2 = 250, encoded as 0xfa 0x01.
	if len(raw) < 2 || raw[0] != 0xfa || raw[1] != 0x01 {
		t.Fatalf("payload does not start with field 31: % x", raw[:min(4, len(raw))])
	}
}

// TestEncodeDeviceSentMessageRejectsEmptyDestination fails closed: a copy with
// no destination has no chat to appear in.
func TestEncodeDeviceSentMessageRejectsEmptyDestination(t *testing.T) {
	if _, err := EncodeDeviceSentMessage("", "halo"); err == nil {
		t.Fatal("empty destination accepted")
	}
}

// TestDecodePayloadUnwrapsDeviceSentMessage pins the receive side of the
// own-device copy: the account's other devices get the wrapped form, so a
// decoder that only reads the outer message sees nothing. The destination is
// reported because the copy belongs to that chat, not to the sending device.
func TestDecodePayloadUnwrapsDeviceSentMessage(t *testing.T) {
	raw, err := EncodeDeviceSentMessage("628123@s.whatsapp.net", "dari hp")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := DecodePayload(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Kind != PayloadText || payload.Text != "dari hp" {
		t.Fatalf("payload = %#v", payload)
	}
	if payload.Destination != "628123@s.whatsapp.net" {
		t.Fatalf("destination = %q", payload.Destination)
	}

	// The text reader unwraps too, because it is the same decision.
	if text, err := DecodeTextMessage(raw); err != nil || text != "dari hp" {
		t.Fatalf("text = %q, %v", text, err)
	}
}

// TestDecodePayloadReportsNoDestinationForPlainMessages keeps the two shapes
// distinguishable: an unwrapped message names no chat because the sender is
// the chat.
func TestDecodePayloadReportsNoDestinationForPlainMessages(t *testing.T) {
	raw, err := EncodeTextMessage("halo")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := DecodePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Destination != "" {
		t.Fatalf("destination = %q, want empty", payload.Destination)
	}
}

// TestDecodePayloadUnwrapsNestedCopies keeps the bounded loop honest: a copy
// of a copy is still one message, and stopping at one level would surface an
// empty outer message.
func TestDecodePayloadUnwrapsNestedCopies(t *testing.T) {
	inner, err := EncodeDeviceSentMessage("628123@s.whatsapp.net", "berlapis")
	if err != nil {
		t.Fatal(err)
	}
	var wrapped protobuf.Message
	if err := proto.Unmarshal(inner, &wrapped); err != nil {
		t.Fatal(err)
	}
	outer, err := proto.Marshal(&protobuf.Message{
		DeviceSentMessage: &protobuf.DeviceSentMessage{
			DestinationJID: proto.String("628999@s.whatsapp.net"),
			Message:        &wrapped,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := DecodePayload(outer)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Text != "berlapis" {
		t.Fatalf("text = %q", payload.Text)
	}
	// The outermost destination is the chat the copy was addressed to.
	if payload.Destination != "628999@s.whatsapp.net" {
		t.Fatalf("destination = %q", payload.Destination)
	}
}

// TestDecodeTextMessageHandlesBothCarriers covers the two forms a text can
// arrive in, because a peer chooses which to send.
func TestDecodeTextMessageHandlesBothCarriers(t *testing.T) {
	conversation, err := EncodeTextMessage("plain")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeTextMessage(conversation); err != nil || got != "plain" {
		t.Fatalf("conversation decode = %q, %v", got, err)
	}

	extended, err := proto.Marshal(&protobuf.Message{
		ExtendedTextMessage: &protobuf.ExtendedTextMessage{Text: proto.String("rich")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeTextMessage(extended); err != nil || got != "rich" {
		t.Fatalf("extended decode = %q, %v", got, err)
	}
}

// TestDecodeTextMessageRejectsEmptyPayloads fails closed rather than publishing
// an empty message, which would look like a delivered blank message.
func TestDecodeTextMessageRejectsEmptyPayloads(t *testing.T) {
	cases := map[string][]byte{
		"nil":     nil,
		"empty":   {},
		"no text": {0x10, 0x01}, // field 2 varint, no conversation
		"garbage": bytes.Repeat([]byte{0xff}, 8),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTextMessage(raw); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := EncodeTextMessage(""); err == nil {
		t.Fatal("empty text accepted")
	}
}

// TestTextSurvivesUTF8 keeps a non-ASCII body intact through the protobuf layer.
func TestTextSurvivesUTF8(t *testing.T) {
	text := "halo dunia ✓ 日本語"
	raw, err := EncodeTextMessage(text)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTextMessage(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != text {
		t.Fatalf("round trip = %q", got)
	}
}

// TestPadUnpadRoundTrip pins the padding scheme the service actually applies
// (whatsmeow padMessage/unpadMessage): v2 plaintexts carry N copies of the
// byte N; version 3 carries none. The live queue replay decrypted to
// wire-format errors and "no text" verdicts because the trailing pad bytes
// are not protobuf.
func TestPadUnpadRoundTrip(t *testing.T) {
	raw, err := EncodeTextMessage("halo")
	if err != nil {
		t.Fatal(err)
	}
	padded := PadMessage(raw)
	if !bytes.HasPrefix(padded, raw) {
		t.Fatal("padding did not append after the payload")
	}
	padLen := int(padded[len(padded)-1])
	if padLen < 1 || padLen > 15 {
		t.Fatalf("pad length %d outside the 1..15 range", padLen)
	}
	if !bytes.Equal(padded[len(padded)-padLen:], bytes.Repeat([]byte{byte(padLen)}, padLen)) {
		t.Fatal("padding is not N copies of the byte N")
	}

	unpadded, err := UnpadMessage(padded, "2")
	if err != nil {
		t.Fatalf("unpad: %v", err)
	}
	if !bytes.Equal(unpadded, raw) {
		t.Fatal("unpad did not restore the payload")
	}
	text, err := DecodeTextMessage(unpadded)
	if err != nil || text != "halo" {
		t.Fatalf("decode after unpad = %q, %v", text, err)
	}

	// Version 3 plaintexts are carried unpadded: unpad must be a no-op.
	through, err := UnpadMessage(raw, "3")
	if err != nil || !bytes.Equal(through, raw) {
		t.Fatalf("v3 passthrough = %v, %q", err, through)
	}
}

// TestUnpadRejectsUnpaddedPlaintext keeps the loud failure: an unpadded
// plaintext is not something this protocol produced, and stripping its last
// byte would corrupt it.
func TestUnpadRejectsUnpaddedPlaintext(t *testing.T) {
	raw, _ := EncodeTextMessage("tanpa padding")
	if _, err := UnpadMessage(raw, "2"); err == nil {
		t.Fatal("unpadded plaintext accepted")
	}
}

// mediaMessage is one complete, valid upload the media tests mutate.
func mediaMessage() MediaMessage {
	return MediaMessage{
		Kind:          PayloadImage,
		URL:           "https://mmg.whatsapp.net/x",
		DirectPath:    "/v/t62/x",
		MimeType:      "image/jpeg",
		Caption:       "pantai",
		FileSHA256:    bytes.Repeat([]byte{0x01}, 32),
		FileEncSHA256: bytes.Repeat([]byte{0x02}, 32),
		MediaKey:      bytes.Repeat([]byte{0x03}, 32),
		FileLength:    1234,
		Width:         800,
		Height:        600,
	}
}

// TestEncodeMediaMessageImage pins the image fields a recipient needs to
// download and decrypt: location, digests, key, length and mimetype.
func TestEncodeMediaMessageImage(t *testing.T) {
	raw, err := EncodeMediaMessage(mediaMessage())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var message protobuf.Message
	if err := proto.Unmarshal(raw, &message); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	img := message.GetImageMessage()
	if img == nil {
		t.Fatal("imageMessage missing")
	}
	if img.GetUrl() != "https://mmg.whatsapp.net/x" || img.GetDirectPath() != "/v/t62/x" {
		t.Fatalf("location = %q %q", img.GetUrl(), img.GetDirectPath())
	}
	if img.GetMimetype() != "image/jpeg" || img.GetCaption() != "pantai" {
		t.Fatalf("mime/caption = %q %q", img.GetMimetype(), img.GetCaption())
	}
	if img.GetFileLength() != 1234 || img.GetWidth() != 800 || img.GetHeight() != 600 {
		t.Fatalf("size = %d %dx%d", img.GetFileLength(), img.GetWidth(), img.GetHeight())
	}
	if !bytes.Equal(img.GetMediaKey(), bytes.Repeat([]byte{0x03}, 32)) {
		t.Fatal("media key did not survive")
	}
	if !bytes.Equal(img.GetFileSHA256(), bytes.Repeat([]byte{0x01}, 32)) ||
		!bytes.Equal(img.GetFileEncSHA256(), bytes.Repeat([]byte{0x02}, 32)) {
		t.Fatal("digests did not survive")
	}
}

// TestEncodeMediaMessageDocument pins the document fields: name and title are
// what the recipient's client shows in a file bubble.
func TestEncodeMediaMessageDocument(t *testing.T) {
	m := mediaMessage()
	m.Kind = PayloadDocument
	m.MimeType = "application/pdf"
	m.FileName = "laporan.pdf"
	m.Title = "laporan"
	m.Caption = ""
	raw, err := EncodeMediaMessage(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var message protobuf.Message
	if err := proto.Unmarshal(raw, &message); err != nil {
		t.Fatal(err)
	}
	doc := message.GetDocumentMessage()
	if doc == nil {
		t.Fatal("documentMessage missing")
	}
	if doc.GetFileName() != "laporan.pdf" || doc.GetTitle() != "laporan" || doc.GetMimetype() != "application/pdf" {
		t.Fatalf("document = %#v", doc)
	}
}

// TestEncodeMediaMessageRejectsIncomplete fails closed on every field a
// download or a decrypt needs.
func TestEncodeMediaMessageRejectsIncomplete(t *testing.T) {
	cases := map[string]func(*MediaMessage){
		"kind":      func(m *MediaMessage) { m.Kind = PayloadText },
		"url":       func(m *MediaMessage) { m.URL = "" },
		"direct":    func(m *MediaMessage) { m.DirectPath = "" },
		"mime":      func(m *MediaMessage) { m.MimeType = "" },
		"key":       func(m *MediaMessage) { m.MediaKey = []byte{1} },
		"file hash": func(m *MediaMessage) { m.FileSHA256 = nil },
		"enc hash":  func(m *MediaMessage) { m.FileEncSHA256 = make([]byte, 31) },
		"length":    func(m *MediaMessage) { m.FileLength = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := mediaMessage()
			mutate(&m)
			if _, err := EncodeMediaMessage(m); err == nil {
				t.Fatal("incomplete media accepted")
			}
		})
	}
}
