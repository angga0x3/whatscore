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
