package messaging

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"google.golang.org/protobuf/proto"

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
