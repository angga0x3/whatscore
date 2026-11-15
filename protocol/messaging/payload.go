package messaging

import (
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
