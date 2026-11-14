package messaging

import (
	"errors"
	"fmt"

	"github.com/angga0x3/whatscore/protocol/binary"
)

const (
	tagMessage = "message"
	tagBody    = "body"
)

// MessageTypeText is the <message type> value the reference uses for a text
// payload (PF-033).
const MessageTypeText = "text"

// ErrInvalidMessage is returned for malformed message stanzas.
var ErrInvalidMessage = errors.New("messaging: invalid message stanza")

// TextMessage is a text stanza: the required envelope fields plus the text
// carried by the <body> child.
type TextMessage struct {
	ID   string
	To   JID
	Text string
}

// BuildTextMessage builds the <message to type="text" id> stanza with one
// <body> child holding Text (PF-033, PF-034).
//
// To must be a full chat address (user and server) without a device: the
// reference refuses to send to a device-qualified JID outside the peer path.
// ID must be non-empty and free of whitespace. Text may be empty.
func BuildTextMessage(msg TextMessage) (*binary.Node, error) {
	if err := msg.To.validateAddress(); err != nil {
		return nil, fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if msg.To.Device > 0 {
		return nil, fmt.Errorf("%w: to %q is device-qualified", ErrInvalidMessage, msg.To)
	}
	if err := validateMessageID(msg.ID); err != nil {
		return nil, err
	}
	return &binary.Node{
		Tag: tagMessage,
		Attrs: binary.Attrs{
			"id":   msg.ID,
			"to":   msg.To.String(),
			"type": MessageTypeText,
		},
		Children: []binary.Node{{Tag: tagBody, Bytes: []byte(msg.Text)}},
	}, nil
}

// ParseTextMessage reads a <message type="text"> stanza produced by
// BuildTextMessage. Unknown children (enc, meta, device-identity, ...) are
// ignored; a missing, child-bearing, or contentless <body> is an error.
func ParseTextMessage(node *binary.Node) (*TextMessage, error) {
	if node == nil || node.Tag != tagMessage {
		return nil, fmt.Errorf("%w: expected %q, got %s", ErrInvalidMessage, tagMessage, tagOf(node))
	}

	to, err := ParseJID(node.Attrs["to"])
	if err != nil {
		return nil, fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if to.User == "" {
		return nil, fmt.Errorf("%w: to %q has no user", ErrInvalidMessage, to)
	}
	if msgType := node.Attrs["type"]; msgType != MessageTypeText {
		return nil, fmt.Errorf("%w: type %q is not %q", ErrInvalidMessage, msgType, MessageTypeText)
	}

	id := node.Attrs["id"]
	if err := validateMessageID(id); err != nil {
		return nil, err
	}

	body := firstChild(node, tagBody)
	if body == nil {
		return nil, fmt.Errorf("%w: no %q child", ErrInvalidMessage, tagBody)
	}
	if len(body.Children) > 0 {
		return nil, fmt.Errorf("%w: %q child has children", ErrInvalidMessage, tagBody)
	}
	if body.Bytes == nil {
		return nil, fmt.Errorf("%w: %q child has no content", ErrInvalidMessage, tagBody)
	}

	return &TextMessage{ID: id, To: to, Text: string(body.Bytes)}, nil
}

// validateMessageID enforces a non-empty ID with no whitespace. The reference
// generates opaque 20-character IDs and echoes server IDs verbatim.
func validateMessageID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty id", ErrInvalidMessage)
	}
	for i := 0; i < len(id); i++ {
		switch id[i] {
		case ' ', '\t', '\r', '\n':
			return fmt.Errorf("%w: id %q contains whitespace", ErrInvalidMessage, id)
		}
	}
	return nil
}

// firstChild returns the first child with the given tag, matching the
// reference's "first match wins" lookup.
func firstChild(node *binary.Node, tag string) *binary.Node {
	for i := range node.Children {
		if node.Children[i].Tag == tag {
			return &node.Children[i]
		}
	}
	return nil
}

func tagOf(node *binary.Node) string {
	if node == nil {
		return "<nil>"
	}
	return node.Tag
}
