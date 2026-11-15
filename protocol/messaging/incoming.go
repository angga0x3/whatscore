package messaging

import (
	"fmt"
	"strconv"
	"time"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// IncomingText is a text message received from another user or group.
type IncomingText struct {
	ID          string
	From        JID
	Participant JID
	Text        string
	Timestamp   time.Time
}

// ParseIncomingText parses a <message type="text"> stanza that uses "from"
// instead of "to". Unknown children (enc, meta, ...) are ignored.
func ParseIncomingText(node *binary.Node) (*IncomingText, error) {
	if node == nil || node.Tag != tagMessage {
		return nil, fmt.Errorf("%w: expected %q, got %s", ErrInvalidMessage, tagMessage, tagOf(node))
	}
	if msgType := node.Attrs["type"]; msgType != MessageTypeText {
		return nil, fmt.Errorf("%w: type %q is not %q", ErrInvalidMessage, msgType, MessageTypeText)
	}
	from, err := ParseJID(node.Attrs["from"])
	if err != nil {
		return nil, fmt.Errorf("%w: from: %w", ErrInvalidMessage, err)
	}
	if from.User == "" {
		return nil, fmt.Errorf("%w: from %q has no user", ErrInvalidMessage, from)
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

	incoming := &IncomingText{ID: id, From: from, Text: string(body.Bytes)}
	if participant := node.Attrs["participant"]; participant != "" {
		incoming.Participant, err = ParseJID(participant)
		if err != nil {
			return nil, fmt.Errorf("%w: participant: %w", ErrInvalidMessage, err)
		}
		if incoming.Participant.User == "" {
			return nil, fmt.Errorf("%w: participant %q has no user", ErrInvalidMessage, participant)
		}
	}
	if raw := node.Attrs["t"]; raw != "" {
		seconds, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: t %q is not unix seconds", ErrInvalidMessage, raw)
		}
		incoming.Timestamp = time.Unix(seconds, 0).UTC()
	}
	return incoming, nil
}
