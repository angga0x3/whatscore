package messaging

import (
	"errors"
	"fmt"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// Chat-state stanzas (whatsmeow SendChatPresence): the typing indicator a
// client sends while composing and the paused marker when it stops. The node
// carries no id — the server routes it by the to address and the child tag.
//
//	<chatstate to="chat"><composing/></chatstate>
//	<chatstate to="chat"><paused/></chatstate>

const (
	TagChatState  = "chatstate"
	ChatComposing = "composing"
	ChatPaused    = "paused"
)

// ErrInvalidChatState is returned for malformed chat-state stanzas.
var ErrInvalidChatState = errors.New("messaging: invalid chatstate")

// BuildChatState builds the typing-indicator stanza for chat: composing
// while the user types, paused when they stop.
func BuildChatState(chat JID, composing bool) (*binary.Node, error) {
	if err := chat.validateAddress(); err != nil {
		return nil, fmt.Errorf("%w: to: %w", ErrInvalidChatState, err)
	}
	if chat.User == "" {
		return nil, fmt.Errorf("%w: to %q has no user", ErrInvalidChatState, chat)
	}
	state := ChatPaused
	if composing {
		state = ChatComposing
	}
	return &binary.Node{
		Tag:      TagChatState,
		Attrs:    binary.Attrs{"to": chat.String()},
		Children: []binary.Node{{Tag: state}},
	}, nil
}
