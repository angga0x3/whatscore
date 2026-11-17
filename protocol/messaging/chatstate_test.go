package messaging

import (
	"bytes"
	"errors"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// TestBuildChatState pins the typing-indicator wire form: <chatstate to=chat>
// with a composing or paused child, and no id — the server routes by address.
func TestBuildChatState(t *testing.T) {
	chat := JID{User: "62817408010", Server: UserServer}
	for _, tc := range []struct {
		composing bool
		want      string
	}{
		{true, ChatComposing},
		{false, ChatPaused},
	} {
		node, err := BuildChatState(chat, tc.composing)
		if err != nil {
			t.Fatalf("composing=%v: %v", tc.composing, err)
		}
		if node.Tag != TagChatState {
			t.Fatalf("tag = %q", node.Tag)
		}
		if node.Attrs["to"] != chat.String() {
			t.Fatalf("to = %q", node.Attrs["to"])
		}
		if len(node.Children) != 1 || node.Children[0].Tag != tc.want {
			t.Fatalf("children = %#v, want one %q", node.Children, tc.want)
		}
		codec := binary.NewCodec(nil)
		frame, err := codec.Encode(node)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		back, err := codec.Decode(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if back.Children[0].Tag != tc.want {
			t.Fatalf("round trip lost the state child")
		}
	}
}

// TestBuildChatStateRejectsInvalidJID keeps the loud failure for an unusable
// chat address.
func TestBuildChatStateRejectsInvalidJID(t *testing.T) {
	if _, err := BuildChatState(JID{}, true); !errors.Is(err, ErrInvalidChatState) {
		t.Fatalf("err = %v, want ErrInvalidChatState", err)
	}
}
