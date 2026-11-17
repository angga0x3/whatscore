package protobuf

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestProtocolMessageTypeIsFieldTwo pins the reference field number. This
// project declared `type` as field 1 for a long time; a live group message
// then decoded its type as absent (REVOKE by default) while the wire carried
// field 2, and the reference proto confirmed field 1 is the revoke/edit key
// (PF-094).
func TestProtocolMessageTypeIsFieldTwo(t *testing.T) {
	raw, err := proto.Marshal(&Message{
		ProtocolMessage: &ProtocolMessage{
			Type: ProtocolMessage_APP_STATE_SYNC_KEY_REQUEST.Enum(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Message.protocolMessage = 12 → 0x62; ProtocolMessage.type = 2 varint →
	// 0x10, then the enum value 7.
	want := []byte{0x62, 0x02, 0x10, 0x07}
	if len(raw) != len(want) {
		t.Fatalf("payload = % x, want % x", raw, want)
	}
	for i := range want {
		if raw[i] != want[i] {
			t.Fatalf("payload = % x, want % x", raw, want)
		}
	}
}

// TestProtocolMessageTypeDecodesFromFieldTwo is the read half: a message the
// reference would send (type = 5, history sync) decodes as that type.
func TestProtocolMessageTypeDecodesFromFieldTwo(t *testing.T) {
	raw := []byte{0x62, 0x02, 0x10, 0x05}
	var message Message
	if err := proto.Unmarshal(raw, &message); err != nil {
		t.Fatal(err)
	}
	if got := message.GetProtocolMessage().GetType(); got != ProtocolMessage_HISTORY_SYNC_NOTIFICATION {
		t.Fatalf("type = %v, want HISTORY_SYNC_NOTIFICATION", got)
	}
}
