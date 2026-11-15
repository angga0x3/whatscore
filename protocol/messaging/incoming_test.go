package messaging

import (
	"errors"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/protocol/binary"
)

func incomingNode(attrs binary.Attrs, body []byte) *binary.Node {
	return &binary.Node{
		Tag:      "message",
		Attrs:    attrs,
		Children: []binary.Node{{Tag: "body", Bytes: body}},
	}
}

func TestParseIncomingText(t *testing.T) {
	node := incomingNode(binary.Attrs{
		"id": "ABC", "type": "text", "from": "628123@s.whatsapp.net", "t": "1700000000",
	}, []byte("hello"))
	got, err := ParseIncomingText(node)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "ABC" || got.From.String() != "628123@s.whatsapp.net" || got.Text != "hello" {
		t.Fatalf("parsed = %#v", got)
	}
	if !got.Timestamp.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("timestamp = %v", got.Timestamp)
	}
	if !got.Participant.IsEmpty() {
		t.Fatalf("participant = %v", got.Participant)
	}

	group := incomingNode(binary.Attrs{
		"id": "G1", "type": "text", "from": "123@g.us", "participant": "456@s.whatsapp.net",
	}, []byte("group"))
	got, err = ParseIncomingText(group)
	if err != nil {
		t.Fatal(err)
	}
	if got.From.String() != "123@g.us" || got.Participant.String() != "456@s.whatsapp.net" {
		t.Fatalf("group parsed = %#v", got)
	}
}

func TestParseIncomingTextInvalid(t *testing.T) {
	cases := map[string]*binary.Node{
		"nil":             nil,
		"wrong tag":       {Tag: "iq"},
		"missing type":    incomingNode(binary.Attrs{"id": "x", "from": "1@s.whatsapp.net"}, []byte("x")),
		"wrong type":      incomingNode(binary.Attrs{"id": "x", "type": "image", "from": "1@s.whatsapp.net"}, []byte("x")),
		"server from":     incomingNode(binary.Attrs{"id": "x", "type": "text", "from": "s.whatsapp.net"}, []byte("x")),
		"bad from":        incomingNode(binary.Attrs{"id": "x", "type": "text", "from": "a b@s.whatsapp.net"}, []byte("x")),
		"empty id":        incomingNode(binary.Attrs{"type": "text", "from": "1@s.whatsapp.net"}, []byte("x")),
		"no body":         {Tag: "message", Attrs: binary.Attrs{"id": "x", "type": "text", "from": "1@s.whatsapp.net"}},
		"body children":   {Tag: "message", Attrs: binary.Attrs{"id": "x", "type": "text", "from": "1@s.whatsapp.net"}, Children: []binary.Node{{Tag: "body", Children: []binary.Node{{Tag: "x"}}}}},
		"bad timestamp":   incomingNode(binary.Attrs{"id": "x", "type": "text", "from": "1@s.whatsapp.net", "t": "soon"}, []byte("x")),
		"bad participant": incomingNode(binary.Attrs{"id": "x", "type": "text", "from": "1@g.us", "participant": "bad"}, []byte("x")),
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseIncomingText(node); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("want ErrInvalidMessage, got %v", err)
			}
		})
	}
}
