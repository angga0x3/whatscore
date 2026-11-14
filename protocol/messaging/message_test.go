package messaging

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
)

func TestBuildParseTextMessage(t *testing.T) {
	target := JID{User: "6281234567890", Server: UserServer}
	texts := []string{
		"hello",
		"",
		"héllo 👋\nsecond line",
		strings.Repeat("x", 4096),
		"<body>not markup</body>",
	}
	for i, tc := range texts {
		t.Run(fmt.Sprintf("text %d", i), func(t *testing.T) {
			want := TextMessage{ID: "3EB0C0FFEE", To: target, Text: tc}

			node, err := BuildTextMessage(want)
			if err != nil {
				t.Fatalf("BuildTextMessage: %v", err)
			}
			if node.Tag != "message" {
				t.Fatalf("tag = %q", node.Tag)
			}
			if len(node.Attrs) != 3 {
				t.Fatalf("attrs = %#v, want to/type/id only", node.Attrs)
			}
			if node.Attrs["to"] != target.String() || node.Attrs["id"] != want.ID || node.Attrs["type"] != MessageTypeText {
				t.Fatalf("attrs = %#v", node.Attrs)
			}
			if len(node.Children) != 1 || node.Children[0].Tag != "body" {
				t.Fatalf("children = %#v", node.Children)
			}

			got := parseThroughCodec(t, node)
			if got == nil {
				t.Fatal("parse returned nil")
			}
			if *got != want {
				t.Fatalf("round trip = %#v, want %#v", *got, want)
			}
		})
	}
}

// parseThroughCodec encodes, decodes, and parses a message stanza, asserting
// the re-encoded bytes are stable.
func parseThroughCodec(t *testing.T, node *binary.Node) *TextMessage {
	t.Helper()
	codec := binary.NewCodec(nil)

	wire, err := codec.Encode(node)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := codec.Decode(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	again, err := codec.Encode(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(wire, again) {
		t.Fatalf("re-encode is not byte-stable:\n%x\n%x", wire, again)
	}

	got, err := ParseTextMessage(decoded)
	if err != nil {
		t.Fatalf("ParseTextMessage: %v", err)
	}
	return got
}

func TestParseTextMessageIgnoresUnknownChildren(t *testing.T) {
	node := &binary.Node{
		Tag:   "message",
		Attrs: binary.Attrs{"to": "6281234567890@s.whatsapp.net", "id": "ABC", "type": "text"},
		Children: []binary.Node{
			{Tag: "enc", Attrs: binary.Attrs{"v": "2", "type": "msg"}, Bytes: []byte{0x08, 0x01}},
			{Tag: "body", Bytes: []byte("hello")},
			{Tag: "meta", Attrs: binary.Attrs{"appdata": "default"}},
		},
	}
	got, err := ParseTextMessage(node)
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != "hello" || got.ID != "ABC" {
		t.Fatalf("parsed = %#v", got)
	}
}

func TestBuildTextMessageInvalid(t *testing.T) {
	valid := TextMessage{ID: "ABC", To: JID{User: "6281234567890", Server: UserServer}, Text: "hi"}
	cases := map[string]TextMessage{
		"zero to":         {ID: "ABC", Text: "hi"},
		"server only to":  {ID: "ABC", To: JID{Server: UserServer}, Text: "hi"},
		"device to":       {ID: "ABC", To: JID{User: "6281234567890", Device: 2, Server: UserServer}, Text: "hi"},
		"empty id":        {To: valid.To, Text: "hi"},
		"whitespace id":   {ID: "A B", To: valid.To, Text: "hi"},
		"tab in id":       {ID: "A\tB", To: valid.To, Text: "hi"},
		"at in user":      {ID: "ABC", To: JID{User: "a@b", Server: UserServer}, Text: "hi"},
		"space in server": {ID: "ABC", To: JID{User: "a", Server: "s.whatsapp.net "}, Text: "hi"},
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildTextMessage(msg); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("want ErrInvalidMessage, got %v", err)
			}
		})
	}
}

func TestParseTextMessageInvalid(t *testing.T) {
	base := func() *binary.Node {
		return &binary.Node{
			Tag:      "message",
			Attrs:    binary.Attrs{"to": "6281234567890@s.whatsapp.net", "id": "ABC", "type": "text"},
			Children: []binary.Node{{Tag: "body", Bytes: []byte("hi")}},
		}
	}
	cases := map[string]*binary.Node{
		"nil":             nil,
		"wrong tag":       {Tag: "receipt"},
		"missing to":      {Tag: "message", Attrs: binary.Attrs{"id": "ABC", "type": "text"}, Children: base().Children},
		"empty to":        {Tag: "message", Attrs: binary.Attrs{"to": "", "id": "ABC", "type": "text"}, Children: base().Children},
		"bad to":          {Tag: "message", Attrs: binary.Attrs{"to": "a@b@c", "id": "ABC", "type": "text"}, Children: base().Children},
		"server only to":  {Tag: "message", Attrs: binary.Attrs{"to": "s.whatsapp.net", "id": "ABC", "type": "text"}, Children: base().Children},
		"missing id":      {Tag: "message", Attrs: binary.Attrs{"to": "628@s.whatsapp.net", "type": "text"}, Children: base().Children},
		"missing type":    {Tag: "message", Attrs: binary.Attrs{"to": "628@s.whatsapp.net", "id": "ABC"}, Children: base().Children},
		"media type":      {Tag: "message", Attrs: binary.Attrs{"to": "628@s.whatsapp.net", "id": "ABC", "type": "media"}, Children: base().Children},
		"no body":         {Tag: "message", Attrs: base().Attrs},
		"empty children":  {Tag: "message", Attrs: base().Attrs, Children: []binary.Node{{Tag: "enc"}}},
		"body has kids":   {Tag: "message", Attrs: base().Attrs, Children: []binary.Node{{Tag: "body", Children: []binary.Node{{Tag: "x"}}}}},
		"body no content": {Tag: "message", Attrs: base().Attrs, Children: []binary.Node{{Tag: "body"}}},
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTextMessage(node); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("want ErrInvalidMessage, got %v", err)
			}
		})
	}
}

func TestBuildTextMessageEscapesNothing(t *testing.T) {
	// Text is carried as bytes, not markup: a value that looks like XML must
	// survive unchanged and must not create extra children.
	msg := TextMessage{
		ID:   "ABC",
		To:   JID{User: "6281234567890", Server: UserServer},
		Text: `<message to="x"><body>nested</body></message>`,
	}
	node, err := BuildTextMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(node.Children) != 1 {
		t.Fatalf("children = %d, want 1", len(node.Children))
	}
	got, err := ParseTextMessage(node)
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != msg.Text {
		t.Fatalf("text = %q, want %q", got.Text, msg.Text)
	}
}
