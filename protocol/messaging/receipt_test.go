package messaging

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/protocol/binary"
)

func TestBuildParseReceipt(t *testing.T) {
	chat := JID{User: "6281234567890", Server: UserServer}
	group := JID{User: "120363021234567890", Server: GroupServer}
	sender := JID{User: "6289999999999", Server: UserServer}

	cases := map[string]Receipt{
		"read": {
			ID:        "3EB0C0FFEE",
			To:        chat,
			Type:      ReceiptTypeRead,
			Timestamp: time.Unix(1700000000, 0).UTC(),
		},
		"delivered omits type and t": {
			ID: "3EB0C0FFEE",
			To: chat,
		},
		"read-self": {
			ID:        "3EB0C0FFEE",
			To:        chat,
			Type:      ReceiptTypeReadSelf,
			Timestamp: time.Unix(1700000001, 0).UTC(),
		},
		"group participant": {
			ID:          "3EB0C0FFEE",
			To:          group,
			Type:        ReceiptTypePlayed,
			Participant: sender,
			Timestamp:   time.Unix(1700000002, 0).UTC(),
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			node, err := BuildReceipt(want)
			if err != nil {
				t.Fatalf("BuildReceipt: %v", err)
			}
			if node.Tag != "receipt" {
				t.Fatalf("tag = %q", node.Tag)
			}
			wantAttrs := 2 // id, to
			if want.Type != "" {
				wantAttrs++
			}
			if !want.Participant.IsEmpty() {
				wantAttrs++
			}
			if !want.Timestamp.IsZero() {
				wantAttrs++
			}
			if len(node.Attrs) != wantAttrs {
				t.Fatalf("attrs = %#v, want %d entries", node.Attrs, wantAttrs)
			}

			codec := binary.NewCodec(nil)
			wire, err := codec.Encode(node)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			decoded, err := codec.Decode(bytes.NewReader(wire))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			got, err := ParseReceipt(decoded)
			if err != nil {
				t.Fatalf("ParseReceipt: %v", err)
			}
			if got.ID != want.ID || got.To != want.To || got.Type != want.Type || got.Participant != want.Participant {
				t.Fatalf("parsed = %#v, want %#v", *got, want)
			}
			if !got.Timestamp.Equal(want.Timestamp) {
				t.Fatalf("timestamp = %v, want %v", got.Timestamp, want.Timestamp)
			}
			if !got.Timestamp.IsZero() && got.Timestamp.Location() != time.UTC {
				t.Fatalf("timestamp location = %v, want UTC", got.Timestamp.Location())
			}
		})
	}
}

func TestBuildReceiptInvalid(t *testing.T) {
	chat := JID{User: "6281234567890", Server: UserServer}
	cases := map[string]Receipt{
		"empty id":        {To: chat},
		"zero to":         {ID: "ABC"},
		"server only to":  {ID: "ABC", To: JID{Server: UserServer}},
		"bad participant": {ID: "ABC", To: chat, Participant: JID{Server: GroupServer}},
	}
	for name, receipt := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildReceipt(receipt); !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("want ErrInvalidReceipt, got %v", err)
			}
		})
	}
}

func TestParseReceiptInvalid(t *testing.T) {
	valid := binary.Attrs{"id": "ABC", "to": "6281234567890@s.whatsapp.net"}
	cases := map[string]*binary.Node{
		"nil":             nil,
		"wrong tag":       {Tag: "message"},
		"missing id":      {Tag: "receipt", Attrs: binary.Attrs{"to": valid["to"]}},
		"missing to":      {Tag: "receipt", Attrs: binary.Attrs{"id": "ABC"}},
		"server only to":  {Tag: "receipt", Attrs: binary.Attrs{"id": "ABC", "to": "s.whatsapp.net"}},
		"bad to":          {Tag: "receipt", Attrs: binary.Attrs{"id": "ABC", "to": "a@b@c"}},
		"bad participant": {Tag: "receipt", Attrs: binary.Attrs{"id": "ABC", "to": valid["to"], "participant": "nope@"}},
		"bad timestamp":   {Tag: "receipt", Attrs: binary.Attrs{"id": "ABC", "to": valid["to"], "t": "yesterday"}},
		"batched receipt": {Tag: "receipt", Attrs: valid, Children: []binary.Node{{
			Tag:      "list",
			Children: []binary.Node{{Tag: "item", Attrs: binary.Attrs{"id": "DEF"}}},
		}}},
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReceipt(node); !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("want ErrInvalidReceipt, got %v", err)
			}
		})
	}
}

func TestReceiptTypeVocabulary(t *testing.T) {
	// The delivered type is the empty string: the attribute is omitted on the
	// wire (PF-035). Pinning it stops a future "cleanup" from writing
	// type="delivered", which the references never emit.
	if ReceiptTypeDelivered != "" {
		t.Fatalf("ReceiptTypeDelivered = %q, want empty", ReceiptTypeDelivered)
	}
	want := map[string]string{
		"sender":       ReceiptTypeSender,
		"retry":        ReceiptTypeRetry,
		"read":         ReceiptTypeRead,
		"read-self":    ReceiptTypeReadSelf,
		"played":       ReceiptTypePlayed,
		"played-self":  ReceiptTypePlayedSelf,
		"server-error": ReceiptTypeServerError,
		"inactive":     ReceiptTypeInactive,
		"peer_msg":     ReceiptTypePeerMsg,
		"hist_sync":    ReceiptTypeHistorySync,
	}
	for wantValue, got := range want {
		if got != wantValue {
			t.Fatalf("receipt type constant = %q, want %q", got, wantValue)
		}
	}
}

// TestBuildReceiptList pins the multi-id read receipt wire form (whatsmeow
// MarkRead): the first id rides the attrs, the rest under <list><item id>.
func TestBuildReceiptList(t *testing.T) {
	node, err := BuildReceipt(Receipt{
		ID:       "FIRST",
		To:       JID{User: "62817408010", Server: UserServer},
		Type:     "read",
		ExtraIDs: []string{"SECOND", "THIRD"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.Attrs["id"] != "FIRST" || node.Attrs["type"] != "read" {
		t.Fatalf("attrs = %#v", node.Attrs)
	}
	list := node.Children[0]
	if list.Tag != "list" || len(list.Children) != 2 {
		t.Fatalf("list = %#v", list)
	}
	if list.Children[0].Attrs["id"] != "SECOND" || list.Children[1].Attrs["id"] != "THIRD" {
		t.Fatalf("items = %#v", list.Children)
	}
}
