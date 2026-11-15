package messaging

import (
	"errors"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/protocol/binary"
)

func TestParseIncomingReceipt(t *testing.T) {
	node := &binary.Node{Tag: "receipt", Attrs: binary.Attrs{
		"from": "628123@s.whatsapp.net", "id": "ABC", "type": "read", "t": "1700000000",
	}}
	got, err := ParseIncomingReceipt(node)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "ABC" || got.From.String() != "628123@s.whatsapp.net" || got.Type != "read" {
		t.Fatalf("receipt = %#v", got)
	}
	if !got.Timestamp.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("timestamp = %v", got.Timestamp)
	}
}

func TestParseIncomingReceiptsBatch(t *testing.T) {
	node := &binary.Node{
		Tag:   "receipt",
		Attrs: binary.Attrs{"from": "1@s.whatsapp.net", "id": "A", "t": "1700000000"},
		Children: []binary.Node{{Tag: "list", Children: []binary.Node{
			{Tag: "item", Attrs: binary.Attrs{"id": "B"}},
			{Tag: "other"},
			{Tag: "item", Attrs: binary.Attrs{"id": "C"}},
		}}},
	}
	got, err := ParseIncomingReceipts(node)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ID != "A" || got[1].ID != "B" || got[2].ID != "C" {
		t.Fatalf("receipts = %#v", got)
	}
	for _, receipt := range got {
		if receipt.From.String() != "1@s.whatsapp.net" || !receipt.Timestamp.Equal(time.Unix(1700000000, 0).UTC()) {
			t.Fatalf("receipt = %#v", receipt)
		}
	}
}

func TestParseIncomingReceiptInvalid(t *testing.T) {
	cases := map[string]*binary.Node{
		"nil":         nil,
		"wrong tag":   {Tag: "message"},
		"no from":     {Tag: "receipt", Attrs: binary.Attrs{"id": "x"}},
		"server from": {Tag: "receipt", Attrs: binary.Attrs{"from": "s.whatsapp.net", "id": "x"}},
		"no id":       {Tag: "receipt", Attrs: binary.Attrs{"from": "1@s.whatsapp.net"}},
		"bad id":      {Tag: "receipt", Attrs: binary.Attrs{"from": "1@s.whatsapp.net", "id": "a b"}},
		"bad t":       {Tag: "receipt", Attrs: binary.Attrs{"from": "1@s.whatsapp.net", "id": "x", "t": "soon"}},
		"empty list": {Tag: "receipt", Attrs: binary.Attrs{"from": "1@s.whatsapp.net"},
			Children: []binary.Node{{Tag: "list"}}},
		"bad item": {Tag: "receipt", Attrs: binary.Attrs{"from": "1@s.whatsapp.net"},
			Children: []binary.Node{{Tag: "list", Children: []binary.Node{{Tag: "item"}}}}},
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseIncomingReceipts(node); !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("want ErrInvalidReceipt, got %v", err)
			}
		})
	}
}
