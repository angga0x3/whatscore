package messaging

import (
	"bytes"
	"errors"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
)

func TestEncryptedTextRoundTrip(t *testing.T) {
	want := EncryptedText{
		ID:         "ENC1",
		To:         JID{User: "628123", Server: UserServer},
		Version:    EncVersion2,
		Carrier:    CarrierPKMsg,
		Ciphertext: []byte{0x01, 0x02, 0x03},
	}
	node, err := BuildEncryptedText(want)
	if err != nil {
		t.Fatal(err)
	}
	codec := binary.NewCodec(nil)
	frame, err := codec.Encode(node)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := codec.Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEncryptedText(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.To != want.To || got.Version != want.Version ||
		got.Carrier != want.Carrier || !bytes.Equal(got.Ciphertext, want.Ciphertext) {
		t.Fatalf("parsed = %#v", got)
	}
}

func TestEncryptedTextDefaults(t *testing.T) {
	node, err := BuildEncryptedText(EncryptedText{
		ID: "X", To: JID{User: "1", Server: UserServer}, Carrier: CarrierMsg, Ciphertext: []byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	enc := firstChild(node, tagEnc)
	if enc.Attrs[attrVersion] != EncVersion2 {
		t.Fatalf("version = %q", enc.Attrs[attrVersion])
	}
}

func TestEncryptedTextInvalid(t *testing.T) {
	valid := EncryptedText{
		ID: "X", To: JID{User: "1", Server: UserServer},
		Carrier: CarrierMsg, Ciphertext: []byte{1},
	}
	cases := map[string]EncryptedText{
		"empty id":        {To: valid.To, Carrier: CarrierMsg, Ciphertext: []byte{1}},
		"server to":       {ID: "X", To: JID{Server: UserServer}, Carrier: CarrierMsg, Ciphertext: []byte{1}},
		"device to":       {ID: "X", To: JID{User: "1", Device: 2, Server: UserServer}, Carrier: CarrierMsg, Ciphertext: []byte{1}},
		"bad version":     {ID: "X", To: valid.To, Version: "1", Carrier: CarrierMsg, Ciphertext: []byte{1}},
		"empty carrier":   {ID: "X", To: valid.To, Ciphertext: []byte{1}},
		"unknown carrier": {ID: "X", To: valid.To, Carrier: "x", Ciphertext: []byte{1}},
		"no ciphertext":   {ID: "X", To: valid.To, Carrier: CarrierMsg},
	}
	for name, message := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildEncryptedText(message); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("want ErrInvalidMessage, got %v", err)
			}
		})
	}

	parseCases := map[string]*binary.Node{
		"nil":        nil,
		"wrong tag":  {Tag: "iq"},
		"wrong type": {Tag: "message", Attrs: binary.Attrs{"id": "X", "to": "1@s.whatsapp.net", "type": "image"}},
		"no enc":     {Tag: "message", Attrs: binary.Attrs{"id": "X", "to": "1@s.whatsapp.net", "type": "text"}},
		"empty enc": {Tag: "message", Attrs: binary.Attrs{"id": "X", "to": "1@s.whatsapp.net", "type": "text"},
			Children: []binary.Node{{Tag: "enc", Attrs: binary.Attrs{"v": "2", "type": "msg"}}}},
		"bad version": {Tag: "message", Attrs: binary.Attrs{"id": "X", "to": "1@s.whatsapp.net", "type": "text"},
			Children: []binary.Node{{Tag: "enc", Attrs: binary.Attrs{"v": "1", "type": "msg"}, Bytes: []byte{1}}}},
		"bad carrier": {Tag: "message", Attrs: binary.Attrs{"id": "X", "to": "1@s.whatsapp.net", "type": "text"},
			Children: []binary.Node{{Tag: "enc", Attrs: binary.Attrs{"v": "2", "type": "x"}, Bytes: []byte{1}}}},
	}
	for name, node := range parseCases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEncryptedText(node); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("want ErrInvalidMessage, got %v", err)
			}
		})
	}
}
