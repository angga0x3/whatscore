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
	// The parse side reads the inbound shape: the service stamps "from" onto
	// what it delivers. The built node carries "to" only, so the round trip
	// adds the sender the live wire would have.
	decoded.Attrs["from"] = "628999@s.whatsapp.net"
	got, err := ParseEncryptedText(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.To != want.To || got.Version != want.Version ||
		got.Carrier != want.Carrier || !bytes.Equal(got.Ciphertext, want.Ciphertext) {
		t.Fatalf("parsed = %#v", got)
	}
	if got.From.User != "628999" || got.From.Server != UserServer {
		t.Fatalf("from = %s", got.From)
	}
}

// TestParseEncryptedTextWithoutTo pins the live inbound shape: the offline
// queue replay arrives with "from" alone, and refusing it for a missing "to"
// is what kept every queued message from being decrypted (PF-087).
func TestParseEncryptedTextWithoutTo(t *testing.T) {
	node := &binary.Node{
		Tag: tagMessage,
		Attrs: binary.Attrs{
			"id": "LIVE1", "from": "266988689592415:35@lid", "type": MessageTypeText,
		},
		Children: []binary.Node{{
			Tag: tagEnc, Attrs: binary.Attrs{attrVersion: EncVersion2, attrCarrier: CarrierPKMsg},
			Bytes: []byte{0x07},
		}},
	}
	got, err := ParseEncryptedText(node)
	if err != nil {
		t.Fatalf("live shape rejected: %v", err)
	}
	if !got.To.IsEmpty() {
		t.Fatalf("to = %s, want empty", got.To)
	}
	if got.From.String() != "266988689592415:35@lid" {
		t.Fatalf("from = %s", got.From)
	}
}

// TestParseEncryptedTextRequiresFrom keeps the sender mandatory: without it
// the session lookup has no peer to name.
func TestParseEncryptedTextRequiresFrom(t *testing.T) {
	node := &binary.Node{
		Tag:   tagMessage,
		Attrs: binary.Attrs{"id": "LIVE2", "type": MessageTypeText},
		Children: []binary.Node{{
			Tag: tagEnc, Attrs: binary.Attrs{attrVersion: EncVersion2, attrCarrier: CarrierMsg},
			Bytes: []byte{0x07},
		}},
	}
	if _, err := ParseEncryptedText(node); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("err = %v, want ErrInvalidMessage", err)
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

// TestBuildEncryptedTextPeerAddressing pins the two shapes a device-qualified
// destination has: refused by default (the server fans out to the account's
// devices), and allowed when the caller means exactly one device — the
// own-device copy and a retry receipt do. The second shape carries
// device_fanout="false", because there is nothing left to fan out.
func TestBuildEncryptedTextPeerAddressing(t *testing.T) {
	deviceJID := JID{User: "266988689592415", Device: 39, Server: "lid"}
	message := EncryptedText{ID: "P1", To: deviceJID, Carrier: CarrierMsg, Ciphertext: []byte{1, 2, 3}}

	if _, err := BuildEncryptedText(message); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("device-qualified to accepted without Peer: %v", err)
	}

	message.Peer = true
	node, err := BuildEncryptedText(message)
	if err != nil {
		t.Fatalf("peer-addressed build: %v", err)
	}
	if got := node.Attrs["to"]; got != "266988689592415:39@lid" {
		t.Fatalf("to = %q", got)
	}
	if got := node.Attrs["device_fanout"]; got != "false" {
		t.Fatalf("device_fanout = %q, want false", got)
	}

	// An account address is unaffected: no fan-out attribute is invented.
	node, err = BuildEncryptedText(EncryptedText{
		ID: "P2", To: JID{User: "628123", Server: UserServer}, Carrier: CarrierMsg, Ciphertext: []byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := node.Attrs["device_fanout"]; ok {
		t.Fatal("account-addressed stanza carries device_fanout")
	}
}

// TestParseEncryptedTextReadsTheParticipant pins the group shape: "from" is
// the group and "participant" is the member whose device wrote the stanza,
// which is the only address that names a Signal session.
func TestParseEncryptedTextReadsTheParticipant(t *testing.T) {
	node := &binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id": "G1", "from": "120363046767601853@g.us", "type": "text",
			"participant": "200506840473775@lid",
		},
		Children: []binary.Node{{
			Tag: "enc", Attrs: binary.Attrs{"v": "2", "type": CarrierPKMsg}, Bytes: []byte{7},
		}},
	}
	envelope, err := ParseEncryptedText(node)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if envelope.From.String() != "120363046767601853@g.us" {
		t.Fatalf("from = %q", envelope.From)
	}
	if envelope.Participant.String() != "200506840473775@lid" {
		t.Fatalf("participant = %q", envelope.Participant)
	}

	// A 1:1 stanza leaves it empty.
	node.Attrs = binary.Attrs{"id": "D1", "from": "628123@s.whatsapp.net", "type": "text"}
	envelope, err = ParseEncryptedText(node)
	if err != nil {
		t.Fatal(err)
	}
	if !envelope.Participant.IsEmpty() {
		t.Fatalf("participant = %q on a 1:1 stanza", envelope.Participant)
	}

	// A malformed participant is a malformed stanza.
	node.Attrs["participant"] = "not a jid"
	if _, err := ParseEncryptedText(node); err == nil {
		t.Fatal("malformed participant accepted")
	}
}
