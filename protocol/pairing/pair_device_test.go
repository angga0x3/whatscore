package pairing

import (
	"bytes"
	"errors"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
)

func TestParsePairDevice(t *testing.T) {
	node := &binary.Node{
		Tag:   "iq",
		Attrs: binary.Attrs{"from": "s.whatsapp.net", "id": "req-1", "type": "set"},
		Children: []binary.Node{{
			Tag: "pair-device",
			Children: []binary.Node{
				{Tag: "ref", Bytes: []byte("ref-one")},
				{Tag: "unexpected"},
				{Tag: "ref", Bytes: []byte("ref-two")},
			},
		}},
	}
	refs, err := ParsePairDevice(node)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || refs[0] != "ref-one" || refs[1] != "ref-two" {
		t.Fatalf("refs = %v", refs)
	}

	ack, err := PairDeviceAck(node)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Tag != "iq" || ack.Attrs["to"] != "s.whatsapp.net" || ack.Attrs["id"] != "req-1" || ack.Attrs["type"] != "result" {
		t.Fatalf("ack = %#v", ack)
	}
}

func TestPairDeviceWireRoundTrip(t *testing.T) {
	codec := binary.NewCodec(nil)
	want := &binary.Node{
		Tag:   "iq",
		Attrs: binary.Attrs{"from": "s.whatsapp.net", "id": "req-1"},
		Children: []binary.Node{{
			Tag:      "pair-device",
			Children: []binary.Node{{Tag: "ref", Bytes: []byte("ref-one")}},
		}},
	}
	encoded, err := codec.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := codec.Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	refs, err := ParsePairDevice(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != "ref-one" {
		t.Fatalf("refs = %v", refs)
	}
}

func TestPairDeviceInvalid(t *testing.T) {
	cases := map[string]*binary.Node{
		"nil":                   nil,
		"wrong tag":             {Tag: "message"},
		"no child":              {Tag: "iq", Attrs: binary.Attrs{"from": "x", "id": "y"}},
		"empty ref":             {Tag: "iq", Children: []binary.Node{{Tag: "pair-device", Children: []binary.Node{{Tag: "ref"}}}}},
		"no refs":               {Tag: "iq", Children: []binary.Node{{Tag: "pair-device"}}},
		"unexpected child only": {Tag: "iq", Children: []binary.Node{{Tag: "pair-device", Children: []binary.Node{{Tag: "x"}}}}},
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePairDevice(node); !errors.Is(err, ErrInvalidPairingNode) {
				t.Fatalf("want ErrInvalidPairingNode, got %v", err)
			}
		})
	}

	if _, err := PairDeviceAck(&binary.Node{Tag: "iq", Attrs: binary.Attrs{"from": "x"}}); !errors.Is(err, ErrInvalidPairingNode) {
		t.Fatalf("ack without id: %v", err)
	}
}

func TestParsePairSuccess(t *testing.T) {
	node := &binary.Node{
		Tag:   "iq",
		Attrs: binary.Attrs{"id": "req-2", "type": "result"},
		Children: []binary.Node{{
			Tag: "pair-success",
			Children: []binary.Node{
				{Tag: "device", Attrs: binary.Attrs{"jid": "628123@s.whatsapp.net", "lid": "999@lid"}},
				{Tag: "biz", Attrs: binary.Attrs{"name": "Synthetic Biz"}},
				{Tag: "platform", Attrs: binary.Attrs{"name": "test-platform"}},
				{Tag: "client-props", Bytes: []byte{0x01, 0x02}},
				{Tag: "device-identity", Bytes: []byte{0x03, 0x04}},
			},
		}},
	}
	got, err := ParsePairSuccess(node)
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestID != "req-2" || got.ID != "628123@s.whatsapp.net" || got.LID != "999@lid" ||
		got.BusinessName != "Synthetic Biz" || got.Platform != "test-platform" ||
		!bytes.Equal(got.ClientProps, []byte{0x01, 0x02}) || !bytes.Equal(got.DeviceIdentity, []byte{0x03, 0x04}) {
		t.Fatalf("parsed = %#v", got)
	}
}

func TestPairSuccessInvalid(t *testing.T) {
	cases := map[string]*binary.Node{
		"nil":       nil,
		"wrong tag": {Tag: "message"},
		"no child":  {Tag: "iq", Attrs: binary.Attrs{"id": "x"}},
		"no jid": {Tag: "iq", Children: []binary.Node{{Tag: "pair-success", Children: []binary.Node{
			{Tag: "device-identity", Bytes: []byte{1}},
		}}}},
		"no identity": {Tag: "iq", Children: []binary.Node{{Tag: "pair-success", Children: []binary.Node{
			{Tag: "device", Attrs: binary.Attrs{"jid": "x@s.whatsapp.net"}},
		}}}},
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePairSuccess(node); !errors.Is(err, ErrInvalidPairingNode) {
				t.Fatalf("want ErrInvalidPairingNode, got %v", err)
			}
		})
	}
}
