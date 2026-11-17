package messaging

import (
	"errors"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// TestBuildDeviceQuery pins the usync shape: one query for the devices of the
// chat and the account, because a DM is encrypted per device, not per account.
func TestBuildDeviceQuery(t *testing.T) {
	node, err := BuildDeviceQuery("42", []string{"628555@s.whatsapp.net", "628994340905:39@s.whatsapp.net"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if node.Tag != "iq" || node.Attrs["type"] != "get" || node.Attrs["xmlns"] != "usync" ||
		node.Attrs["to"] != "s.whatsapp.net" || node.Attrs["id"] != "42" {
		t.Fatalf("iq attrs = %#v", node.Attrs)
	}
	usync := node.Children[0]
	if usync.Tag != "usync" || usync.Attrs["sid"] != "42" || usync.Attrs["mode"] != "query" ||
		usync.Attrs["context"] != "message" || usync.Attrs["last"] != "true" || usync.Attrs["index"] != "0" {
		t.Fatalf("usync attrs = %#v", usync.Attrs)
	}
	if usync.Children[0].Tag != "query" || usync.Children[0].Children[0].Tag != "devices" {
		t.Fatalf("query = %#v", usync.Children[0])
	}
	list := usync.Children[1]
	if list.Tag != "list" || len(list.Children) != 2 {
		t.Fatalf("list = %#v", list)
	}
	// The account address is asked for without its device suffix: the answer
	// names every device, including this one, which the sender then skips.
	if list.Children[1].Attrs["jid"] != "628994340905@s.whatsapp.net" {
		t.Fatalf("account user = %#v", list.Children[1].Attrs)
	}

	if _, err := BuildDeviceQuery("", []string{"628555@s.whatsapp.net"}); err == nil {
		t.Fatal("empty id accepted")
	}
	if _, err := BuildDeviceQuery("1", nil); err == nil {
		t.Fatal("empty account list accepted")
	}
	if _, err := BuildDeviceQuery("1", []string{"bad jid@s.whatsapp.net"}); err == nil {
		t.Fatal("bad account accepted")
	}
}

// TestParseDeviceQuery reads the reply the server actually sends: one <user>
// per account, whose <device-list> children are the devices to encrypt for.
func TestParseDeviceQuery(t *testing.T) {
	reply := &binary.Node{
		Tag:   "iq",
		Attrs: binary.Attrs{"type": "result"},
		Children: []binary.Node{{
			Tag: "usync", Children: []binary.Node{{
				Tag: "list", Children: []binary.Node{{
					Tag: "user", Attrs: binary.Attrs{"jid": "628555@s.whatsapp.net"},
					Children: []binary.Node{{
						Tag: "devices", Children: []binary.Node{{
							Tag: "device-list", Children: []binary.Node{
								{Tag: "device", Attrs: binary.Attrs{"id": "0"}},
								{Tag: "device", Attrs: binary.Attrs{"id": "12"}},
							},
						}},
					}},
				}},
			}},
		}},
	}
	devices, err := ParseDeviceQuery(reply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("devices = %v", devices)
	}
	// Device 0 is the bare user JID; the list is sorted for deterministic
	// participant order, and ':' sorts before '@'.
	if devices[0] != "628555:12@s.whatsapp.net" || devices[1] != "628555@s.whatsapp.net" {
		t.Fatalf("devices = %v", devices)
	}
}

// TestParseDeviceQueryFailsClosed keeps a missing or unusable list from
// becoming an account-wide send, which is exactly the shape that leaves other
// devices showing "waiting for this message".
func TestParseDeviceQueryFailsClosed(t *testing.T) {
	usyncUser := func(children ...binary.Node) *binary.Node {
		return &binary.Node{Tag: "usync", Children: []binary.Node{{
			Tag: "list", Children: []binary.Node{{
				Tag: "user", Attrs: binary.Attrs{"jid": "628555@s.whatsapp.net"}, Children: children,
			}},
		}}}
	}
	usyncDevices := func(entries ...binary.Node) *binary.Node {
		return usyncUser(binary.Node{Tag: "devices", Children: []binary.Node{{
			Tag: "device-list", Children: entries,
		}}})
	}
	cases := map[string]*binary.Node{
		"nil":        nil,
		"error iq":   {Tag: "iq", Attrs: binary.Attrs{"type": "error"}},
		"no usync":   {Tag: "iq", Attrs: binary.Attrs{"type": "result"}},
		"no list":    {Tag: "iq", Attrs: binary.Attrs{"type": "result"}, Children: []binary.Node{{Tag: "usync"}}},
		"no devices": {Tag: "iq", Attrs: binary.Attrs{"type": "result"}, Children: []binary.Node{*usyncUser()}},
		"no entries": {Tag: "iq", Attrs: binary.Attrs{"type": "result"}, Children: []binary.Node{*usyncDevices()}},
		"bad id": {Tag: "iq", Attrs: binary.Attrs{"type": "result"},
			Children: []binary.Node{*usyncDevices(binary.Node{Tag: "device", Attrs: binary.Attrs{"id": "x"}})}},
		"hosted": {Tag: "iq", Attrs: binary.Attrs{"type": "result"},
			Children: []binary.Node{*usyncDevices(binary.Node{Tag: "device", Attrs: binary.Attrs{"id": "1", "is_hosted": "true"}})}},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDeviceQuery(reply); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
