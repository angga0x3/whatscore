package messaging

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// BuildDeviceQuery asks for the device list used for message encryption.
func BuildDeviceQuery(id string, accounts []string) (*binary.Node, error) {
	if err := validateMessageID(id); err != nil {
		return nil, err
	}
	users := make([]binary.Node, 0, len(accounts))
	seen := map[string]bool{}
	for _, raw := range accounts {
		jid, err := ParseJID(raw)
		if err != nil || jid.User == "" || (jid.Server != UserServer && jid.Server != "lid") {
			return nil, fmt.Errorf("%w: invalid device-query account %q", ErrInvalidMessage, raw)
		}
		jid.Device = 0
		if !seen[jid.String()] {
			users = append(users, binary.Node{Tag: "user", Attrs: binary.Attrs{"jid": jid.String()}})
			seen[jid.String()] = true
		}
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("%w: empty device query", ErrInvalidMessage)
	}
	return &binary.Node{Tag: "iq", Attrs: binary.Attrs{
		"id": id, "to": "s.whatsapp.net", "xmlns": "usync", "type": "get",
	}, Children: []binary.Node{{Tag: "usync", Attrs: binary.Attrs{
		"sid": id, "mode": "query", "context": "message", "last": "true", "index": "0",
	}, Children: []binary.Node{
		{Tag: "query", Children: []binary.Node{{Tag: "devices", Attrs: binary.Attrs{"version": "2"}}}},
		{Tag: "list", Children: users},
	}}}}, nil
}

// ParseDeviceQuery reads only explicit device entries. An absent list must
// never silently become an account-wide encrypted send.
func ParseDeviceQuery(reply *binary.Node) ([]string, error) {
	if reply == nil || reply.Tag != "iq" || reply.Attrs["type"] != "result" {
		return nil, fmt.Errorf("%w: device query failed", ErrInvalidMessage)
	}
	usync := firstChild(reply, "usync")
	if usync == nil {
		return nil, fmt.Errorf("%w: no usync result", ErrInvalidMessage)
	}
	list := firstChild(usync, "list")
	if list == nil {
		return nil, fmt.Errorf("%w: no device list", ErrInvalidMessage)
	}
	seen := map[string]bool{}
	for i := range list.Children {
		user := &list.Children[i]
		if user.Tag != "user" {
			continue
		}
		jid, err := ParseJID(user.Attrs["jid"])
		if err != nil || jid.User == "" || (jid.Server != UserServer && jid.Server != "lid") {
			return nil, fmt.Errorf("%w: invalid device-list user", ErrInvalidMessage)
		}
		devices := firstChild(user, "devices")
		if devices == nil {
			return nil, fmt.Errorf("%w: no devices for %s", ErrInvalidMessage, jid.String())
		}
		entries := firstChild(devices, "device-list")
		if entries == nil {
			return nil, fmt.Errorf("%w: missing device-list for %s", ErrInvalidMessage, jid.String())
		}
		for _, device := range entries.Children {
			if device.Tag != "device" {
				continue
			}
			if device.Attrs["is_hosted"] == "true" || device.Attrs["is_hosted"] == "1" {
				return nil, fmt.Errorf("%w: hosted devices are unsupported", ErrInvalidMessage)
			}
			id, err := strconv.ParseUint(device.Attrs["id"], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid device id", ErrInvalidMessage)
			}
			jid.Device = uint16(id)
			seen[jid.String()] = true
		}
	}
	devices := make([]string, 0, len(seen))
	for device := range seen {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	if len(devices) == 0 {
		return nil, fmt.Errorf("%w: no recipient devices", ErrInvalidMessage)
	}
	return devices, nil
}
