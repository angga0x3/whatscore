package pairing

import (
	"errors"
	"fmt"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// ErrInvalidPairingNode is returned for malformed pairing stanzas.
var ErrInvalidPairingNode = errors.New("pairing: invalid pairing node")

// Tags of the pairing exchange (PF-016).
const (
	tagIQ          = "iq"
	tagPairDevice  = "pair-device"
	tagPairSuccess = "pair-success"
	tagRef         = "ref"
)

// ParsePairDevice returns the refs carried by the server's <pair-device>
// stanza. Unexpected child tags are skipped, matching the reference.
func ParsePairDevice(node *binary.Node) ([]string, error) {
	if node == nil || node.Tag != tagIQ {
		return nil, fmt.Errorf("%w: expected iq, got %v", ErrInvalidPairingNode, tagOf(node))
	}
	device := firstChild(node, tagPairDevice)
	if device == nil {
		return nil, fmt.Errorf("%w: no pair-device child", ErrInvalidPairingNode)
	}

	refs := make([]string, 0, len(device.Children))
	for i := range device.Children {
		child := &device.Children[i]
		if child.Tag != tagRef {
			continue
		}
		if len(child.Bytes) == 0 {
			return nil, fmt.Errorf("%w: empty ref", ErrInvalidPairingNode)
		}
		refs = append(refs, string(child.Bytes))
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf("%w: pair-device has no refs", ErrInvalidPairingNode)
	}
	return refs, nil
}

// PairDeviceAck builds the iq result that acknowledges a <pair-device>
// stanza, echoing its from and id attributes.
func PairDeviceAck(node *binary.Node) (*binary.Node, error) {
	if node == nil || node.Tag != tagIQ {
		return nil, fmt.Errorf("%w: expected iq, got %v", ErrInvalidPairingNode, tagOf(node))
	}
	from, id := node.Attrs["from"], node.Attrs["id"]
	if from == "" || id == "" {
		return nil, fmt.Errorf("%w: pair-device iq needs from and id", ErrInvalidPairingNode)
	}
	return &binary.Node{
		Tag:   tagIQ,
		Attrs: binary.Attrs{"to": from, "id": id, "type": "result"},
	}, nil
}

// PairSuccess is the parsed <pair-success> stanza (PF-016). Identity
// verification is not part of this parser; DeviceIdentity is the opaque
// protobuf container the caller must authenticate.
type PairSuccess struct {
	RequestID      string
	ID             string
	LID            string
	BusinessName   string
	Platform       string
	ClientProps    []byte
	DeviceIdentity []byte
}

// ParsePairSuccess parses the server's <iq><pair-success> stanza.
func ParsePairSuccess(node *binary.Node) (*PairSuccess, error) {
	if node == nil || node.Tag != tagIQ {
		return nil, fmt.Errorf("%w: expected iq, got %v", ErrInvalidPairingNode, tagOf(node))
	}
	success := firstChild(node, tagPairSuccess)
	if success == nil {
		return nil, fmt.Errorf("%w: no pair-success child", ErrInvalidPairingNode)
	}

	result := &PairSuccess{RequestID: node.Attrs["id"]}
	for i := range success.Children {
		child := &success.Children[i]
		switch child.Tag {
		case "device":
			if result.ID == "" {
				result.ID = child.Attrs["jid"]
				result.LID = child.Attrs["lid"]
			}
		case "biz":
			if result.BusinessName == "" {
				result.BusinessName = child.Attrs["name"]
			}
		case "platform":
			if result.Platform == "" {
				result.Platform = child.Attrs["name"]
			}
		case "client-props":
			if result.ClientProps == nil {
				result.ClientProps = cloneBytes(child.Bytes)
			}
		case "device-identity":
			if result.DeviceIdentity == nil {
				result.DeviceIdentity = cloneBytes(child.Bytes)
			}
		}
	}

	if result.ID == "" {
		return nil, fmt.Errorf("%w: pair-success has no device jid", ErrInvalidPairingNode)
	}
	if len(result.DeviceIdentity) == 0 {
		return nil, fmt.Errorf("%w: pair-success has no device-identity", ErrInvalidPairingNode)
	}
	return result, nil
}

func firstChild(node *binary.Node, tag string) *binary.Node {
	for i := range node.Children {
		if node.Children[i].Tag == tag {
			return &node.Children[i]
		}
	}
	return nil
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}

func tagOf(node *binary.Node) string {
	if node == nil {
		return "<nil>"
	}
	return node.Tag
}
