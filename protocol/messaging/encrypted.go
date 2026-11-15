package messaging

import (
	"fmt"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// Encrypted message constants (PF-036).
const (
	tagEnc       = "enc"
	attrVersion  = "v"
	attrCarrier  = "type"
	EncVersion2  = "2"
	CarrierMsg   = "msg"
	CarrierPKMsg = "pkmsg"
	CarrierSKMsg = "skmsg"
)

// EncryptedText is an encrypted text message: the plaintext message envelope
// plus the Signal ciphertext in an <enc> child (PF-036).
type EncryptedText struct {
	ID         string
	To         JID
	Version    string
	Carrier    string
	Ciphertext []byte
}

// BuildEncryptedText builds `<message id to type="text"><enc v=... type=...>`
// with the ciphertext as content.
func BuildEncryptedText(message EncryptedText) (*binary.Node, error) {
	if err := message.To.validateAddress(); err != nil {
		return nil, fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if message.To.Device > 0 {
		return nil, fmt.Errorf("%w: to %q is device-qualified", ErrInvalidMessage, message.To)
	}
	if err := validateMessageID(message.ID); err != nil {
		return nil, err
	}
	if message.Version == "" {
		message.Version = EncVersion2
	}
	if message.Version != EncVersion2 {
		return nil, fmt.Errorf("%w: unsupported enc version %q", ErrInvalidMessage, message.Version)
	}
	switch message.Carrier {
	case CarrierMsg, CarrierPKMsg, CarrierSKMsg:
	case "":
		return nil, fmt.Errorf("%w: empty enc carrier", ErrInvalidMessage)
	default:
		return nil, fmt.Errorf("%w: unknown enc carrier %q", ErrInvalidMessage, message.Carrier)
	}
	if len(message.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: empty ciphertext", ErrInvalidMessage)
	}
	return &binary.Node{
		Tag: tagMessage,
		Attrs: binary.Attrs{
			"id":   message.ID,
			"to":   message.To.String(),
			"type": MessageTypeText,
		},
		Children: []binary.Node{{
			Tag:   tagEnc,
			Attrs: binary.Attrs{attrVersion: message.Version, attrCarrier: message.Carrier},
			Bytes: append([]byte(nil), message.Ciphertext...),
		}},
	}, nil
}

// ParseEncryptedText reads the envelope and the first <enc> child.
func ParseEncryptedText(node *binary.Node) (*EncryptedText, error) {
	if node == nil || node.Tag != tagMessage {
		return nil, fmt.Errorf("%w: expected %q, got %s", ErrInvalidMessage, tagMessage, tagOf(node))
	}
	if msgType := node.Attrs["type"]; msgType != MessageTypeText {
		return nil, fmt.Errorf("%w: type %q is not %q", ErrInvalidMessage, msgType, MessageTypeText)
	}
	to, err := ParseJID(node.Attrs["to"])
	if err != nil {
		return nil, fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if to.User == "" {
		return nil, fmt.Errorf("%w: to %q has no user", ErrInvalidMessage, to)
	}
	id := node.Attrs["id"]
	if err := validateMessageID(id); err != nil {
		return nil, err
	}
	enc := firstChild(node, tagEnc)
	if enc == nil {
		return nil, fmt.Errorf("%w: no %q child", ErrInvalidMessage, tagEnc)
	}
	if len(enc.Children) > 0 || enc.Bytes == nil || len(enc.Bytes) == 0 {
		return nil, fmt.Errorf("%w: %q child has no usable content", ErrInvalidMessage, tagEnc)
	}
	version := enc.Attrs[attrVersion]
	if version != EncVersion2 {
		return nil, fmt.Errorf("%w: unsupported enc version %q", ErrInvalidMessage, version)
	}
	switch carrier := enc.Attrs[attrCarrier]; carrier {
	case CarrierMsg, CarrierPKMsg, CarrierSKMsg:
		return &EncryptedText{
			ID: id, To: to, Version: version, Carrier: carrier,
			Ciphertext: append([]byte(nil), enc.Bytes...),
		}, nil
	default:
		return nil, fmt.Errorf("%w: unknown enc carrier %q", ErrInvalidMessage, enc.Attrs[attrCarrier])
	}
}
