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
	// MessageTypeMedia is the stanza type the live service stamps on
	// encrypted media messages (PF-089); "text" covers everything else.
	MessageTypeMedia = "media"
)

// EncryptedText is an encrypted text message: the plaintext message envelope
// plus the Signal ciphertext in an <enc> child (PF-036).
type EncryptedText struct {
	ID   string
	To   JID // the recipient on outbound stanzas; the live service omits it inbound
	From JID // the sender on inbound stanzas; the reference omits it outbound
	// Participant is the member whose device wrote a group stanza. "from" on
	// a group stanza is the group, so this is the only address that names a
	// Signal session. Empty on 1:1 stanzas.
	Participant JID
	Version     string
	Carrier     string
	Ciphertext  []byte
	// Type names the transport class: "text" (default) or "media". The live
	// service stamps "media" on encrypted image/sticker/video/audio/document
	// stanzas (PF-089); the payload inside decides what a client renders.
	Type string
	// Peer addresses one device of an account rather than the account. The
	// normal outbound shape names a user JID and the server fans out to its
	// devices; a device-qualified "to" is only legal when the sender means
	// exactly that device — the own-device copy and a retry receipt do
	// (whatsmeow's `SendRequestExtra{Peer: true}`). Such a stanza also
	// carries device_fanout="false", because there is nothing left to fan
	// out.
	Peer bool
}

// BuildEncryptedText builds `<message id to type="text"><enc v=... type=...>`
// with the ciphertext as content.
func BuildEncryptedText(message EncryptedText) (*binary.Node, error) {
	if err := message.To.validateAddress(); err != nil {
		return nil, fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if message.To.Device > 0 && !message.Peer {
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
	msgType := message.Type
	if msgType == "" {
		msgType = MessageTypeText
	}
	switch msgType {
	case MessageTypeText, MessageTypeMedia:
	default:
		return nil, fmt.Errorf("%w: unknown message type %q", ErrInvalidMessage, msgType)
	}
	attrs := binary.Attrs{
		"id":   message.ID,
		"to":   message.To.String(),
		"type": msgType,
	}
	if message.To.Device > 0 {
		// A device-addressed stanza goes to that device alone; the attribute
		// is what tells the server not to fan it out to the account's others.
		attrs["device_fanout"] = "false"
	}
	return &binary.Node{
		Tag:   tagMessage,
		Attrs: attrs,
		Children: []binary.Node{{
			Tag:   tagEnc,
			Attrs: binary.Attrs{attrVersion: message.Version, attrCarrier: message.Carrier},
			Bytes: append([]byte(nil), message.Ciphertext...),
		}},
	}, nil
}

// ParseEncryptedText reads the envelope and the first <enc> child.
//
// "to" is optional and "from" is required, reversing the outbound shape: the
// live service addresses inbound stanzas with "from" alone — the queue replay
// arrived with no "to" at all — while the peer that owns the session is the
// sender, not the recipient.
func ParseEncryptedText(node *binary.Node) (*EncryptedText, error) {
	if node == nil || node.Tag != tagMessage {
		return nil, fmt.Errorf("%w: expected %q, got %s", ErrInvalidMessage, tagMessage, tagOf(node))
	}
	// The stanza's type attr names the transport class, not the payload:
	// "text" carries conversation payloads, "media" carries image/sticker/
	// video/audio/document ones. DecodePayload decides what a decrypted
	// payload actually is, so the gate here only refuses types the live
	// service has never sent with an <enc> child.
	switch msgType := node.Attrs["type"]; msgType {
	case MessageTypeText, MessageTypeMedia:
	default:
		return nil, fmt.Errorf("%w: type %q is not a transport type this project has observed", ErrInvalidMessage, msgType)
	}
	envelope := &EncryptedText{ID: node.Attrs["id"]}
	if err := validateMessageID(envelope.ID); err != nil {
		return nil, err
	}
	if raw := node.Attrs["to"]; raw != "" {
		to, err := ParseJID(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
		}
		if to.User == "" {
			return nil, fmt.Errorf("%w: to %q has no user", ErrInvalidMessage, to)
		}
		envelope.To = to
	}
	from, err := ParseJID(node.Attrs["from"])
	if err != nil {
		return nil, fmt.Errorf("%w: from: %w", ErrInvalidMessage, err)
	}
	if from.User == "" {
		return nil, fmt.Errorf("%w: from %q has no user", ErrInvalidMessage, from)
	}
	envelope.From = from
	if raw := node.Attrs["participant"]; raw != "" {
		participant, err := ParseJID(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: participant: %w", ErrInvalidMessage, err)
		}
		if participant.User == "" {
			return nil, fmt.Errorf("%w: participant %q has no user", ErrInvalidMessage, participant)
		}
		envelope.Participant = participant
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
	envelope.Version = version
	switch carrier := enc.Attrs[attrCarrier]; carrier {
	case CarrierMsg, CarrierPKMsg, CarrierSKMsg:
		envelope.Carrier = carrier
		envelope.Ciphertext = append([]byte(nil), enc.Bytes...)
		return envelope, nil
	default:
		return nil, fmt.Errorf("%w: unknown enc carrier %q", ErrInvalidMessage, enc.Attrs[attrCarrier])
	}
}
