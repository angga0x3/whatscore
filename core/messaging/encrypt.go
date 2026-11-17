package messaging

import (
	"context"
	"fmt"
	"strings"

	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// ErrNoSession is returned when an encrypted send has no established session.
var ErrNoSession = fmt.Errorf("%w: no signal session", ErrInvalidMessage)

// PeerSession is one established peer session used for encryption.
type PeerSession struct {
	PeerIdentity [32]byte
	State        *signal.State
}

// SetPeer installs a session for peer. The caller owns persistence.
func (s *Sender) SetPeer(peer string, session *PeerSession) error {
	if session == nil || session.State == nil {
		return fmt.Errorf("core/messaging: nil peer session")
	}
	if peer == "" {
		return fmt.Errorf("core/messaging: empty peer")
	}
	if s.peers == nil {
		s.peers = make(map[string]*PeerSession)
	}
	s.peers[peer] = session
	return nil
}

// SendEncryptedText encrypts text for to and writes <message><enc>.
// It returns the message id and the updated session, which the caller must
// persist before sending again.
func (s *Sender) SendEncryptedText(ctx context.Context, to, text string) (string, *PeerSession, error) {
	return s.SendEncryptedTextWithID(ctx, to, "", text)
}

// SendEncryptedTextWithID is SendEncryptedText with a caller-chosen id; an
// empty id generates one.
//
// A shared id is what lets one logical message reach several devices: the
// recipient copy and the own-device copy of a 1:1 send carry the same id, so
// the phone shows one message rather than two, and receipts name one id.
func (s *Sender) SendEncryptedTextWithID(ctx context.Context, to, id, text string) (string, *PeerSession, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	jid, err := stanza.ParseJID(strings.TrimSpace(to))
	if err != nil {
		return "", nil, fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if jid.User == "" {
		return "", nil, fmt.Errorf("%w: to %q has no user", ErrInvalidMessage, to)
	}
	session := s.peers[jid.String()]
	if session == nil {
		return "", nil, ErrNoSession
	}

	if id == "" {
		id, err = s.newID()
		if err != nil {
			return "", nil, fmt.Errorf("%w: generate id: %w", ErrInvalidMessage, err)
		}
	}
	// The plaintext inside <enc> is a protobuf Message on both carriers (PF-083)
	// — the msg carrier after a bootstrap carries it exactly like the pkmsg one
	// — and it is padded like whatsmeow pads, because a compliant receiver
	// validates the padding and refuses unpadded plaintexts.
	payload, err := stanza.EncodeTextMessage(text)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	ciphertext, err := session.State.Encrypt(stanza.PadMessage(payload), s.identity, session.PeerIdentity)
	if err != nil {
		return "", nil, fmt.Errorf("core/messaging: encrypt: %w", err)
	}
	node, err := stanza.BuildEncryptedText(stanza.EncryptedText{
		ID: id, To: jid, Carrier: stanza.CarrierMsg, Ciphertext: ciphertext,
		Peer: jid.Device > 0,
	})
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	frame, err := s.codec.Encode(node)
	if err != nil {
		return "", nil, fmt.Errorf("core/messaging: encode: %w", err)
	}
	if err := s.write.WriteFrame(ctx, frame); err != nil {
		return "", nil, fmt.Errorf("core/messaging: write: %w", err)
	}
	return id, session, nil
}

// SetIdentity sets only the public identity, which is enough to encrypt with
// an existing session.
func (s *Sender) SetIdentity(identity [32]byte) { s.identity = identity }

// SetIdentityPair sets the identity key pair, which is required to initiate a
// session from a peer bundle.
func (s *Sender) SetIdentityPair(pair signal.KeyPair) {
	s.idPair = pair
	s.identity = pair.Public
}

// SendEncryptedPayload sends an arbitrary protobuf Message payload over an
// established session, padded and encrypted like a text send. It exists for
// the server-driven protocol messages — the app state key request is one —
// that ride the same session as text but carry no conversation field.
func (s *Sender) SendEncryptedPayload(ctx context.Context, to string, payload []byte) (string, *PeerSession, error) {
	return s.SendEncryptedPayloadWithID(ctx, to, "", payload)
}

// SendEncryptedPayloadWithID is SendEncryptedPayload with a caller-chosen id.
// An empty id generates one.
//
// A shared id is what lets one logical message reach several devices: the
// recipient copy and the own-device copy of a 1:1 send carry the same id, so
// the phone's copy is the same message rather than a second one, and receipts
// name one id instead of two.
func (s *Sender) SendEncryptedPayloadWithID(ctx context.Context, to, id string, payload []byte) (string, *PeerSession, error) {
	return s.SendEncryptedPayloadAs(ctx, to, id, stanza.MessageTypeText, payload)
}

// SendEncryptedPayloadAs is SendEncryptedPayloadWithID with an explicit
// transport class: "text" for conversation payloads, "media" for the five
// attachment kinds (PF-089). The class is what the live service stamps on the
// stanza; the payload itself decides what a client renders.
func (s *Sender) SendEncryptedPayloadAs(ctx context.Context, to, id, msgType string, payload []byte) (string, *PeerSession, error) {
	return s.sendPayload(ctx, to, id, msgType, payload, false)
}

// SendPeerPayload sends a payload to exactly one device of an account — the
// shape the own-device copy needs. A device-less destination is device 0 (the
// primary phone) and is honoured too: the stanza carries device_fanout="false"
// so the server does not hand the same ciphertext to devices whose sessions
// it cannot open.
func (s *Sender) SendPeerPayload(ctx context.Context, to, id, msgType string, payload []byte) (string, *PeerSession, error) {
	return s.sendPayload(ctx, to, id, msgType, payload, true)
}

// sendPayload is the shared body; peer permits and marks a peer address.
func (s *Sender) sendPayload(ctx context.Context, to, id, msgType string, payload []byte, peer bool) (string, *PeerSession, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	jid, err := stanza.ParseJID(strings.TrimSpace(to))
	if err != nil {
		return "", nil, fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if jid.User == "" {
		return "", nil, fmt.Errorf("%w: to %q has no user", ErrInvalidMessage, to)
	}
	session := s.peers[jid.String()]
	if session == nil {
		return "", nil, ErrNoSession
	}

	if id == "" {
		id, err = s.newID()
		if err != nil {
			return "", nil, fmt.Errorf("%w: generate id: %w", ErrInvalidMessage, err)
		}
	}
	ciphertext, err := session.State.Encrypt(stanza.PadMessage(payload), s.identity, session.PeerIdentity)
	if err != nil {
		return "", nil, fmt.Errorf("core/messaging: encrypt: %w", err)
	}
	node, err := stanza.BuildEncryptedText(stanza.EncryptedText{
		ID: id, To: jid, Type: msgType, Carrier: stanza.CarrierMsg, Ciphertext: ciphertext,
		Peer: peer || jid.Device > 0,
	})
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	frame, err := s.codec.Encode(node)
	if err != nil {
		return "", nil, fmt.Errorf("core/messaging: encode: %w", err)
	}
	if err := s.write.WriteFrame(ctx, frame); err != nil {
		return "", nil, fmt.Errorf("core/messaging: write: %w", err)
	}
	return id, session, nil
}
