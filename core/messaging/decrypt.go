package messaging

import (
	"context"
	"fmt"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
)

// ErrNoPeerSession is returned when an inbound encrypted message has no
// matching peer session.
var ErrNoPeerSession = fmt.Errorf("%w: no peer session", ErrInvalidMessage)

// SetReceiverPeer installs the session used to decrypt messages from peer.
func (r *Receiver) SetReceiverPeer(peer string, session *PeerSession) error {
	if session == nil || session.State == nil {
		return fmt.Errorf("core/messaging: nil peer session")
	}
	if peer == "" {
		return fmt.Errorf("core/messaging: empty peer")
	}
	if r.peers == nil {
		r.peers = make(map[string]*PeerSession)
	}
	r.peers[peer] = session
	return nil
}

// SetReceiverIdentity sets this device's Signal identity public key.
func (r *Receiver) SetReceiverIdentity(identity [32]byte) { r.identity = identity }

// handleEnc dispatches an inbound <enc> by carrier.
//
// The live ratchet is never mutated on failure: decryption runs on a clone,
// and the advanced state replaces the live one only after success. Callers
// that persist sessions should save the updated state through their store.
func (r *Receiver) handleEnc(ctx context.Context, node *binary.Node) {
	envelope, err := stanza.ParseEncryptedText(node)
	if err != nil {
		r.logger.WarnContext(ctx, "dropping malformed encrypted message", "error", err)
		r.decryptFailed(node)
		return
	}
	if envelope.Carrier == stanza.CarrierPKMsg {
		r.handlePreKey(ctx, node)
		return
	}
	r.decryptWithSession(ctx, node, envelope)
}

// decryptWithSession decrypts with an existing session.
func (r *Receiver) decryptWithSession(ctx context.Context, node *binary.Node, envelope *stanza.EncryptedText) {
	// The session belongs to whoever encrypted to us: the sender (see
	// handlePreKey). The live service omits "to" on inbound stanzas, so the
	// old lookup keyed on it could never have matched a real message.
	peer := envelope.From
	session := r.peers[peer.String()]
	if session == nil {
		r.logger.WarnContext(ctx, "dropping encrypted message without session", "peer", peer)
		r.decryptFailed(node)
		return
	}

	attempt, err := session.State.Clone()
	if err != nil {
		r.logger.WarnContext(ctx, "dropping encrypted message: clone failed", "error", err)
		r.decryptFailed(node)
		return
	}
	plaintext, err := attempt.Decrypt(envelope.Ciphertext, session.PeerIdentity, r.identity)
	if err != nil {
		r.logger.WarnContext(ctx, "dropping encrypted message: decrypt failed", "error", err)
		r.decryptFailed(node)
		return
	}
	session.State = attempt
	r.observe(peer.String(), session)

	// Strip the service's padding before parsing (see handlePreKey).
	if plaintext, err = stanza.UnpadMessage(plaintext, envelope.Version); err != nil {
		r.logger.WarnContext(ctx, "dropping encrypted message: unpad failed", "error", err)
		r.decryptFailed(node)
		return
	}

	// The decrypted bytes are a protobuf Message, not a raw string. A payload
	// with no text (an image, a reaction, a protocol message) is not an error
	// here: it decrypts fine and this layer simply has nothing to render.
	text, err := stanza.DecodeTextMessage(plaintext)
	if err != nil {
		r.logger.InfoContext(ctx, "decrypted a message with no text payload", "peer", peer, "error", err)
		return
	}

	timestamp := timestampOf(node)
	r.bus.Publish(events.Event{
		Type:      events.TypeMessage,
		SessionID: r.sessionID,
		Timestamp: timestamp,
		Message: &events.Message{
			ID:        envelope.ID,
			Chat:      peer.String(),
			Sender:    peer.String(),
			Timestamp: timestamp,
			Direction: events.DirectionIncoming,
			Text:      text,
			IsGroup:   peer.Server == stanza.GroupServer,
		},
	})
}

// publishIncoming turns one decoded payload into the event the rest of the
// stack sees: a text message, or a message carrying a media attachment.
func (r *Receiver) publishIncoming(ctx context.Context, id string, peer stanza.JID, timestamp time.Time, payload *stanza.Payload) {
	msg := &events.Message{
		ID:        id,
		Chat:      peer.String(),
		Sender:    peer.String(),
		Timestamp: timestamp,
		Direction: events.DirectionIncoming,
		IsGroup:   peer.Server == stanza.GroupServer,
	}
	switch payload.Kind {
	case stanza.PayloadText:
		msg.Text = payload.Text
	case stanza.PayloadProtocol:
		if payload.Protocol != nil {
			msg.Protocol = &events.ProtocolInfo{
				Type:    payload.Protocol.Type,
				AppKeys: payload.Protocol.AppKeys,
			}
		}
	case stanza.PayloadImage, stanza.PayloadSticker, stanza.PayloadVideo, stanza.PayloadAudio, stanza.PayloadDocument:
		m := payload.Media
		msg.Text = m.Caption
		msg.Media = &events.MediaAttachment{
			Kind:              string(payload.Kind),
			MimeType:          m.MimeType,
			Caption:           m.Caption,
			FileName:          m.FileName,
			FileLength:        m.FileLength,
			MediaKey:          m.MediaKey,
			FileSHA256:        m.FileSHA256,
			FileEncSHA256:     m.FileEncSHA256,
			DirectPath:        m.DirectPath,
			MediaKeyTimestamp: m.MediaKeyTimestamp,
			KeysType:          m.KeysType,
		}
	default:
		r.logger.DebugContext(ctx, "payload has no renderable content", "kind", payload.Kind)
		return
	}
	if payload.Kind == stanza.PayloadProtocol && payload.Protocol != nil && payload.Protocol.HistorySync != nil {
		msg.Protocol.HistorySync = true
	}
	r.bus.Publish(events.Event{
		Type:      events.TypeMessage,
		SessionID: r.sessionID,
		Timestamp: timestamp,
		Message:   msg,
	})
}
