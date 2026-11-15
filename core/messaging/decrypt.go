package messaging

import (
	"context"
	"fmt"

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

// handleEncrypted decrypts an inbound <message><enc> and publishes it.
//
// The live ratchet is never mutated on failure: decryption runs on a clone,
// and the advanced state replaces the live one only after success. Callers
// that persist sessions should save the updated state through their store.
func (r *Receiver) handleEncrypted(ctx context.Context, node *binary.Node) {
	envelope, err := stanza.ParseEncryptedText(node)
	if err != nil {
		r.logger.WarnContext(ctx, "dropping malformed encrypted message", "error", err)
		return
	}
	if envelope.Carrier == stanza.CarrierPKMsg {
		// Prekey messages need a session bootstrap, which is a separate flow.
		r.logger.DebugContext(ctx, "dropping prekey message without bootstrap")
		return
	}
	peer := envelope.To
	session := r.peers[peer.String()]
	if session == nil {
		r.logger.WarnContext(ctx, "dropping encrypted message without session", "peer", peer)
		return
	}

	attempt, err := session.State.Clone()
	if err != nil {
		r.logger.WarnContext(ctx, "dropping encrypted message: clone failed", "error", err)
		return
	}
	plaintext, err := attempt.Decrypt(envelope.Ciphertext, session.PeerIdentity, r.identity)
	if err != nil {
		r.logger.WarnContext(ctx, "dropping encrypted message: decrypt failed", "error", err)
		return
	}
	session.State = attempt

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
			Text:      string(plaintext),
			IsGroup:   peer.Server == stanza.GroupServer,
		},
	})
}
