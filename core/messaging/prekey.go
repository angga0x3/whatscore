package messaging

import (
	"context"
	"errors"
	"fmt"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// ErrNoPreKey is returned when a prekey message references a prekey this
// device does not hold.
var ErrNoPreKey = errors.New("core/messaging: missing prekey")

// PreKeySource supplies this device's prekey material for inbound bootstrap.
// Implementations are expected to consult durable storage.
type PreKeySource interface {
	Identity() signal.KeyPair
	SignedPreKey(id uint32) (*signal.SignedPreKey, error)
	OneTimePreKey(id uint32) (*signal.PreKey, error)
}

// bootstrapPeer decrypts a PreKeySignalMessage, installs the new session, and
// returns the peer identity plus plaintext (PF-065).
func (r *Receiver) bootstrapPeer(ctx context.Context, envelope *stanza.EncryptedText, source PreKeySource, peer stanza.JID) (*PeerSession, []byte, error) {
	if source == nil {
		return nil, nil, ErrNoPreKey
	}
	prekeyMessage, err := signal.ParsePreKeyMessage(envelope.Ciphertext)
	if err != nil {
		return nil, nil, err
	}
	signed, err := source.SignedPreKey(prekeyMessage.SignedPreKeyID)
	if err != nil || signed == nil {
		return nil, nil, fmt.Errorf("%w: signed prekey %d: %w", ErrNoPreKey, prekeyMessage.SignedPreKeyID, err)
	}
	var oneTime *signal.PreKey
	if prekeyMessage.PreKeyID != 0 {
		oneTime, err = source.OneTimePreKey(prekeyMessage.PreKeyID)
		if err != nil || oneTime == nil {
			return nil, nil, fmt.Errorf("%w: one-time prekey %d: %w", ErrNoPreKey, prekeyMessage.PreKeyID, err)
		}
	}

	identity := source.Identity()
	state, plaintext, err := signal.AcceptPreKeyMessage(envelope.Ciphertext, identity, *signed, oneTime)
	if err != nil {
		return nil, nil, err
	}
	session := &PeerSession{PeerIdentity: prekeyMessage.IdentityKey, State: state}
	if err := r.SetReceiverPeer(peer.String(), session); err != nil {
		return nil, nil, err
	}
	r.logger.DebugContext(ctx, "bootstrapped signal session", "peer", peer)
	return session, plaintext, nil
}

// SetPreKeySource installs the prekey provider used for pkmsg bootstrap.
func (r *Receiver) SetPreKeySource(source PreKeySource) { r.prekeys = source }

// handlePreKey decrypts a pkmsg carrier, bootstrapping the session when
// needed, and publishes the carried text.
func (r *Receiver) handlePreKey(ctx context.Context, node *binary.Node) {
	envelope, err := stanza.ParseEncryptedText(node)
	if err != nil {
		r.logger.WarnContext(ctx, "dropping malformed prekey message", "error", err)
		return
	}
	peer := envelope.To
	_, plaintext, err := r.bootstrapPeer(ctx, envelope, r.prekeys, peer)
	if err != nil {
		r.logger.WarnContext(ctx, "dropping prekey message", "error", err)
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
			Text:      string(plaintext),
			IsGroup:   peer.Server == stanza.GroupServer,
		},
	})
}
