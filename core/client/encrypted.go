package client

import (
	"context"
	"errors"
	"fmt"

	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// SessionStore persists one peer's Signal session. core/signalsession.Manager
// satisfies it.
type SessionStore interface {
	LoadRecord(ctx context.Context, peer string) (*PeerRecord, error)
	SaveRecord(ctx context.Context, peer string, record *PeerRecord) error
}

// PeerRecord is the persisted session for one peer: its identity key plus the
// ratchet state.
type PeerRecord struct {
	PeerIdentity [32]byte
	State        *signal.State
}

// WithSessionStore wires persistence for encrypted messaging.
func WithSessionStore(store SessionStore) Option {
	return func(o *options) error {
		if store == nil {
			return fmt.Errorf("%w: nil session store", ErrInvalidConfig)
		}
		o.sessions = store
		return nil
	}
}

// SendEncrypted loads (or establishes) the peer session, encrypts, sends, and
// persists the advanced state.
//
// The carrier is chosen by session existence: a known session uses msg, an
// unknown peer with a bundle source uses pkmsg. Without either, ErrNoSession.
func (c *Client) SendEncrypted(ctx context.Context, msg Message) (string, error) {
	if c.sessions == nil {
		return "", fmt.Errorf("%w: no session store", ErrInvalidConfig)
	}
	record, err := c.loadPeer(ctx, msg.To)
	if err != nil && !errors.Is(err, coremessaging.ErrNoSession) {
		return "", err
	}
	if record == nil {
		id, session, err := c.sender.SendPreKeyText(ctx, msg.To, msg.Text, c.registrationID)
		if err != nil {
			return "", err
		}
		if err := c.savePeer(ctx, msg.To, session); err != nil {
			return "", err
		}
		return id, nil
	}

	if err := c.sender.SetPeer(msg.To, record); err != nil {
		return "", err
	}
	id, session, err := c.sender.SendEncryptedText(ctx, msg.To, msg.Text)
	if err != nil {
		return "", err
	}
	return id, c.savePeer(ctx, msg.To, session)
}

// loadPeer returns the stored session, or nil when none exists yet.
func (c *Client) loadPeer(ctx context.Context, peer string) (*coremessaging.PeerSession, error) {
	record, err := c.sessions.LoadRecord(ctx, peer)
	if err != nil {
		return nil, coremessaging.ErrNoSession
	}
	return &coremessaging.PeerSession{PeerIdentity: record.PeerIdentity, State: record.State}, nil
}

func (c *Client) savePeer(ctx context.Context, peer string, session *coremessaging.PeerSession) error {
	record := &PeerRecord{PeerIdentity: session.PeerIdentity, State: session.State}
	if err := c.sessions.SaveRecord(ctx, peer, record); err != nil {
		return fmt.Errorf("client: persist session for %q: %w", peer, err)
	}
	return nil
}

// SetRegistrationID sets the registration id sent in prekey messages.
func (c *Client) SetRegistrationID(id uint32) { c.registrationID = id }
