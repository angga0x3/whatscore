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

	id, err := s.newID()
	if err != nil {
		return "", nil, fmt.Errorf("%w: generate id: %w", ErrInvalidMessage, err)
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

// Identity returns this sender's Signal identity public key.
func (s *Sender) Identity() [32]byte { return s.identity }

// SetIdentity sets only the public identity, which is enough to encrypt with
// an existing session.
func (s *Sender) SetIdentity(identity [32]byte) { s.identity = identity }

// SetIdentityPair sets the identity key pair, which is required to initiate a
// session from a peer bundle.
func (s *Sender) SetIdentityPair(pair signal.KeyPair) {
	s.idPair = pair
	s.identity = pair.Public
}
