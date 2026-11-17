package messaging

import (
	"context"
	"fmt"
	"strings"

	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// ErrNoIdentity is returned when a session must be initiated but the sender
// has no identity key pair.
var ErrNoIdentity = fmt.Errorf("%w: no identity key pair", ErrInvalidMessage)

// PreKeyBundleSource supplies a peer's published bundle for the first
// message, before any session exists.
type PreKeyBundleSource interface {
	PreKeyBundle(ctx context.Context, peer string) (*signal.PreKeyBundle, error)
}

// SetPreKeyBundleSource installs the bundle provider used by
// SendPreKeyText. Without one, an unknown peer fails with ErrNoSession.
func (s *Sender) SetPreKeyBundleSource(source PreKeyBundleSource) { s.bundles = source }

// SendPreKeyText establishes a session from the peer's bundle and sends the
// first message as a pkmsg carrier (PF-066).
//
// The returned session replaces any previous one for the peer; the caller
// must persist it through core/signalsession before sending again.
func (s *Sender) SendPreKeyText(ctx context.Context, to, text string, registrationID uint32) (string, *PeerSession, error) {
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
	if s.bundles == nil {
		return "", nil, ErrNoSession
	}
	peer := jid.String()
	bundle, err := s.bundles.PreKeyBundle(ctx, peer)
	if err != nil {
		return "", nil, fmt.Errorf("core/messaging: bundle for %q: %w", peer, err)
	}
	return s.sendPreKeyTextWithBundle(ctx, jid, peer, "", text, registrationID, bundle)
}

// SendPreKeyTextWithBundle sends the first message using a bundle the caller
// already holds. A prekey fetch is a server round trip with its own failure
// modes, so callers that manage the connection themselves fetch it and hand it
// over rather than letting the sender do I/O it cannot retry.
func (s *Sender) SendPreKeyTextWithBundle(ctx context.Context, to, text string, bundle *signal.PreKeyBundle, registrationID uint32) (string, *PeerSession, error) {
	return s.SendPreKeyTextWithBundleID(ctx, to, "", text, bundle, registrationID)
}

// SendPreKeyTextWithBundleID is SendPreKeyTextWithBundle with a caller-chosen
// id; an empty id generates one. The id is shared with the own-device copy of
// the same send, so the phone renders one message instead of two.
func (s *Sender) SendPreKeyTextWithBundleID(ctx context.Context, to, id, text string, bundle *signal.PreKeyBundle, registrationID uint32) (string, *PeerSession, error) {
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
	return s.sendPreKeyTextWithBundle(ctx, jid, jid.String(), id, text, registrationID, bundle)
}

// sendPreKeyTextWithBundle is the shared body of both public entry points.
func (s *Sender) sendPreKeyTextWithBundle(ctx context.Context, jid stanza.JID, _, id, text string, registrationID uint32, bundle *signal.PreKeyBundle) (string, *PeerSession, error) {
	payload, err := stanza.EncodeTextMessage(text)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	return s.SendPreKeyPayloadAs(ctx, jid.String(), id, stanza.MessageTypeText, payload, bundle, registrationID)
}

// SendPreKeyPayloadAs sends an arbitrary payload as the first message of a
// session, over a pkmsg carrier. It is the first-contact half of
// SendEncryptedPayloadAs: text uses it with the text class, an upload with
// the media class.
func (s *Sender) SendPreKeyPayloadAs(ctx context.Context, to, id, msgType string, payload []byte, bundle *signal.PreKeyBundle, registrationID uint32) (string, *PeerSession, error) {
	jid, err := stanza.ParseJID(strings.TrimSpace(to))
	if err != nil {
		return "", nil, fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if jid.User == "" {
		return "", nil, fmt.Errorf("%w: to %q has no user", ErrInvalidMessage, to)
	}
	return s.sendPreKeyPayload(ctx, jid, id, msgType, payload, registrationID, bundle)
}

func (s *Sender) sendPreKeyPayload(ctx context.Context, jid stanza.JID, id, msgType string, payload []byte, registrationID uint32, bundle *signal.PreKeyBundle) (string, *PeerSession, error) {
	peer := jid.String()
	if bundle == nil {
		return "", nil, fmt.Errorf("%w: nil bundle for %q", ErrInvalidMessage, peer)
	}
	if err := signal.ParsePreKeyBundle(*bundle); err != nil {
		return "", nil, fmt.Errorf("core/messaging: bundle for %q: %w", peer, err)
	}

	if s.idPair.Public == ([32]byte{}) {
		return "", nil, ErrNoIdentity
	}
	initiator, err := signal.Initiate(s.idPair, *bundle)
	if err != nil {
		return "", nil, fmt.Errorf("core/messaging: initiate: %w", err)
	}
	state, err := signal.NewInitiator(initiator.Keys.RootKey, bundle.SignedPreKey, initiator.Keys.ChainKey)
	if err != nil {
		return "", nil, fmt.Errorf("core/messaging: initiate state: %w", err)
	}
	state.SetPendingPreKey(signal.PendingPreKey{
		RegistrationID: registrationID, SignedPreKeyID: initiator.SignedPreKeyID,
		PreKeyID: initiator.OneTimePreKeyID, BaseKey: initiator.EphemeralPublic,
	})
	if id == "" {
		id, err = s.newID()
		if err != nil {
			return "", nil, fmt.Errorf("%w: generate id: %w", ErrInvalidMessage, err)
		}
	}

	if len(payload) == 0 {
		return "", nil, fmt.Errorf("%w: empty payload", ErrInvalidMessage)
	}
	// Pad before encrypting (whatsmeow padMessage): a compliant receiver
	// validates the padding and refuses unpadded plaintexts.
	ciphertext, err := state.Encrypt(stanza.PadMessage(payload), s.identity, bundle.IdentityKey)
	if err != nil {
		return "", nil, fmt.Errorf("core/messaging: encrypt: %w", err)
	}
	wire, err := initiator.BuildPreKeyMessage(s.identity, registrationID, ciphertext)
	if err != nil {
		return "", nil, fmt.Errorf("core/messaging: prekey message: %w", err)
	}
	node, err := stanza.BuildEncryptedText(stanza.EncryptedText{
		ID: id, To: jid, Type: msgType, Carrier: stanza.CarrierPKMsg, Ciphertext: wire,
		Peer:           jid.Device > 0,
		DeviceIdentity: s.deviceIdentity,
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

	session := &PeerSession{PeerIdentity: bundle.IdentityKey, State: state}
	if s.peers == nil {
		s.peers = make(map[string]*PeerSession)
	}
	s.peers[peer] = session
	return id, session, nil
}
