package messaging

import (
	"context"
	"fmt"
	"sort"

	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	"google.golang.org/protobuf/proto"
)

// DeviceSource resolves account addresses into concrete recipient devices.
type DeviceSource interface {
	Devices(context.Context, []string) ([]string, error)
}

// DirectMessage describes one logical message, including the sender's device
// addresses so its other devices receive DeviceSentMessage rather than a copy
// encrypted for the recipient.
type DirectMessage struct {
	To, ID, Type   string
	OwnJID, OwnLID string
	RegistrationID uint32
	Message        *protobuf.Message
	// Persist must finish before the frame leaves. This prevents a restart
	// from reusing a message key that a remote device has already received.
	Persist func(context.Context, string, *PeerSession) error
}

// SendDirect writes one message stanza with a separate encrypted participant
// for every recipient and own device. No account-wide ciphertext is emitted.
func (s *Sender) SendDirect(ctx context.Context, source DeviceSource, request DirectMessage) (string, map[string]*PeerSession, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	to, err := stanza.ParseJID(request.To)
	if err != nil || to.User == "" || to.Device != 0 || (to.Server != stanza.UserServer && to.Server != "lid") {
		return "", nil, fmt.Errorf("%w: invalid direct destination", ErrInvalidMessage)
	}
	if source == nil || request.Message == nil || request.Persist == nil {
		return "", nil, fmt.Errorf("%w: direct send requires devices, payload and persistence", ErrInvalidMessage)
	}
	ownPN, err := stanza.ParseJID(request.OwnJID)
	if err != nil || ownPN.User == "" {
		return "", nil, fmt.Errorf("%w: missing own account address", ErrInvalidMessage)
	}
	ownLID := stanza.JID{}
	if request.OwnLID != "" {
		ownLID, err = stanza.ParseJID(request.OwnLID)
		if err != nil {
			return "", nil, err
		}
	}
	isOwn := func(jid stanza.JID) bool {
		return (jid.User == ownPN.User && jid.Server == ownPN.Server) ||
			(ownLID.User != "" && jid.User == ownLID.User && jid.Server == ownLID.Server)
	}
	accounts := []string{to.String(), ownPN.Normalize().String()}
	devices, err := source.Devices(ctx, accounts)
	if err != nil {
		return "", nil, fmt.Errorf("direct devices: %w", err)
	}
	payload, err := proto.Marshal(request.Message)
	if err != nil {
		return "", nil, err
	}
	ownPayload, err := stanza.EncodeDeviceSentPayload(to.String(), request.Message)
	if err != nil {
		return "", nil, err
	}
	msgType := request.Type
	if msgType == "" {
		msgType = stanza.MessageTypeText
	}
	if msgType != stanza.MessageTypeText && msgType != stanza.MessageTypeMedia {
		return "", nil, fmt.Errorf("%w: invalid direct type", ErrInvalidMessage)
	}
	id := request.ID
	if id == "" {
		id, err = s.newID()
		if err != nil {
			return "", nil, err
		}
	}
	participants := []binary.Node{}
	updated := map[string]*PeerSession{}
	seen := map[string]bool{}
	recipientCount := 0
	includeIdentity := false
	sort.Strings(devices)
	for _, raw := range devices {
		jid, err := stanza.ParseJID(raw)
		if err != nil || jid.User == "" {
			return "", nil, fmt.Errorf("%w: invalid direct device %q", ErrInvalidMessage, raw)
		}
		if jid == ownPN || (ownLID.User != "" && jid == ownLID) {
			continue
		}
		own := isOwn(jid)
		if !own && (jid.User != to.User || jid.Server != to.Server) {
			return "", nil, fmt.Errorf("%w: unrelated device in query", ErrInvalidMessage)
		}
		peer := jid.String()
		if seen[peer] {
			continue
		}
		seen[peer] = true
		plaintext := payload
		if own {
			plaintext = ownPayload
		} else {
			recipientCount++
		}
		session := s.peers[peer]
		// Old snapshots discarded pending bootstrap metadata. If no inbound
		// message authenticated that session, a new bundle is required; a
		// bare msg cannot bootstrap a remote device that never got the pkmsg.
		if session == nil || (!session.State.HasReceived() && !session.State.HasPendingPreKey()) {
			if s.bundles == nil {
				return "", nil, ErrNoSession
			}
			bundle, err := s.bundles.PreKeyBundle(ctx, peer)
			if err != nil {
				return "", nil, fmt.Errorf("bundle for %s: %w", peer, err)
			}
			init, err := signal.Initiate(s.idPair, *bundle)
			if err != nil {
				return "", nil, err
			}
			state, err := signal.NewInitiator(init.Keys.RootKey, bundle.SignedPreKey, init.Keys.ChainKey)
			if err != nil {
				return "", nil, err
			}
			state.SetPendingPreKey(signal.PendingPreKey{RegistrationID: request.RegistrationID,
				SignedPreKeyID: init.SignedPreKeyID, PreKeyID: init.OneTimePreKeyID, BaseKey: init.EphemeralPublic})
			session = &PeerSession{PeerIdentity: bundle.IdentityKey, State: state}
		} else {
			cloned, err := session.State.Clone()
			if err != nil {
				return "", nil, err
			}
			session = &PeerSession{PeerIdentity: session.PeerIdentity, State: cloned}
		}
		ciphertext, err := session.State.Encrypt(stanza.PadMessage(plaintext), s.identity, session.PeerIdentity)
		if err != nil {
			return "", nil, err
		}
		ciphertext, pending, err := session.State.WrapPendingPreKey(ciphertext, s.identity)
		if err != nil {
			return "", nil, err
		}
		carrier := stanza.CarrierMsg
		if pending {
			if len(s.deviceIdentity) == 0 {
				return "", nil, fmt.Errorf("%w: missing paired device identity", ErrInvalidMessage)
			}
			carrier = stanza.CarrierPKMsg
			includeIdentity = true
		}
		participants = append(participants, binary.Node{Tag: "to", Attrs: binary.Attrs{"jid": peer},
			Children: []binary.Node{{Tag: "enc", Attrs: binary.Attrs{"v": "2", "type": carrier}, Bytes: ciphertext}}})
		updated[peer] = session
	}
	if len(participants) == 0 || (!isOwn(to) && recipientCount == 0) {
		return "", nil, fmt.Errorf("%w: no devices for destination", ErrInvalidMessage)
	}
	node := &binary.Node{Tag: "message", Attrs: binary.Attrs{"to": to.String(), "id": id, "type": msgType},
		Children: []binary.Node{{Tag: "participants", Children: participants}}}
	if includeIdentity {
		node.Children = append(node.Children, binary.Node{Tag: "device-identity", Bytes: append([]byte(nil), s.deviceIdentity...)})
	}
	frame, err := s.codec.Encode(node)
	if err != nil {
		return "", nil, err
	}
	for peer, session := range updated {
		if err := request.Persist(ctx, peer, session); err != nil {
			return "", nil, fmt.Errorf("persist %s before send: %w", peer, err)
		}
		if err := s.SetPeer(peer, session); err != nil {
			return "", nil, err
		}
	}
	if err := s.write.WriteFrame(ctx, frame); err != nil {
		return id, updated, fmt.Errorf("direct write (state already persisted): %w", err)
	}
	return id, updated, nil
}
