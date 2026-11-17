package main

// The app state key request: when a patch references a key id this device
// does not hold, it asks for the key by sending an APP_STATE_SYNC_KEY_REQUEST
// protocol message to its own account. The phone (primary device) receives
// it and answers with an APP_STATE_SYNC_KEY_SHARE, which the runtime stores
// and uses to verify the pending patches. whatsmeow appstate.go
// requestAppStateKeys does the same through SendPeerMessage.
//
// It lives here with the own-device copy because both are the same kind of
// send: a message addressed to one device of the account, riding the ratchet
// that device's own messages bootstrapped.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"

	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	waproto "google.golang.org/protobuf/proto"
)

// sendAppStateKeyRequest asks the phone for the missing app state keys. The
// request rides the existing ratchet with the phone's device (bootstrapped
// from its messages, persisted across runs) — no bundle fetch needed: what
// the phone will accept is the chain its own messages created. The phone
// answers with an APP_STATE_SYNC_KEY_SHARE, whose storage triggers the patch
// re-request.
func sendAppStateKeyRequest(ctx context.Context, sender *coremessaging.Sender, sessions *sessionsFile, sessionsPath, phonePeer string, keyIDs [][]byte) error {
	if len(keyIDs) == 0 {
		return nil
	}
	ids := make([]*protobuf.AppStateSyncKeyId, 0, len(keyIDs))
	for _, id := range keyIDs {
		kid := append([]byte(nil), id...)
		ids = append(ids, &protobuf.AppStateSyncKeyId{ID: kid})
	}
	payload, err := waproto.Marshal(&protobuf.Message{
		ProtocolMessage: &protobuf.ProtocolMessage{
			Type: protobuf.ProtocolMessage_APP_STATE_SYNC_KEY_REQUEST.Enum(),
			AppStateSyncKeyRequest: &protobuf.AppStateSyncKeyRequest{
				KeyIDs: ids,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal key request: %w", err)
	}
	id, updated, err := sender.SendEncryptedPayload(ctx, phonePeer, payload)
	if err != nil {
		return err
	}
	// The request advanced the phone ratchet. Persist it, like any other send:
	// the phone's answer rides the same chain, and a process that exits before
	// the next decrypt would otherwise restore a spent state.
	if err := sessions.persist(sessionsPath, phonePeer, updated); err != nil {
		return fmt.Errorf("persist phone session after the key request: %w", err)
	}
	fmt.Printf("app state key request sent (%d ids) via %s as %s\n", len(keyIDs), phonePeer, id)
	return nil
}

// phonePeerFor finds the stored peer session that belongs to the phone (the
// primary device): its JID user matches the account's LID user, because the
// LID is account-scoped while the device suffix differs per device.
func phonePeerFor(lid string, sessions map[string]storedSession) string {
	lidUser := jidUserFor(lid)
	if lidUser == "" {
		return ""
	}
	for peer := range sessions {
		if jidUserFor(peer) == lidUser {
			return peer
		}
	}
	return ""
}

// isOwnAccount reports whether dest addresses this account, by either of its
// two identities: the phone number and the LID are the same account under
// different addressing, and a self-send must not also produce a copy.
func isOwnAccount(dest string, record *credentialRecord) bool {
	user := jidUserFor(dest)
	if user == "" {
		return false
	}
	return user == jidUserFor(record.JID) || user == jidUserFor(record.LID)
}

// jidUserFor returns the user part of a JID, without the device or the
// server. The LID is account-scoped while the device suffix differs per
// device, which is why the phone is found by user and not by full JID.
func jidUserFor(jid string) string {
	user := jid
	if at := strings.Index(user, "@"); at >= 0 {
		user = user[:at]
	}
	if colon := strings.Index(user, ":"); colon >= 0 {
		user = user[:colon]
	}
	return user
}

// ownDevicePeers lists the account's other devices: every stored session
// whose JID user matches the account LID user, minus this device itself.
//
// The copies are per device, not per account: a stanza addressed to the
// account without device_fanout is handed to every device, and only the one
// whose session produced the ciphertext can open it — the rest show "waiting
// for this message". Device 0 (the bare LID) is the primary phone.
func ownDevicePeers(record *credentialRecord, sessions map[string]storedSession) []string {
	if record == nil {
		return nil
	}
	user := jidUserFor(record.LID)
	if user == "" {
		return nil
	}
	var peers []string
	for peer := range sessions {
		if jidUserFor(peer) != user {
			continue
		}
		if peer == record.LID || peer == record.JID {
			continue
		}
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	return peers
}

// sendOwnDeviceCopy delivers the DeviceSentMessage copy of a 1:1 send to the
// account's other devices — the phone and any linked device whose ratchet the
// session file holds. Each copy is addressed to exactly one device
// (device_fanout="false"), which is what makes it readable there.
func sendOwnDeviceCopy(ctx context.Context, w coremessaging.FrameWriter, codec wabinary.Codec, sessions *sessionsFile, sessionsPath string, record *credentialRecord, destJID, messageID string, inner *protobuf.Message) error {
	peers := ownDevicePeers(record, sessions.Sessions)
	if len(peers) == 0 {
		return fmt.Errorf("no session with another device of this account; the copy cannot ride an existing ratchet")
	}
	payload, err := stanza.EncodeDeviceSentPayload(destJID, inner)
	if err != nil {
		return err
	}
	identityPair := signal.KeyPair{Private: record.IdentityPriv, Public: record.IdentityPub}
	var errs []error
	for _, peer := range peers {
		if peer == destJID {
			continue
		}
		rec, ok := sessions.Sessions[peer]
		if !ok {
			continue
		}
		state := &signal.State{}
		raw, err := base64.StdEncoding.DecodeString(rec.State)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", peer, err))
			continue
		}
		if err := state.UnmarshalBinary(raw); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", peer, err))
			continue
		}
		var peerIdentity [32]byte
		copy(peerIdentity[:], rec.PeerIdentity)

		sender, err := coremessaging.NewSender(w, coremessaging.WithCodec(codec))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sender.SetIdentityPair(identityPair)
		if err := sender.SetPeer(peer, &coremessaging.PeerSession{PeerIdentity: peerIdentity, State: state}); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", peer, err))
			continue
		}
		// The copy rides the recipient copy's id: one logical message, two
		// ciphertexts. A fresh id would make the device render the send twice.
		id, updated, err := sender.SendPeerPayload(ctx, peer, messageID, stanza.MessageTypeText, payload)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", peer, err))
			continue
		}
		if err := sessions.persist(sessionsPath, peer, updated); err != nil {
			errs = append(errs, fmt.Errorf("%s: persist: %w", peer, err))
			continue
		}
		fmt.Printf("own-device copy sent as %s via %s\n", id, peer)
	}
	return errors.Join(errs...)
}
