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
	"fmt"
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

// sendOwnDeviceCopy delivers the DeviceSentMessage copy of a 1:1 send to the
// account's own device — the phone's, over the ratchet its messages
// bootstrapped (persisted in the sessions file). The phone renders the
// wrapped message in the destination chat as outgoing, which is how a linked
// device's send appears on the sender's phone. whatsmeow marshalMessage
// builds this second plaintext for every 1:1 send.
func sendOwnDeviceCopy(ctx context.Context, w coremessaging.FrameWriter, codec wabinary.Codec, sessions *sessionsFile, sessionsPath string, record *credentialRecord, destJID, messageID string, inner *protobuf.Message) error {
	phonePeer := phonePeerFor(record.LID, sessions.Sessions)
	if phonePeer == "" {
		return fmt.Errorf("no session with the phone's device; the copy cannot ride an existing ratchet")
	}
	if phonePeer == destJID {
		return fmt.Errorf("the destination is the phone's own device; the copy would duplicate the recipient copy")
	}
	rec, ok := sessions.Sessions[phonePeer]
	if !ok {
		return fmt.Errorf("phone session vanished")
	}
	state := &signal.State{}
	raw, err := base64.StdEncoding.DecodeString(rec.State)
	if err != nil {
		return err
	}
	if err := state.UnmarshalBinary(raw); err != nil {
		return err
	}
	var peerIdentity [32]byte
	copy(peerIdentity[:], rec.PeerIdentity)

	identityPair := signal.KeyPair{Private: record.IdentityPriv, Public: record.IdentityPub}
	sender, err := coremessaging.NewSender(w, coremessaging.WithCodec(codec))
	if err != nil {
		return err
	}
	sender.SetIdentityPair(identityPair)
	if err := sender.SetPeer(phonePeer, &coremessaging.PeerSession{
		PeerIdentity: peerIdentity,
		State:        state,
	}); err != nil {
		return err
	}
	payload, err := stanza.EncodeDeviceSentPayload(destJID, inner)
	if err != nil {
		return err
	}
	// The copy rides the recipient copy's id: one logical message, two
	// ciphertexts. A fresh id would make the phone render the send twice.
	id, updated, err := sender.SendEncryptedPayloadWithID(ctx, phonePeer, messageID, payload)
	if err != nil {
		return err
	}
	// The copy advanced the phone ratchet. Persist it before anything else
	// touches the store, or the next run continues from a chain the phone has
	// already moved past.
	if err := sessions.persist(sessionsPath, phonePeer, updated); err != nil {
		return fmt.Errorf("persist phone session after the own-device copy: %w", err)
	}
	fmt.Printf("own-device copy sent as %s via %s\n", id, phonePeer)
	return nil
}
