package main

// The app state key request: when a patch references a key id this device
// does not hold, it asks for the key by sending an APP_STATE_SYNC_KEY_REQUEST
// protocol message to its own account. The phone (primary device) receives
// it and answers with an APP_STATE_SYNC_KEY_SHARE, which the runtime stores
// and uses to verify the pending patches. whatsmeow appstate.go
// requestAppStateKeys does the same through SendPeerMessage.

import (
	"context"
	"fmt"

	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	waproto "google.golang.org/protobuf/proto"
)

// sendAppStateKeyRequest asks the phone for the missing app state keys. The
// message rides the same first-contact path as any first text: fetch the
// account's own bundle, initiate, encrypt the protocol payload, and send it
// as a pkmsg to the user JID (never device-qualified — the phone routes it).
func sendAppStateKeyRequest(ctx context.Context, d *dispatcher, sc noise.SecureConn, codec wabinary.Codec, record *credentialRecord, source *preKeyStore, keyIDs [][]byte) error {
	if len(keyIDs) == 0 {
		return nil
	}
	ownJID := userPartOf(record.JID)
	if ownJID == "" {
		return fmt.Errorf("key request: account JID %q has no user part", record.JID)
	}

	bundle, err := fetchPreKeyBundle(ctx, d, ownJID)
	if err != nil {
		return fmt.Errorf("prekey bundle for %s: %w", ownJID, err)
	}
	if err := signal.ParsePreKeyBundle(*bundle); err != nil {
		return fmt.Errorf("own bundle for %s does not verify: %w", ownJID, err)
	}

	identityPair := signal.KeyPair{Private: record.IdentityPriv, Public: record.IdentityPub}
	initiator, err := signal.Initiate(identityPair, *bundle)
	if err != nil {
		return fmt.Errorf("initiate: %w", err)
	}
	state, err := signal.NewInitiator(initiator.Keys.RootKey, bundle.SignedPreKey, initiator.Keys.ChainKey)
	if err != nil {
		return fmt.Errorf("initiator state: %w", err)
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

	ciphertext, err := state.Encrypt(stanza.PadMessage(payload), identityPair.Public, bundle.IdentityKey)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	wire, err := initiator.BuildPreKeyMessage(identityPair.Public, record.RegistrationID, ciphertext)
	if err != nil {
		return fmt.Errorf("prekey message: %w", err)
	}

	messageID, err := randomID()
	if err != nil {
		return err
	}
	toJID, err := stanza.ParseJID(ownJID)
	if err != nil {
		return fmt.Errorf("parse own jid: %w", err)
	}
	node, err := stanza.BuildEncryptedText(stanza.EncryptedText{
		ID:         messageID,
		To:         toJID,
		Carrier:    stanza.CarrierPKMsg,
		Ciphertext: wire,
	})
	if err != nil {
		return fmt.Errorf("build envelope: %w", err)
	}
	frame, err := codec.Encode(node)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	fmt.Printf("app state key request sent (%d ids) to %s\n", len(keyIDs), ownJID)
	return nil
}

// userPartOf strips the device suffix and server from a JID, leaving the
// bare account number ("628123:37@s.whatsapp.net" → "628123").
func userPartOf(jid string) string {
	local, _, ok := cut(jid, "@")
	if !ok {
		return ""
	}
	user, _, _ := cut(local, ":")
	return user
}

func cut(s, sep string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if string(s[i]) == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
