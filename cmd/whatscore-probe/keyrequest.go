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
	"strings"

	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	waproto "google.golang.org/protobuf/proto"
)

// sendAppStateKeyRequest asks the phone for the missing app state keys. The
// request rides the existing ratchet with the phone's device (bootstrapped
// from its messages, persisted across runs) — no bundle fetch needed, and
// none is served for the own account anyway. The phone answers with an
// APP_STATE_SYNC_KEY_SHARE, whose storage triggers the patch re-request.
func sendAppStateKeyRequest(ctx context.Context, sender *coremessaging.Sender, phonePeer string, keyIDs [][]byte) error {
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
	id, _, err := sender.SendEncryptedPayload(ctx, phonePeer, payload)
	if err != nil {
		return err
	}
	fmt.Printf("app state key request sent (%d ids) via %s as %s\n", len(keyIDs), phonePeer, id)
	return nil
}

// phonePeerFor finds the stored peer session that belongs to the phone (the
// primary device): its JID user matches the account's LID user, because the
// LID is account-scoped while the device suffix differs per device.
func phonePeerFor(lid string, sessions map[string]storedSession) string {
	lidUser := lid
	if at := strings.Index(lid, "@"); at >= 0 {
		lidUser = lid[:at]
	}
	if colon := strings.Index(lidUser, ":"); colon >= 0 {
		lidUser = lidUser[:colon]
	}
	for peer := range sessions {
		user := peer
		if at := strings.Index(peer, "@"); at >= 0 {
			user = peer[:at]
		}
		if colon := strings.Index(user, ":"); colon >= 0 {
			user = user[:colon]
		}
		if user == lidUser {
			return peer
		}
	}
	return ""
}
