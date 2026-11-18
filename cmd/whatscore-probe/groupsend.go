package main

// Group send v1: the probe sends one group message per run, so the sender
// key is ephemeral — a fresh chain, signing pair and id per send. Members
// get the SKDM + the skmsg in the same flow; no cross-run state needed.
// whatsmeow send.go, the group branch: pairwise SKDM under <participants>,
// one <enc type=skmsg> for the content, phash for the fanout.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	waproto "google.golang.org/protobuf/proto"
)

// groupMember is one member device of a group.
type groupMember struct {
	JID string
}

// fetchGroupParticipants asks the group for its member devices: iq get
// xmlns w:g2 to the group JID, <query request="interactive"/>.
func fetchGroupParticipants(ctx context.Context, d *dispatcher, groupJID string) ([]groupMember, error) {
	reply, err := d.request(ctx, &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to": groupJID, "type": "get", "xmlns": "w:g2", "id": mustRequestID(ctx),
		},
		Children: []wabinary.Node{{Tag: "query", Attrs: wabinary.Attrs{"request": "interactive"}}},
	}, 20*time.Second)
	if err != nil {
		return nil, err
	}
	group := child(reply, "group")
	if group == nil {
		return nil, fmt.Errorf("group info reply has no <group>")
	}
	var members []groupMember
	var collect func(node *wabinary.Node)
	collect = func(node *wabinary.Node) {
		for i := range node.Children {
			if node.Children[i].Tag != "participant" {
				continue
			}
			p := &node.Children[i]
			if jid := p.Attrs["jid"]; jid != "" {
				members = append(members, groupMember{JID: jid})
			}
			collect(p)
		}
	}
	collect(group)
	if len(members) == 0 {
		return nil, fmt.Errorf("group lists no participants")
	}
	return members, nil
}

// participantListHashV2 is the phash attribute (whatsmeow): sha256 over the
// AD-form device JIDs joined, first 6 bytes, base64, "2:" prefix.
func participantListHashV2(devices []string) string {
	sorted := append([]string(nil), devices...)
	sort.Strings(sorted)
	hash := sha256.Sum256([]byte(strings.Join(sorted, "")))
	return "2:" + base64.RawStdEncoding.EncodeToString(hash[:6])
}

// jidUser strips the device suffix and server from a JID.
func jidUser(jid string) string {
	user := jid
	if at := strings.Index(jid, "@"); at >= 0 {
		user = jid[:at]
	}
	if colon := strings.Index(user, ":"); colon >= 0 {
		user = user[:colon]
	}
	return user
}

// sendGroupText sends one text message to a group. The sender key is
// ephemeral: a fresh chain, signing pair and id per send, with the SKDM
// delivered pairwise to every member device in the same flow.
func sendGroupText(ctx context.Context, d *dispatcher, sc noise.SecureConn, codec wabinary.Codec, record *credentialRecord, groupJID, messageID, text string) ([]string, error) {
	members, err := fetchGroupParticipants(ctx, d, groupJID)
	if err != nil {
		return nil, fmt.Errorf("group members: %w", err)
	}

	// The sender key: ephemeral, fresh per send.
	dist, state, err := signal.CreateSenderKeyDistribution(uint32(time.Now().Unix() & 0x7fffffff))
	if err != nil {
		return nil, fmt.Errorf("create sender key: %w", err)
	}

	// SKDM wire form.
	distWire, err := signal.SerializeSenderKeyDistribution(dist)
	if err != nil {
		return nil, fmt.Errorf("serialize skdm: %w", err)
	}

	// Group content: one encryption under the sender chain.
	innerPayload, err := stanza.EncodeTextMessage(text)
	if err != nil {
		return nil, err
	}
	wire, _, err := signal.EncryptSenderKeyMessage(state, stanza.PadMessage(innerPayload))
	if err != nil {
		return nil, fmt.Errorf("group encrypt: %w", err)
	}

	identityPair := signal.KeyPair{Private: record.IdentityPriv, Public: record.IdentityPub}

	// Pairwise SKDM delivery: every member device except our own. First
	// contact: fetch the member's bundle, initiate, encrypt, send as pkmsg.
	ownLID := jidUser(record.LID)
	var devices []string
	var toNodes []wabinary.Node
	for _, member := range members {
		if jidUser(member.JID) == ownLID {
			continue
		}
		memberJID, memberErr := stanza.ParseJID(member.JID)
		if memberErr != nil {
			continue
		}

		bundle, bundleErr := fetchPreKeyBundle(ctx, d, member.JID)
		if bundleErr != nil {
			fmt.Printf("skdm: bundle for %s: %v\n", member.JID, bundleErr)
			continue
		}
		if verifyErr := signal.ParsePreKeyBundle(*bundle); verifyErr != nil {
			fmt.Printf("skdm: bundle verify for %s: %v\n", member.JID, verifyErr)
			continue
		}
		initiator, initErr := signal.Initiate(identityPair, *bundle)
		if initErr != nil {
			fmt.Printf("skdm: initiate for %s: %v\n", member.JID, initErr)
			continue
		}
		st, stErr := signal.NewInitiator(initiator.Keys.RootKey, bundle.SignedPreKey, initiator.Keys.ChainKey)
		if stErr != nil {
			fmt.Printf("skdm: state for %s: %v\n", member.JID, stErr)
			continue
		}

		// The SKDM travels inside a protobuf Message wrapper.
		skdPayload, skdErr := waproto.Marshal(&protobuf.Message{
			SenderKeyDistributionMessage: &protobuf.SenderKeyDistributionMessage{
				GroupID:                             protoStr(groupJID),
				AxolotlSenderKeyDistributionMessage: distWire,
			},
		})
		if skdErr != nil {
			continue
		}
		enc, encErr := st.Encrypt(stanza.PadMessage(skdPayload), identityPair.Public, bundle.IdentityKey)
		if encErr != nil {
			fmt.Printf("skdm: encrypt for %s: %v\n", member.JID, encErr)
			continue
		}
		skdmWire, skdmWireErr := initiator.BuildPreKeyMessage(identityPair.Public, record.RegistrationID, enc)
		if skdmWireErr != nil {
			fmt.Printf("skdm: prekey message for %s: %v\n", member.JID, skdmWireErr)
			continue
		}
		skdmID, skdmIDErr := randomID()
		if skdmIDErr != nil {
			continue
		}
		skdmNode, skdmNodeErr := stanza.BuildEncryptedText(stanza.EncryptedText{
			ID: skdmID, To: memberJID, Carrier: stanza.CarrierPKMsg, Ciphertext: skdmWire,
		})
		if skdmNodeErr != nil {
			continue
		}
		skdmFrame, skdmFrameErr := codec.Encode(skdmNode)
		if skdmFrameErr != nil {
			continue
		}
		if skdmWriteErr := sc.WriteFrame(ctx, skdmFrame); skdmWriteErr != nil {
			continue
		}
		devices = append(devices, member.JID)
		toNodes = append(toNodes, wabinary.Node{
			Tag: "to", Attrs: wabinary.Attrs{"jid": member.JID},
		})
	}

	// The group message: one skmsg for the content, phash for the fanout.
	node := &wabinary.Node{
		Tag: "message",
		Attrs: wabinary.Attrs{
			"id":    messageID,
			"type":  "text",
			"to":    groupJID,
			"phash": participantListHashV2(devices),
		},
		Children: append(toNodes, wabinary.Node{
			Tag: "enc", Attrs: wabinary.Attrs{"v": "2", "type": "skmsg"}, Bytes: wire,
		}),
	}
	frame, err := codec.Encode(node)
	if err != nil {
		return nil, err
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		return nil, err
	}
	return devices, nil
}

// protoStr returns a pointer to a string, for proto2 optional fields.
func protoStr(value string) *string { return &value }
