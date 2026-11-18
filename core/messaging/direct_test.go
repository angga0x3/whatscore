package messaging

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	"google.golang.org/protobuf/proto"
)

// mapBundles serves one prekey bundle per device address.
type mapBundles map[string]*signal.PreKeyBundle

func (m mapBundles) PreKeyBundle(_ context.Context, peer string) (*signal.PreKeyBundle, error) {
	bundle, ok := m[peer]
	if !ok {
		return nil, ErrNoPreKey
	}
	return bundle, nil
}

// fixedDevices returns the same device list for every account query.
type fixedDevices []string

func (d fixedDevices) Devices(context.Context, []string) ([]string, error) { return d, nil }

// recordingWriter remembers whether the frame was written before or after the
// persistence callback, because that order is what protects a message key.
type recordingWriter struct {
	events []string
	frames [][]byte
}

func (w *recordingWriter) WriteFrame(_ context.Context, frame []byte) error {
	w.events = append(w.events, "write")
	w.frames = append(w.frames, append([]byte(nil), frame...))
	return nil
}

func (w *recordingWriter) persist(_ context.Context, peer string, _ *PeerSession) error {
	w.events = append(w.events, "persist:"+peer)
	return nil
}

// establishedPeer runs a full X3DH handshake and authenticates the session with
// a reply, which is what a real peer does before the next send may use msg.
func establishedPeer(t *testing.T, identity signal.KeyPair) (signal.KeyPair, *PeerSession, *signal.State) {
	t.Helper()
	peerIdentity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signal.GenerateSignedPreKey(1, signal.XEdDSASigner{Private: peerIdentity.Private})
	if err != nil {
		t.Fatal(err)
	}
	oneTime, err := signal.GeneratePreKey(2)
	if err != nil {
		t.Fatal(err)
	}
	initiated, err := signal.Initiate(identity, signal.PreKeyBundle{
		IdentityKey:           peerIdentity.Public,
		SignedPreKeyID:        signed.ID,
		SignedPreKey:          signed.Pair.Public,
		SignedPreKeySignature: signed.Signature,
		OneTimePreKeyID:       oneTime.ID,
		OneTimePreKey:         &oneTime.Pair.Public,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := signal.NewInitiator(initiated.Keys.RootKey, signed.Pair.Public, initiated.Keys.ChainKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := signal.Respond(peerIdentity, signed.Pair, &oneTime.Pair, identity.Public, initiated.EphemeralPublic)
	if err != nil {
		t.Fatal(err)
	}
	theirs := signal.NewResponder(keys.RootKey, signed.Pair, keys.ChainKey)
	reply, err := theirs.Encrypt([]byte("akui"), peerIdentity.Public, identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Decrypt(reply, peerIdentity.Public, identity.Public); err != nil {
		t.Fatal(err)
	}
	return peerIdentity, &PeerSession{PeerIdentity: peerIdentity.Public, State: state}, theirs
}

func decryptedText(t *testing.T, ciphertext []byte, state *signal.State, sender, receiver [32]byte) string {
	t.Helper()
	plaintext, err := state.Decrypt(ciphertext, sender, receiver)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	plaintext, err = stanza.UnpadMessage(plaintext, "2")
	if err != nil {
		t.Fatalf("unpad: %v", err)
	}
	text, err := stanza.DecodeTextMessage(plaintext)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return text
}

func participantFor(t *testing.T, node *binary.Node, jid string) []byte {
	t.Helper()
	participants := node.Children[0]
	for i := range participants.Children {
		if participants.Children[i].Attrs["jid"] == jid {
			return participants.Children[i].Children[0].Bytes
		}
	}
	t.Fatalf("no participant for %s", jid)
	return nil
}

// TestSendDirectFansOutPerDevice pins the shape that fixes "waiting for this
// message": one stanza, one ciphertext per device, and the sender's own
// devices get the DeviceSentMessage plaintext rather than the recipient's.
func TestSendDirectFansOutPerDevice(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	to := "628555@s.whatsapp.net"
	recipientDevices := []string{"628555:12@s.whatsapp.net", "628555:13@s.whatsapp.net"}
	ownDevices := []string{"266988689592415@lid", "266988689592415:35@lid"}
	const ownPN = "628994340905:39@s.whatsapp.net"
	const ownLID = "266988689592415:39@lid"

	writer := &recordingWriter{}
	sender, err := NewSender(writer)
	if err != nil {
		t.Fatal(err)
	}
	sender.SetIdentityPair(identity)
	sender.SetDeviceIdentity([]byte("device-identity-blob"))

	type peerState struct {
		peer  *PeerSession
		state *signal.State
		id    signal.KeyPair
	}
	states := map[string]peerState{}
	for _, peer := range append(append([]string{}, recipientDevices...), ownDevices...) {
		peerID, session, theirs := establishedPeer(t, identity)
		states[peer] = peerState{peer: session, state: theirs, id: peerID}
		if err := sender.SetPeer(peer, session); err != nil {
			t.Fatal(err)
		}
	}
	devices := append(append([]string{ownPN}, recipientDevices...), ownDevices...)
	id, updated, err := sender.SendDirect(context.Background(), fixedDevices(devices), DirectMessage{
		To: to, Type: stanza.MessageTypeText,
		OwnJID: ownPN, OwnLID: ownLID, RegistrationID: 4242,
		Message: &protobuf.Message{Conversation: proto.String("halo banyak perangkat")},
		Persist: writer.persist,
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if id == "" {
		t.Fatal("empty id")
	}
	if len(updated) != len(recipientDevices)+len(ownDevices) {
		t.Fatalf("updated = %d", len(updated))
	}
	if len(writer.frames) != 1 {
		t.Fatalf("frames = %d, want one participant stanza", len(writer.frames))
	}

	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatal(err)
	}
	if node.Tag != "message" || node.Attrs["to"] != to || node.Attrs["id"] != id || node.Attrs["type"] != "text" {
		t.Fatalf("stanza attrs = %#v", node.Attrs)
	}
	if len(node.Children) != 1 || node.Children[0].Tag != "participants" {
		t.Fatalf("children = %#v", node.Children)
	}
	participants := node.Children[0].Children
	if len(participants) != len(recipientDevices)+len(ownDevices) {
		t.Fatalf("participants = %d", len(participants))
	}
	for _, peer := range recipientDevices {
		got := decryptedText(t, participantFor(t, node, peer), states[peer].state, identity.Public, states[peer].id.Public)
		if got != "halo banyak perangkat" {
			t.Fatalf("%s text = %q", peer, got)
		}
	}
	for _, peer := range ownDevices {
		plaintext, err := states[peer].state.Decrypt(participantFor(t, node, peer), identity.Public, states[peer].id.Public)
		if err != nil {
			t.Fatalf("%s copy: %v", peer, err)
		}
		plaintext, err = stanza.UnpadMessage(plaintext, "2")
		if err != nil {
			t.Fatal(err)
		}
		payload, err := stanza.DecodePayload(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if payload.Text != "halo banyak perangkat" || payload.Destination != to {
			t.Fatalf("%s copy = %#v", peer, payload)
		}
	}

	// Every advanced ratchet was persisted before the frame left, or a restart
	// could reuse a message key the server already has.
	if len(writer.events) == 0 || writer.events[len(writer.events)-1] != "write" {
		t.Fatalf("events = %v, want every persist before the write", writer.events)
	}
	for _, event := range writer.events[:len(writer.events)-1] {
		if event == "write" {
			t.Fatalf("write happened before persists: %v", writer.events)
		}
	}
}

// TestSendDirectBootstrapsAndKeepsPending pins first contact: a device with no
// authenticated session receives a pkmsg, the payload is readable, and the
// bootstrap stays pending until a reply proves it arrived.
func TestSendDirectBootstrapsAndKeepsPending(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	prekeys := newTestPreKeys(t, true)
	peer := "628555:12@s.whatsapp.net"

	writer := &recordingWriter{}
	sender, err := NewSender(writer)
	if err != nil {
		t.Fatal(err)
	}
	sender.SetIdentityPair(identity)
	sender.SetDeviceIdentity([]byte("device-identity-blob"))
	sender.SetPreKeyBundleSource(mapBundles{peer: &prekeys.bundle})

	request := DirectMessage{
		To: "628555@s.whatsapp.net", Type: stanza.MessageTypeText,
		OwnJID: "628994340905:39@s.whatsapp.net", RegistrationID: 4242,
		Message: &protobuf.Message{Conversation: proto.String("pertama")},
		Persist: writer.persist,
	}
	if _, _, err := sender.SendDirect(context.Background(), fixedDevices{peer}, request); err != nil {
		t.Fatalf("send: %v", err)
	}
	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatal(err)
	}
	participant := node.Children[0].Children[0]
	if got := participant.Children[0].Attrs["type"]; got != stanza.CarrierPKMsg {
		t.Fatalf("carrier = %q, want pkmsg", got)
	}
	var hasIdentity bool
	for _, child := range node.Children {
		if child.Tag == "device-identity" {
			hasIdentity = true
		}
	}
	if !hasIdentity {
		t.Fatal("pkmsg stanza has no device-identity")
	}

	_, plaintext, err := signal.AcceptPreKeyMessage(participant.Children[0].Bytes,
		prekeys.identity, *prekeys.signed, prekeys.oneTime)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	plaintext, err = stanza.UnpadMessage(plaintext, "2")
	if err != nil {
		t.Fatal(err)
	}
	if text, err := stanza.DecodeTextMessage(plaintext); err != nil || text != "pertama" {
		t.Fatalf("text = %q, %v", text, err)
	}
	session := sender.peers[peer]
	if session == nil || !session.State.HasPendingPreKey() {
		t.Fatal("bootstrap not retained after the first send")
	}

	// The peer never replied, so the second send must carry the bootstrap
	// again; a bare msg would leave a device that missed the first stranded.
	if _, _, err := sender.SendDirect(context.Background(), fixedDevices{peer}, request); err != nil {
		t.Fatalf("second send: %v", err)
	}
	node, err = binary.NewCodec(nil).Decode(bytes.NewReader(writer.frames[1]))
	if err != nil {
		t.Fatal(err)
	}
	if got := node.Children[0].Children[0].Children[0].Attrs["type"]; got != stanza.CarrierPKMsg {
		t.Fatalf("second carrier = %q, want pkmsg", got)
	}
	peerState, plaintext, err := signal.AcceptPreKeyMessage(node.Children[0].Children[0].Children[0].Bytes,
		prekeys.identity, *prekeys.signed, prekeys.oneTime)
	if err != nil {
		t.Fatalf("second accept: %v", err)
	}
	if direct, err := stanza.UnpadMessage(plaintext, "2"); err != nil {
		t.Fatal(err)
	} else if text, err := stanza.DecodeTextMessage(direct); err != nil || text != "pertama" {
		t.Fatalf("second text = %q, %v", text, err)
	}

	// An authenticated reply ends the pending state; the next send is msg.
	// Every send installs a clone, so read the live session back instead of
	// holding the first pointer.
	session = sender.peers[peer]
	if session == nil {
		t.Fatal("session vanished")
	}
	reply, err := peerState.Encrypt([]byte("balasan"), prekeys.identity.Public, identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.State.Decrypt(reply, prekeys.identity.Public, identity.Public); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sender.SendDirect(context.Background(), fixedDevices{peer}, request); err != nil {
		t.Fatalf("third send: %v", err)
	}
	node, err = binary.NewCodec(nil).Decode(bytes.NewReader(writer.frames[2]))
	if err != nil {
		t.Fatal(err)
	}
	if got := node.Children[0].Children[0].Children[0].Attrs["type"]; got != stanza.CarrierMsg {
		t.Fatalf("third carrier = %q, want msg after an authenticated reply", got)
	}
}

// TestSendDirectRefusesWithoutRecipientDevices keeps an account-wide encrypted
// send impossible: no resolved device means no frame.
func TestSendDirectRefusesWithoutRecipientDevices(t *testing.T) {
	sender, err := NewSender(&recordingWriter{})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sender.SetIdentityPair(identity)
	writer := &recordingWriter{}
	sender.write = writer
	_, _, err = sender.SendDirect(context.Background(), fixedDevices{"266988689592415:39@lid"}, DirectMessage{
		To: "628555@s.whatsapp.net", OwnJID: "628994340905:39@s.whatsapp.net",
		OwnLID:  "266988689592415:39@lid",
		Message: &protobuf.Message{Conversation: proto.String("x")},
		Persist: writer.persist,
	})
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("err = %v", err)
	}
	if len(writer.frames) != 0 {
		t.Fatal("a frame was written without a recipient device")
	}
}

// TestAccountAliasMapsOnlyThisAccountsDevices pins the PN→LID session lookup:
// a device query for the account's phone number returns PN addresses, while
// the sessions those devices created live under their LID addresses.
func TestAccountAliasMapsOnlyThisAccountsDevices(t *testing.T) {
	alias := AccountAlias("628994340905:39@s.whatsapp.net", "266988689592415:39@lid")
	if alias == nil {
		t.Fatal("no alias")
	}
	if got := alias("628994340905@s.whatsapp.net"); got != "266988689592415@lid" {
		t.Fatalf("device 0 = %q", got)
	}
	if got := alias("628994340905:35@s.whatsapp.net"); got != "266988689592415:35@lid" {
		t.Fatalf("device 35 = %q", got)
	}
	if got := alias("628555@s.whatsapp.net"); got != "" {
		t.Fatalf("another account mapped to %q", got)
	}
	if alias := AccountAlias("", "266988689592415:39@lid"); alias != nil {
		t.Fatal("alias built without a PN")
	}
}
