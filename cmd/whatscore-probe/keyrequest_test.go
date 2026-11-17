package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	"google.golang.org/protobuf/proto"
)

// captureWriter keeps the frames a send produced, so a test can decode what
// actually went to the wire instead of trusting the call returned.
type captureWriter struct {
	frames [][]byte
}

func (w *captureWriter) WriteFrame(_ context.Context, frame []byte) error {
	w.frames = append(w.frames, append([]byte(nil), frame...))
	return nil
}

// TestPhonePeerForMatchesTheAccountLID pins the rule the own-device copy rides
// on: the phone's session is the one whose JID user equals the account LID
// user, because the LID is account-scoped while the device suffix differs.
func TestPhonePeerForMatchesTheAccountLID(t *testing.T) {
	sessions := map[string]storedSession{
		"628123@s.whatsapp.net":             {},
		"266988689592415:39@lid":            {},
		"999999999999999:12@s.whatsapp.net": {},
	}
	got := phonePeerFor("266988689592415:39@lid", sessions)
	if got != "266988689592415:39@lid" {
		t.Fatalf("phonePeerFor = %q", got)
	}
	if got := phonePeerFor("266988689592415@lid", sessions); got != "266988689592415:39@lid" {
		t.Fatalf("device-less LID = %q", got)
	}
	if got := phonePeerFor("555555555555555:1@lid", sessions); got != "" {
		t.Fatalf("unrelated account matched: %q", got)
	}
	if got := phonePeerFor("", sessions); got != "" {
		t.Fatalf("empty LID matched: %q", got)
	}
}

// TestSendOwnDeviceCopyWrapsForThePhoneAndPersists pins the copy end to end at
// the layer the probe owns: the frame that leaves names the phone, the
// plaintext is a DeviceSentMessage naming the destination, and the phone's
// ratchet is written back so the next run continues it.
func TestSendOwnDeviceCopyWrapsForThePhoneAndPersists(t *testing.T) {
	t.Chdir(t.TempDir())
	sessionsPath := sessionsPathFor("paired.keys.json")

	phonePeer := "266988689592415:35@lid"
	session, _, identity, _ := newCopyFixture(t)
	store := &sessionsFile{Sessions: map[string]storedSession{}}
	if err := store.persist(sessionsPath, phonePeer, session); err != nil {
		t.Fatalf("seed phone session: %v", err)
	}
	before := store.Sessions[phonePeer].State

	record := &credentialRecord{LID: "266988689592415:39@lid"}
	record.IdentityPriv = identity.Private
	record.IdentityPub = identity.Public

	writer := &captureWriter{}
	codec := wabinary.NewCodec(nil)
	if err := sendOwnDeviceCopy(context.Background(), writer, codec, store, sessionsPath, record, "628555@s.whatsapp.net", "MSGID1", textInner("halo dari web")); err != nil {
		t.Fatalf("sendOwnDeviceCopy: %v", err)
	}

	if len(writer.frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(writer.frames))
	}
	node, err := codec.Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	if node.Tag != "message" || node.Attrs["to"] != phonePeer {
		t.Fatalf("stanza = %s to=%q", node.Tag, node.Attrs["to"])
	}
	if node.Attrs["id"] != "MSGID1" {
		t.Fatalf("id = %q, want the recipient copy's id", node.Attrs["id"])
	}
	if node.Attrs["device_fanout"] != "false" {
		t.Fatalf("device_fanout = %q, want false on a device-addressed stanza", node.Attrs["device_fanout"])
	}
	if len(node.Children) != 1 || node.Children[0].Tag != "enc" {
		t.Fatalf("children = %#v", node.Children)
	}

	// The ratchet advanced, so the state on disk must differ: leaving it
	// behind makes the next run encrypt from a chain the phone has left.
	reloaded, err := loadSessionsFile(sessionsPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Sessions[phonePeer].State == before {
		t.Fatal("phone session was not written back after the copy")
	}
}

// TestSendOwnDeviceCopyReportsMissingPhoneSession keeps the failure honest: no
// session with the phone means no copy, and saying so beats sending a copy
// nobody can open.
func TestSendOwnDeviceCopyReportsMissingPhoneSession(t *testing.T) {
	t.Chdir(t.TempDir())
	sessionsPath := sessionsPathFor("paired.keys.json")
	store, err := loadSessionsFile(sessionsPath)
	if err != nil {
		t.Fatal(err)
	}
	record := &credentialRecord{LID: "266988689592415:39@lid"}
	if err := sendOwnDeviceCopy(context.Background(), &captureWriter{}, wabinary.NewCodec(nil), store, sessionsPath, record, "628555@s.whatsapp.net", "MSGID2", textInner("halo")); err == nil {
		t.Fatal("copy sent without a phone session")
	}
}

// TestSendOwnDeviceCopyPlaintextNamesTheDestination decrypts the frame the
// copy produced and checks the wrapper, which is the part a receiver keys on.
func TestSendOwnDeviceCopyPlaintextNamesTheDestination(t *testing.T) {
	t.Chdir(t.TempDir())
	sessionsPath := sessionsPathFor("paired.keys.json")

	phonePeer := "266988689592415:35@lid"
	session, phone, identity, phoneIdentity := newCopyFixture(t)
	// The phone's state must be a copy: the send advances our side only, and
	// decrypting with the object we also read from would prove nothing.
	phoneBefore, err := phone.Clone()
	if err != nil {
		t.Fatalf("clone phone state: %v", err)
	}
	store := &sessionsFile{Sessions: map[string]storedSession{}}
	if err := store.persist(sessionsPath, phonePeer, session); err != nil {
		t.Fatal(err)
	}
	record := &credentialRecord{LID: "266988689592415:39@lid"}
	record.IdentityPriv = identity.Private
	record.IdentityPub = identity.Public

	writer := &captureWriter{}
	codec := wabinary.NewCodec(nil)
	if err := sendOwnDeviceCopy(context.Background(), writer, codec, store, sessionsPath, record, "628555@s.whatsapp.net", "MSGID3", textInner("isi pesan")); err != nil {
		t.Fatal(err)
	}
	node, err := codec.Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := node.Children[0].Bytes
	plaintext, err := phoneBefore.Decrypt(ciphertext, identity.Public, phoneIdentity)
	if err != nil {
		t.Fatalf("the copy does not decrypt with the phone's state: %v", err)
	}
	unpadded, err := stanza.UnpadMessage(plaintext, "2")
	if err != nil {
		t.Fatalf("unpad: %v", err)
	}
	payload, err := stanza.DecodePayload(unpadded)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Text != "isi pesan" || payload.Destination != "628555@s.whatsapp.net" {
		t.Fatalf("payload = %#v", payload)
	}
}

// TestSessionRecordStateIsBase64 guards the file format the probe reads back:
// a plaintext ratchet on disk would be a key leak.
func TestSessionRecordStateIsBase64(t *testing.T) {
	store := &sessionsFile{Sessions: map[string]storedSession{}}
	if err := store.record("111@s.whatsapp.net", newTestPeerSession(t)); err != nil {
		t.Fatal(err)
	}
	rec := store.Sessions["111@s.whatsapp.net"]
	if _, err := base64.StdEncoding.DecodeString(rec.State); err != nil {
		t.Fatalf("state is not base64: %v", err)
	}
}

// newCopyFixture builds the two sides the copy needs: our session with the
// phone (the initiator, which is what sends) and the phone's own state, so a
// test can decrypt what went out.
func newCopyFixture(t *testing.T) (session *coremessaging.PeerSession, phone *signal.State, identity signal.KeyPair, phoneIdentity [32]byte) {
	t.Helper()
	var err error
	identity, err = signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	phonePair, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("phone identity: %v", err)
	}
	signed, err := signal.GenerateSignedPreKey(1, signal.XEdDSASigner{Private: phonePair.Private})
	if err != nil {
		t.Fatalf("signed prekey: %v", err)
	}
	oneTime, err := signal.GeneratePreKey(2)
	if err != nil {
		t.Fatalf("one-time prekey: %v", err)
	}
	bundle := signal.PreKeyBundle{
		IdentityKey:           phonePair.Public,
		SignedPreKeyID:        signed.ID,
		SignedPreKey:          signed.Pair.Public,
		SignedPreKeySignature: signed.Signature,
		OneTimePreKeyID:       oneTime.ID,
		OneTimePreKey:         &oneTime.Pair.Public,
	}
	initiated, err := signal.Initiate(identity, bundle)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	ourState, err := signal.NewInitiator(initiated.Keys.RootKey, signed.Pair.Public, initiated.Keys.ChainKey)
	if err != nil {
		t.Fatalf("initiator state: %v", err)
	}
	// The phone's side of the same handshake: the responder ratchets on the
	// signed prekey, which is the key the bundle published.
	keys, err := signal.Respond(phonePair, signed.Pair, &oneTime.Pair, identity.Public, initiated.EphemeralPublic)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	phone = signal.NewResponder(keys.RootKey, signed.Pair, keys.ChainKey)
	return &coremessaging.PeerSession{PeerIdentity: phonePair.Public, State: ourState}, phone, identity, phonePair.Public
}

// textInner is the payload a text send carries, as a message the copy wraps.
func textInner(text string) *protobuf.Message {
	return &protobuf.Message{Conversation: proto.String(text)}
}

var _ = coremessaging.ErrNoSession

// TestIsOwnAccountMatchesBothIdentities pins the self-send guard: the account
// has a phone-number address and a LID, and a send to either one already
// reaches the phone as the recipient's copy.
func TestIsOwnAccountMatchesBothIdentities(t *testing.T) {
	record := &credentialRecord{
		JID: "628994340905:39@s.whatsapp.net",
		LID: "266988689592415:39@lid",
	}
	for _, dest := range []string{
		"628994340905@s.whatsapp.net",
		"628994340905:39@s.whatsapp.net",
		"266988689592415@lid",
		"266988689592415:12@lid",
	} {
		if !isOwnAccount(dest, record) {
			t.Fatalf("%s not recognised as this account", dest)
		}
	}
	for _, dest := range []string{
		"628555@s.whatsapp.net",
		"999999999999999@lid",
		"",
	} {
		if isOwnAccount(dest, record) {
			t.Fatalf("%s wrongly recognised as this account", dest)
		}
	}
}

// TestOwnDeviceCopyFansOutPerDevice pins the delivery rule the live "waiting
// for this message" placeholder exposed: a copy for the account is not a copy
// for its devices. Each device gets its own ciphertext, addressed to it alone.
func TestOwnDeviceCopyFansOutPerDevice(t *testing.T) {
	t.Chdir(t.TempDir())
	sessionsPath := sessionsPathFor("paired.keys.json")
	record := &credentialRecord{LID: "266988689592415:39@lid", JID: "628994340905:39@s.whatsapp.net"}
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	record.IdentityPriv, record.IdentityPub = identity.Private, identity.Public

	store := &sessionsFile{Sessions: map[string]storedSession{}}
	// Device 0 (the primary phone, bare LID) and a linked device (:35). This
	// device is :39 and must not receive its own copy.
	for _, peer := range []string{"266988689592415@lid", "266988689592415:35@lid"} {
		if err := store.persist(sessionsPath, peer, newTestPeerSession(t)); err != nil {
			t.Fatalf("seed %s: %v", peer, err)
		}
	}
	writer := &captureWriter{}
	codec := wabinary.NewCodec(nil)
	if err := sendOwnDeviceCopy(context.Background(), writer, codec, store, sessionsPath, record, "628555@s.whatsapp.net", "SAMEID", textInner("halo")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if len(writer.frames) != 2 {
		t.Fatalf("frames = %d, want one per other device", len(writer.frames))
	}
	got := map[string]bool{}
	for _, frame := range writer.frames {
		node, err := codec.Decode(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if node.Attrs["id"] != "SAMEID" {
			t.Fatalf("id = %q", node.Attrs["id"])
		}
		if node.Attrs["device_fanout"] != "false" {
			t.Fatalf("device_fanout = %q on a device copy", node.Attrs["device_fanout"])
		}
		got[node.Attrs["to"]] = true
	}
	if !got["266988689592415@lid"] || !got["266988689592415:35@lid"] {
		t.Fatalf("copies went to %v", got)
	}
	if got["266988689592415:39@lid"] {
		t.Fatal("the sending device received its own copy")
	}
}
