package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/core/mediaout"
	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
	storagecredentials "github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
)

// runtimeWriter captures frames the runtime's sender writes.
type runtimeWriter struct{ frames [][]byte }

func (w *runtimeWriter) WriteFrame(_ context.Context, frame []byte) error {
	w.frames = append(w.frames, append([]byte(nil), frame...))
	return nil
}

// newTestVault builds the encrypted store two runtimes can share, which is
// what makes a restart observable.
func newTestVault(t *testing.T) *storagecredentials.Vault {
	t.Helper()
	key, err := envelope.NewKey(bytes.Repeat([]byte{0x11}, envelope.KeySize))
	if err != nil {
		t.Fatalf("envelope key: %v", err)
	}
	vault, err := storagecredentials.NewVault(storagecredentials.NewMemoryBackend(), key)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	return vault
}

// newVaultBackedRuntime builds a runtime whose ratchets live in the vault the
// way the server's do.
func newVaultBackedRuntime(t *testing.T, id string, identity signal.KeyPair, vault *storagecredentials.Vault) (*sessionRuntime, *runtimeWriter) {
	t.Helper()
	signals, err := newSignalStore(vault, id)
	if err != nil {
		t.Fatalf("signal store: %v", err)
	}
	bus := events.NewBus()
	t.Cleanup(bus.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime, err := newSessionRuntime(id, binary.NewCodec(nil), logger, identity, nil, 4242, pairedAccount{}, nil, bus, appStateKeyPath(id), signals, vault)
	if err != nil {
		t.Fatalf("runtime: %v", err)
	}
	writer := &runtimeWriter{}
	runtime.attach(writer)
	return runtime, writer
}

// newPeerPair builds both ends of an established 1:1 Signal conversation: the
// session this device holds and the peer's own state, which is what proves a
// restored ratchet still opens.
func newPeerPair(t *testing.T) (identity, peerIdentity signal.KeyPair, ours *coremessaging.PeerSession, theirs *signal.State) {
	t.Helper()
	var err error
	identity, err = signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	peerIdentity, ours, theirs = peerConversation(t, identity)
	return identity, peerIdentity, ours, theirs
}

// peerConversation builds one peer's side of a conversation with identity.
func peerConversation(t *testing.T, identity signal.KeyPair) (peerIdentity signal.KeyPair, ours *coremessaging.PeerSession, theirs *signal.State) {
	t.Helper()
	var err error
	peerIdentity, err = signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("peer identity: %v", err)
	}
	signed, err := signal.GenerateSignedPreKey(1, signal.XEdDSASigner{Private: peerIdentity.Private})
	if err != nil {
		t.Fatalf("signed prekey: %v", err)
	}
	oneTime, err := signal.GeneratePreKey(2)
	if err != nil {
		t.Fatalf("one-time prekey: %v", err)
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
		t.Fatalf("initiate: %v", err)
	}
	state, err := signal.NewInitiator(initiated.Keys.RootKey, signed.Pair.Public, initiated.Keys.ChainKey)
	if err != nil {
		t.Fatalf("initiator state: %v", err)
	}
	keys, err := signal.Respond(peerIdentity, signed.Pair, &oneTime.Pair, identity.Public, initiated.EphemeralPublic)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	return peerIdentity, &coremessaging.PeerSession{PeerIdentity: peerIdentity.Public, State: state},
		signal.NewResponder(keys.RootKey, signed.Pair, keys.ChainKey)
}

// seedPeerSession writes a peer ratchet the way a previous process would have,
// before any runtime exists.
func seedPeerSession(t *testing.T, vault *storagecredentials.Vault, sessionID, peer string, session *coremessaging.PeerSession) {
	t.Helper()
	store, err := newSignalStore(vault, sessionID)
	if err != nil {
		t.Fatalf("signal store: %v", err)
	}
	if err := store.save(context.Background(), peer, session); err != nil {
		t.Fatalf("seed peer session: %v", err)
	}
}

// TestRuntimeSurvivesARestart is the server half of the PF-087 lesson: a
// ratchet the runtime persisted must come back on the next start, or the
// peer's next msg-carrier message has no session to open and the send path
// re-initiates from a fresh prekey.
func TestRuntimeSurvivesARestart(t *testing.T) {
	identity, peerIdentity, ours, theirs := newPeerPair(t)
	peer := "628123@s.whatsapp.net"
	vault := newTestVault(t)

	// Run one: the session arrives (a decrypt installs it), and the runtime
	// persists it through the vault.
	seedPeerSession(t, vault, "session-1", peer, ours)

	// Run two: a new runtime over the same vault must send on the continued
	// chain, and the peer must be able to open what it wrote.
	second, writer := newVaultBackedRuntime(t, "session-1", identity, vault)
	if _, err := second.DeliverText(context.Background(), peer, "setelah restart"); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(writer.frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(writer.frames))
	}
	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := node.Children[0].Attrs["type"]; got != stanza.CarrierMsg {
		t.Fatalf("carrier = %q, want msg — a restored session, not a fresh pkmsg", got)
	}
	plaintext, err := theirs.Decrypt(node.Children[0].Bytes, identity.Public, peerIdentity.Public)
	if err != nil {
		t.Fatalf("peer cannot open the restored chain: %v", err)
	}
	unpadded, err := stanza.UnpadMessage(plaintext, "2")
	if err != nil {
		t.Fatalf("unpad: %v", err)
	}
	if text, err := stanza.DecodeTextMessage(unpadded); err != nil || text != "setelah restart" {
		t.Fatalf("text = %q, %v", text, err)
	}
}

// TestRuntimePersistsOnSend pins the send half: a send advances the ratchet
// and no observer fires for it, so the runtime has to write the returned
// state itself or the next process starts one step behind the peer.
func TestRuntimePersistsOnSend(t *testing.T) {
	identity, peerIdentity, ours, theirs := newPeerPair(t)
	peer := "628123@s.whatsapp.net"
	vault := newTestVault(t)

	seedPeerSession(t, vault, "session-1", peer, ours)

	first, _ := newVaultBackedRuntime(t, "session-1", identity, vault)
	if _, err := first.DeliverText(context.Background(), peer, "satu"); err != nil {
		t.Fatalf("first send: %v", err)
	}

	// The next process reads what the first wrote. Both messages must open in
	// order on the peer, which only works if the advanced state was saved.
	second, writer := newVaultBackedRuntime(t, "session-1", identity, vault)
	if _, err := second.DeliverText(context.Background(), peer, "dua"); err != nil {
		t.Fatalf("second send: %v", err)
	}
	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	plaintext, err := theirs.Decrypt(node.Children[0].Bytes, identity.Public, peerIdentity.Public)
	if err != nil {
		t.Fatalf("peer cannot open the second message: %v", err)
	}
	unpadded, err := stanza.UnpadMessage(plaintext, "2")
	if err != nil {
		t.Fatalf("unpad: %v", err)
	}
	if text, err := stanza.DecodeTextMessage(unpadded); err != nil || text != "dua" {
		t.Fatalf("text = %q, %v", text, err)
	}
}

// TestRuntimeSendsTheOwnDeviceCopy is the server half of PF-090: a send from
// this device must reach the phone wrapped in DeviceSentMessage, under the
// recipient copy's id, so the phone renders one outgoing message in the
// destination chat instead of nothing.
func TestRuntimeSendsTheOwnDeviceCopy(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	peer := "628555@s.whatsapp.net"
	phone := "266988689592415:35@lid"
	_, recipientSession, _ := peerConversation(t, identity)
	phoneIdentity, phoneSession, phoneState := peerConversation(t, identity)

	vault := newTestVault(t)
	seedPeerSession(t, vault, "session-1", peer, recipientSession)
	seedPeerSession(t, vault, "session-1", phone, phoneSession)

	runtime, writer := newVaultBackedRuntime(t, "session-1", identity, vault)
	runtime.ownLID = "266988689592415:39@lid"
	if _, err := runtime.DeliverText(context.Background(), peer, "halo dari server"); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	if len(writer.frames) != 2 {
		t.Fatalf("frames = %d, want the recipient copy and the own-device copy", len(writer.frames))
	}
	codec := binary.NewCodec(nil)
	recipientNode, err := codec.Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatalf("decode recipient frame: %v", err)
	}
	copyNode, err := codec.Decode(bytes.NewReader(writer.frames[1]))
	if err != nil {
		t.Fatalf("decode copy frame: %v", err)
	}
	if got := copyNode.Attrs["to"]; got != phone {
		t.Fatalf("copy to = %q, want the phone %q", got, phone)
	}
	if copyNode.Attrs["id"] != recipientNode.Attrs["id"] {
		t.Fatalf("copy id = %q, recipient id = %q — one message, one id",
			copyNode.Attrs["id"], recipientNode.Attrs["id"])
	}
	if got := copyNode.Attrs["device_fanout"]; got != "false" {
		t.Fatalf("device_fanout = %q, want false", got)
	}

	plaintext, err := phoneState.Decrypt(copyNode.Children[0].Bytes, identity.Public, phoneIdentity.Public)
	if err != nil {
		t.Fatalf("phone cannot open the copy: %v", err)
	}
	unpadded, err := stanza.UnpadMessage(plaintext, "2")
	if err != nil {
		t.Fatalf("unpad: %v", err)
	}
	payload, err := stanza.DecodePayload(unpadded)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Text != "halo dari server" {
		t.Fatalf("copy text = %q", payload.Text)
	}
	if payload.Destination != peer {
		t.Fatalf("copy destination = %q, want %q", payload.Destination, peer)
	}
}

// TestRuntimeSkipsTheCopyWithoutAPhoneSession pins the honest failure: with
// no ratchet to the phone there is nothing to encrypt the copy to, the
// recipient's copy still goes out, and the send reports success.
func TestRuntimeSkipsTheCopyWithoutAPhoneSession(t *testing.T) {
	identity, _, recipientSession, _ := newPeerPair(t)
	peer := "628555@s.whatsapp.net"
	vault := newTestVault(t)
	seedPeerSession(t, vault, "session-1", peer, recipientSession)

	runtime, writer := newVaultBackedRuntime(t, "session-1", identity, vault)
	runtime.ownLID = "266988689592415:39@lid"
	if _, err := runtime.DeliverText(context.Background(), peer, "tanpa hp"); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(writer.frames) != 1 {
		t.Fatalf("frames = %d, want the recipient copy only", len(writer.frames))
	}
}

// TestRuntimeSkipsTheCopyForSelfSend pins the exception: the recipient of a
// note-to-self is the account itself, whose devices include the phone, so the
// recipient's copy already lands there. A second copy would show the message
// twice in the self chat.
func TestRuntimeSkipsTheCopyForSelfSend(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	ownLID := "266988689592415:39@lid"
	_, selfSession, _ := peerConversation(t, identity)
	_, selfSessionPN, _ := peerConversation(t, identity)

	vault := newTestVault(t)
	seedPeerSession(t, vault, "session-1", ownLID, selfSession)
	seedPeerSession(t, vault, "session-1", "628994340905@s.whatsapp.net", selfSessionPN)

	runtime, writer := newVaultBackedRuntime(t, "session-1", identity, vault)
	runtime.ownLID = ownLID
	runtime.ownJID = "628994340905:39@s.whatsapp.net"
	for _, dest := range []string{ownLID, "628994340905@s.whatsapp.net"} {
		if _, err := runtime.DeliverText(context.Background(), dest, "catatan"); err != nil {
			t.Fatalf("deliver to %s: %v", dest, err)
		}
	}
	if len(writer.frames) != 2 {
		t.Fatalf("frames = %d, want one recipient copy per send and no own-device copy", len(writer.frames))
	}
}

// TestAppStateKeysSurviveARestart pins the vault: the phone shares app state
// sync keys once, and a restart that lost them cannot verify a single patch
// until the phone cooperates again. A plaintext file beside the process is not
// the vault, so the keys travel through it like every other secret.
func TestAppStateKeysSurviveARestart(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	vault := newTestVault(t)

	first, _ := newVaultBackedRuntime(t, "session-1", identity, vault)
	first.storeAppStateKeys(map[string][]byte{
		"aa": {0x01, 0x02},
		"bb": {0x03, 0x04},
	})

	second, _ := newVaultBackedRuntime(t, "session-1", identity, vault)
	second.appStateKeysMu.Lock()
	defer second.appStateKeysMu.Unlock()
	if len(second.appStateKeys) != 2 {
		t.Fatalf("restored keys = %d, want 2", len(second.appStateKeys))
	}
	if string(second.appStateKeys["aa"]) != string([]byte{0x01, 0x02}) {
		t.Fatalf("key aa = %x", second.appStateKeys["aa"])
	}
}

// TestDeliverMediaSendsAndCopies is the server's attachment send: encrypt,
// upload to a stubbed CDN, send under type="media", persist the ratchet, and
// mirror the same message to the phone.
func TestDeliverMediaSendsAndCopies(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	peer := "628555@s.whatsapp.net"
	phone := "266988689592415:35@lid"
	_, recipientSession, recipientState := peerConversation(t, identity)
	_, phoneSession, phoneState := peerConversation(t, identity)

	vault := newTestVault(t)
	seedPeerSession(t, vault, "session-1", peer, recipientSession)
	seedPeerSession(t, vault, "session-1", phone, phoneSession)

	var uploaded []byte
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploaded, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"url":"https://mmg.whatsapp.net/i","direct_path":"/v/t62/i"}`))
	}))
	defer cdn.Close()

	runtime, writer := newVaultBackedRuntime(t, "session-1", identity, vault)
	runtime.ownLID = "266988689592415:39@lid"
	runtime.mediaHTTP = cdn.Client()
	runtime.mediaConnFn = func(context.Context) (*mediaout.Connection, error) {
		return &mediaout.Connection{Auth: "AUTH", Host: strings.TrimPrefix(cdn.URL, "https://")}, nil
	}

	plaintext := append(append([]byte("\x89PNG\r\n\x1a\n"), []byte("IHDR....")...), []byte(" body")...)
	id, err := runtime.DeliverMedia(context.Background(), peer, "photo.png", "image/png", "pantai", plaintext)
	if err != nil {
		t.Fatalf("deliver media: %v", err)
	}
	if id == "" {
		t.Fatal("empty wire id")
	}
	if len(uploaded) == 0 || bytes.Contains(uploaded, plaintext) {
		t.Fatalf("uploaded bytes = %d, plaintext leaked=%v", len(uploaded), bytes.Contains(uploaded, plaintext))
	}
	if len(writer.frames) != 2 {
		t.Fatalf("frames = %d, want recipient copy and own-device copy", len(writer.frames))
	}

	codec := binary.NewCodec(nil)
	recipientNode, err := codec.Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatalf("decode recipient frame: %v", err)
	}
	if got := recipientNode.Attrs["type"]; got != "media" {
		t.Fatalf("recipient stanza type = %q, want media", got)
	}
	copyNode, err := codec.Decode(bytes.NewReader(writer.frames[1]))
	if err != nil {
		t.Fatalf("decode copy frame: %v", err)
	}
	if copyNode.Attrs["to"] != phone || copyNode.Attrs["id"] != recipientNode.Attrs["id"] {
		t.Fatalf("copy to=%q id=%q", copyNode.Attrs["to"], copyNode.Attrs["id"])
	}

	// The peer opens the recipient copy and finds the upload's location, the
	// caption, and digests that match what was uploaded.
	plain, err := recipientState.Decrypt(recipientNode.Children[0].Bytes, identity.Public, recipientSession.PeerIdentity)
	if err != nil {
		t.Fatalf("peer cannot open the media message: %v", err)
	}
	payload, err := stanza.DecodePayload(mustUnpad(t, plain))
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Kind != stanza.PayloadImage || payload.Media.Caption != "pantai" {
		t.Fatalf("payload = %#v / %#v", payload, payload.Media)
	}
	encSum := sha256Sum(uploaded)
	if payload.Media.DirectPath != "/v/t62/i" ||
		!bytes.Equal(payload.Media.FileEncSHA256, encSum[:]) {
		t.Fatalf("media = %#v", payload.Media)
	}

	// The phone opens the wrapped copy and sees the same image message.
	wrapped, err := phoneState.Decrypt(copyNode.Children[0].Bytes, identity.Public, phoneSession.PeerIdentity)
	if err != nil {
		t.Fatalf("phone cannot open the copy: %v", err)
	}
	copied, err := stanza.DecodePayload(mustUnpad(t, wrapped))
	if err != nil {
		t.Fatalf("decode copy payload: %v", err)
	}
	if copied.Destination != peer || copied.Kind != stanza.PayloadImage {
		t.Fatalf("copy payload = %#v", copied)
	}
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

func mustUnpad(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	out, err := stanza.UnpadMessage(plaintext, "2")
	if err != nil {
		t.Fatalf("unpad: %v", err)
	}
	return out
}

// TestSenderKeysSurviveARestart pins the group half of persistence: a chain
// the runtime stored must come back, or every group message after a restart
// is unreadable even though its key was distributed once.
func TestSenderKeysSurviveARestart(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	vault := newTestVault(t)
	group := "120363046767601853@g.us"
	sender := "200506840473775@lid"

	var key coremessaging.SenderKey
	key.ID = 123456
	key.Iteration = 3
	for i := range key.ChainKey {
		key.ChainKey[i] = byte(i + 1)
		key.SigningKey[i] = byte(0x80 + i)
	}

	first, _ := newVaultBackedRuntime(t, "session-1", identity, vault)
	if err := first.persistSenderKey(group, sender, &key); err != nil {
		t.Fatalf("persist: %v", err)
	}

	second, _ := newVaultBackedRuntime(t, "session-1", identity, vault)
	restored, ok := second.receiver.SenderKey(group, sender)
	if !ok {
		t.Fatal("sender key was not restored")
	}
	if restored.ID != key.ID || restored.Iteration != key.Iteration ||
		restored.ChainKey != key.ChainKey || restored.SigningKey != key.SigningKey {
		t.Fatalf("restored = %+v", restored)
	}
}
