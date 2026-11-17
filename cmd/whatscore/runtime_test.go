package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/angga0x3/whatscore/core/events"
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
	runtime, err := newSessionRuntime(id, binary.NewCodec(nil), logger, identity, nil, 4242, pairedAccount{}, nil, bus, "", signals)
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

	vault := newTestVault(t)
	seedPeerSession(t, vault, "session-1", ownLID, selfSession)

	runtime, writer := newVaultBackedRuntime(t, "session-1", identity, vault)
	runtime.ownLID = ownLID
	if _, err := runtime.DeliverText(context.Background(), ownLID, "catatan"); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(writer.frames) != 1 {
		t.Fatalf("frames = %d, want the recipient copy only", len(writer.frames))
	}
}
