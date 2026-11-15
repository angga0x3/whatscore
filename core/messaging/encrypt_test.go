package messaging

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// newPeerPair establishes both sides of a Signal conversation: the initiator
// derives the first sender chain, and the responder starts from the X3DH
// chain, so alice can encrypt and bob can decrypt.
func newPeerPair(tb testing.TB) (alice, bob *signal.State, aliceID, bobID [32]byte) {
	tb.Helper()
	aliceID, bobID = [32]byte{0x11}, [32]byte{0x22}
	root := signal.RootKey{0x33}
	chain := signal.ChainKey{0x44}

	bobRatchet, err := signal.GenerateKeyPair()
	if err != nil {
		tb.Fatal(err)
	}
	bob = signal.NewResponder(root, bobRatchet, chain)

	// The initiator's receiver chain is the X3DH chain on the responder's
	// ratchet key; NewInitiator derives the sender chain from it.
	alice, err = signal.NewInitiator(root, bobRatchet.Public, chain)
	if err != nil {
		tb.Fatal(err)
	}
	return alice, bob, aliceID, bobID
}

func TestSendEncryptedText(t *testing.T) {
	writer := &fakeWriter{}
	sender, err := NewSender(writer)
	if err != nil {
		t.Fatal(err)
	}
	alice, bob, aliceID, bobID := newPeerPair(t)
	sender.SetIdentity(aliceID)
	peer := "628123@s.whatsapp.net"
	if err := sender.SetPeer(peer, &PeerSession{PeerIdentity: bobID, State: alice}); err != nil {
		t.Fatal(err)
	}

	id, session, err := sender.SendEncryptedText(context.Background(), peer, "rahasia")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if session == nil || id == "" {
		t.Fatalf("id = %q", id)
	}
	if len(writer.frames) != 1 {
		t.Fatalf("writes = %d", len(writer.frames))
	}

	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := stanza.ParseEncryptedText(node)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted.ID != id || encrypted.Carrier != stanza.CarrierMsg || encrypted.To.String() != peer {
		t.Fatalf("envelope = %#v", encrypted)
	}
	plaintext, err := bob.Decrypt(encrypted.Ciphertext, aliceID, bobID)
	if err != nil {
		t.Fatalf("peer decrypt: %v", err)
	}
	if string(plaintext) != "rahasia" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestSendEncryptedTextErrors(t *testing.T) {
	sender, _ := NewSender(&fakeWriter{})
	ctx := context.Background()

	if _, _, err := sender.SendEncryptedText(ctx, "1@s.whatsapp.net", "x"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession, got %v", err)
	}
	if err := sender.SetPeer("", &PeerSession{}); err == nil {
		t.Fatal("empty peer must fail")
	}
	if err := sender.SetPeer("p", nil); err == nil {
		t.Fatal("nil session must fail")
	}
	if err := sender.SetPeer("p", &PeerSession{}); err == nil {
		t.Fatal("nil state must fail")
	}
	for _, to := range []string{"", "s.whatsapp.net", "bad space@s.whatsapp.net"} {
		if _, _, err := sender.SendEncryptedText(ctx, to, "x"); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("to %q: %v", to, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := sender.SendEncryptedText(canceled, "1@s.whatsapp.net", "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}
