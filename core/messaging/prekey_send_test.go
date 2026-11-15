package messaging

import (
	"bytes"
	"context"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

type fixedBundles struct {
	bundle *signal.PreKeyBundle
	peer   string
	err    error
}

func (f *fixedBundles) PreKeyBundle(_ context.Context, peer string) (*signal.PreKeyBundle, error) {
	if f.err != nil {
		return nil, f.err
	}
	if peer != f.peer {
		return nil, ErrNoPreKey
	}
	return f.bundle, nil
}

func TestSendPreKeyText(t *testing.T) {
	prekeys := newTestPreKeys(t, true)
	senderPair := keyPairFromSeed(t, []byte("sender-identity-seed"))
	writer := &fakeWriter{}
	sender, err := NewSender(writer)
	if err != nil {
		t.Fatal(err)
	}
	sender.SetIdentityPair(senderPair)
	peer := "628123@s.whatsapp.net"
	sender.SetPreKeyBundleSource(&fixedBundles{bundle: &prekeys.bundle, peer: peer})

	id, session, err := sender.SendPreKeyText(context.Background(), peer, "pertama", 1234)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if id == "" || session == nil {
		t.Fatalf("id = %q", id)
	}
	if len(writer.frames) != 1 {
		t.Fatalf("writes = %d", len(writer.frames))
	}

	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatal(err)
	}
	// ParseEncryptedText reads the inbound shape, which stamps "from"; the
	// wire here is outbound, so the round trip adds a sender the parser needs.
	node.Attrs["from"] = "100000000000000@s.whatsapp.net"
	envelope, err := stanza.ParseEncryptedText(node)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Carrier != stanza.CarrierPKMsg || envelope.ID != id {
		t.Fatalf("envelope = %#v", envelope)
	}

	// The peer side must accept the prekey message and read the text.
	state, plaintext, err := signal.AcceptPreKeyMessage(envelope.Ciphertext,
		prekeys.identity, *prekeys.signed, prekeys.oneTime)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	// Strip the padding the compliant sender added before parsing.
	plaintext, err = stanza.UnpadMessage(plaintext, "2")
	if err != nil {
		t.Fatalf("unpad: %v", err)
	}
	// The decrypted bytes are a protobuf Message, so compare the text it
	// carries rather than the wire bytes.
	gotText, err := stanza.DecodeTextMessage(plaintext)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if gotText != "pertama" {
		t.Fatalf("text = %q", gotText)
	}

	// The sender can continue with a msg carrier using the new session.
	second, _, err := sender.SendEncryptedText(context.Background(), peer, "kedua")
	if err != nil {
		t.Fatalf("follow-up: %v", err)
	}
	if second == "" {
		t.Fatal("empty follow-up id")
	}
	node, err = binary.NewCodec(nil).Decode(bytes.NewReader(writer.frames[1]))
	if err != nil {
		t.Fatal(err)
	}
	// Outbound wire parsed with the inbound-shape parser: stamp "from".
	node.Attrs["from"] = "100000000000000@s.whatsapp.net"
	secondEnvelope, err := stanza.ParseEncryptedText(node)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err = state.Decrypt(secondEnvelope.Ciphertext, senderPair.Public, prekeys.identity.Public)
	if err != nil {
		t.Fatalf("decrypt follow-up: %v", err)
	}
	plaintext, err = stanza.UnpadMessage(plaintext, "2")
	if err != nil {
		t.Fatalf("unpad follow-up: %v", err)
	}
	text, err := stanza.DecodeTextMessage(plaintext)
	if err != nil {
		t.Fatalf("decode follow-up: %v", err)
	}
	if text != "kedua" {
		t.Fatalf("follow-up plaintext = %q", text)
	}
}

func TestSendPreKeyTextErrors(t *testing.T) {
	sender, _ := NewSender(&fakeWriter{})
	ctx := context.Background()
	peer := "1@s.whatsapp.net"

	if _, _, err := sender.SendPreKeyText(ctx, peer, "x", 1); err != ErrNoSession {
		t.Fatalf("no source: %v", err)
	}
	sender.SetPreKeyBundleSource(&fixedBundles{bundle: &signal.PreKeyBundle{}, peer: peer})
	if _, _, err := sender.SendPreKeyText(ctx, peer, "x", 1); err == nil {
		t.Fatal("missing identity pair must fail")
	}

	senderPair := keyPairFromSeed(t, []byte("sender-identity-seed"))
	sender.SetIdentityPair(senderPair)
	if _, _, err := sender.SendPreKeyText(ctx, peer, "x", 1); err == nil {
		t.Fatal("invalid bundle must fail")
	}
	if _, _, err := sender.SendPreKeyText(ctx, "bad space@s.whatsapp.net", "x", 1); err == nil {
		t.Fatal("bad peer must fail")
	}
	sender.SetPreKeyBundleSource(&fixedBundles{err: ErrNoPreKey, peer: peer})
	if _, _, err := sender.SendPreKeyText(ctx, peer, "x", 1); err == nil {
		t.Fatal("source error must propagate")
	}
}
