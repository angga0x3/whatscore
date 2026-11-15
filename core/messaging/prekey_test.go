package messaging

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"

	"golang.org/x/crypto/curve25519"
)

// testPreKeys is an in-memory PreKeySource for bootstrap tests.
type testPreKeys struct {
	identity   signal.KeyPair
	signed     *signal.SignedPreKey
	oneTime    *signal.PreKey
	bundle     signal.PreKeyBundle
	signingKey ed25519.PrivateKey
}

func newTestPreKeys(tb testing.TB, withOneTime bool) *testPreKeys {
	tb.Helper()
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	identity := keyPairFromSeed(tb, signingKey.Seed())
	signedPair := keyPairFromSeed(tb, []byte("signed-prekey-seed"))
	// Sign the way production does: XEdDSA over the identity scalar (PF-067).
	signature, signErr := signal.XEdDSASigner{Private: identity.Private}.SignPreKey(signedPair.Public)
	if signErr != nil {
		tb.Fatalf("sign prekey: %v", signErr)
	}
	signed := &signal.SignedPreKey{ID: 7, Pair: signedPair, Signature: signature}
	fixture := &testPreKeys{identity: identity, signed: signed, signingKey: signingKey}
	fixture.bundle = signal.PreKeyBundle{
		IdentityKey:           identity.Public,
		SignedPreKeyID:        signed.ID,
		SignedPreKey:          signedPair.Public,
		SignedPreKeySignature: signed.Signature,
	}
	if withOneTime {
		oneTimePair := keyPairFromSeed(tb, []byte("one-time-prekey-seed"))
		fixture.oneTime = &signal.PreKey{ID: 9, Pair: oneTimePair}
		fixture.bundle.OneTimePreKeyID = 9
		fixture.bundle.OneTimePreKey = &oneTimePair.Public
	}
	return fixture
}

func (p *testPreKeys) Identity() signal.KeyPair { return p.identity }

func (p *testPreKeys) SignedPreKey(id uint32) (*signal.SignedPreKey, error) {
	if p.signed == nil || p.signed.ID != id {
		return nil, ErrNoPreKey
	}
	return p.signed, nil
}

func (p *testPreKeys) OneTimePreKey(id uint32) (*signal.PreKey, error) {
	if p.oneTime == nil || p.oneTime.ID != id {
		return nil, ErrNoPreKey
	}
	return p.oneTime, nil
}

func keyPairFromSeed(tb testing.TB, seed []byte) signal.KeyPair {
	tb.Helper()
	digest := sha512.Sum512(seed)
	var pair signal.KeyPair
	copy(pair.Private[:], digest[:32])
	pair.Private[0] &= 248
	pair.Private[31] &= 127
	pair.Private[31] |= 64
	pub, err := curve25519.X25519(pair.Private[:], curve25519.Basepoint)
	if err != nil {
		tb.Fatal(err)
	}
	copy(pair.Public[:], pub)
	return pair
}

func TestReceiverBootstrapsPreKeyMessage(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	prekeys := newTestPreKeys(t, true)
	senderPair := keyPairFromSeed(t, []byte("sender-identity-seed"))
	peer := "628123@s.whatsapp.net"

	init, err := signal.Initiate(senderPair, prekeys.bundle)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := signal.NewInitiator(init.Keys.RootKey, prekeys.bundle.SignedPreKey, init.Keys.ChainKey)
	if err != nil {
		t.Fatal(err)
	}
	first, err := alice.Encrypt([]byte("pesan pertama"), senderPair.Public, prekeys.identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := init.BuildPreKeyMessage(senderPair.Public, 1234, first)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewReceiver(bus, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	receiver.SetReceiverIdentity(prekeys.identity.Public)
	receiver.SetPreKeySource(prekeys)
	if err := receiver.HandleFrame(context.Background(), encryptedFrame(t, "PK1", peer, wire, stanza.CarrierPKMsg, 0)); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-sub.C:
		if ev.Message == nil || ev.Message.Text != "pesan pertama" || ev.Message.ID != "PK1" {
			t.Fatalf("message = %#v", ev.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event published")
	}

	// The bootstrapped session must be usable for the next message.
	second, err := alice.Encrypt([]byte("kedua"), senderPair.Public, prekeys.identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.HandleFrame(context.Background(), encryptedFrame(t, "PK2", peer, second, stanza.CarrierMsg, 0)); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		if ev.Message == nil || ev.Message.Text != "kedua" {
			t.Fatalf("message = %#v", ev.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follow-up message was not published")
	}
}

func TestReceiverPreKeyDrops(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	prekeys := newTestPreKeys(t, false)
	senderPair := keyPairFromSeed(t, []byte("sender-identity-seed"))
	peer := "628123@s.whatsapp.net"
	init, err := signal.Initiate(senderPair, prekeys.bundle)
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := signal.NewInitiator(init.Keys.RootKey, prekeys.bundle.SignedPreKey, init.Keys.ChainKey)
	first, _ := alice.Encrypt([]byte("x"), senderPair.Public, prekeys.identity.Public)
	wire, err := init.BuildPreKeyMessage(senderPair.Public, 1, first)
	if err != nil {
		t.Fatal(err)
	}

	receiver, _ := NewReceiver(bus, "s")
	receiver.SetReceiverIdentity(prekeys.identity.Public)
	// No prekey source installed yet.
	if err := receiver.HandleFrame(context.Background(), encryptedFrame(t, "PK3", peer, wire, stanza.CarrierPKMsg, 0)); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("unexpected event: %#v", ev)
	default:
	}

	// Unknown prekey ids are rejected the same way.
	receiver.SetPreKeySource(&testPreKeys{})
	if err := receiver.HandleFrame(context.Background(), encryptedFrame(t, "PK4", peer, wire, stanza.CarrierPKMsg, 0)); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("unexpected event: %#v", ev)
	default:
	}

	// Malformed carrier content is dropped, not fatal.
	if err := receiver.HandleFrame(context.Background(), encryptedFrame(t, "PK5", peer, []byte("not a prekey message"), stanza.CarrierPKMsg, 0)); err != nil {
		t.Fatal(err)
	}
}

func TestReceiverPreKeyRequiresSource(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	receiver, _ := NewReceiver(bus, "s")
	if _, _, err := receiver.bootstrapPeer(context.Background(), &stanza.EncryptedText{}, nil, stanza.JID{}); !errors.Is(err, ErrNoPreKey) {
		t.Fatalf("want ErrNoPreKey, got %v", err)
	}
}
