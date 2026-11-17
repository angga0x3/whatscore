package messaging

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	"google.golang.org/protobuf/proto"
)

// The same reference vectors as protocol/signal's tests (libsignal v0.2.2):
// a chain at iteration 0, a message at iteration 5, and the signing key.
const (
	skChainKey   = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	skSigningPub = "05605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c"
	skMessage    = "3308c0c40710051a209b73ecedee6860cdf3930fb81f9a493cd18ebda6b7526d428d934a6fcde89765df1d7f22a0d7b3a6e2304d7542964a1f27144641e943dcba9c8d41b70d29288a61026c14e09dcc7deaea7e7d524c209e4047944f76e599fdb6552804fcab9708"
	skPlaintext  = "halo grup"
)

// skdmBytes builds the distribution message shaped like libsignal's
// serializer: version nibble, then {id=1, iteration=2, chainKey=3, signingKey=4}.
func skdmBytes(t *testing.T, id, iteration uint32) []byte {
	t.Helper()
	chain, err := hex.DecodeString(skChainKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(skSigningPub)
	if err != nil {
		t.Fatal(err)
	}
	out := []byte{0x33}
	out = append(out, 0x08)
	out = appendVarint(out, uint64(id))
	out = append(out, 0x10)
	out = appendVarint(out, uint64(iteration))
	out = append(out, 0x1a, byte(len(chain)))
	out = append(out, chain...)
	out = append(out, 0x22, byte(len(pub)))
	out = append(out, pub...)
	return out
}

func appendVarint(buf []byte, value uint64) []byte {
	for value >= 0x80 {
		buf = append(buf, byte(value)|0x80)
		value >>= 7
	}
	return append(buf, byte(value))
}

// TestReceiverDecryptsGroupSenderKey walks the live group shape: a 1:1 child
// carries the member's sender key distribution, a second child carries the
// group ciphertext, and together they produce a message event in the group
// chat with the member as sender.
func TestReceiverDecryptsGroupSenderKey(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	prekeys := newTestPreKeys(t, true)
	senderPair := keyPairFromSeed(t, []byte("group-member-seed"))
	group := "120363046767601853@g.us"
	participant := "200506840473775@lid"

	receiver, err := NewReceiver(bus, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	receiver.SetReceiverIdentity(prekeys.identity.Public)
	receiver.SetPreKeySource(prekeys)

	// Frame one: the sender key distribution inside a prekey message.
	init, err := signal.Initiate(senderPair, prekeys.bundle)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := signal.NewInitiator(init.Keys.RootKey, prekeys.bundle.SignedPreKey, init.Keys.ChainKey)
	if err != nil {
		t.Fatal(err)
	}
	distribution, err := proto.Marshal(&protobuf.Message{
		SenderKeyDistributionMessage: &protobuf.SenderKeyDistributionMessage{
			GroupID:                             proto.String(group),
			AxolotlSenderKeyDistributionMessage: skdmBytes(t, 123456, 0),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := alice.Encrypt(stanza.PadMessage(distribution), senderPair.Public, prekeys.identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := init.BuildPreKeyMessage(senderPair.Public, 1234, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	frame := groupEncryptedFrame(t, "G1", group, participant, wire, stanza.CarrierPKMsg)
	if err := receiver.HandleFrame(context.Background(), frame); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("distribution must not publish a message: %#v", ev)
	case <-time.After(100 * time.Millisecond):
	}
	key, ok := receiver.SenderKey(group, participant)
	if !ok {
		t.Fatal("sender key was not stored")
	}
	if key.ID != 123456 || key.Iteration != 0 {
		t.Fatalf("key = %+v", key)
	}

	// Frame two: the group ciphertext, signed with the distributed key.
	message, err := hex.DecodeString(skMessage)
	if err != nil {
		t.Fatal(err)
	}
	groupNode := &binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id": "G2", "from": group, "type": "text", "participant": participant,
		},
		Children: []binary.Node{{
			Tag: "enc", Attrs: binary.Attrs{"v": "2", "type": stanza.CarrierSKMsg}, Bytes: message,
		}},
	}
	if err := receiver.HandleFrame(context.Background(), encodeNode(t, groupNode)); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		if ev.Message == nil {
			t.Fatalf("event = %#v", ev)
		}
		if ev.Message.Text != skPlaintext {
			t.Fatalf("text = %q", ev.Message.Text)
		}
		if ev.Message.Chat != group {
			t.Fatalf("chat = %q, want the group", ev.Message.Chat)
		}
		if ev.Message.Sender != participant {
			t.Fatalf("sender = %q, want the member", ev.Message.Sender)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("group message was not published")
	}

	// The chain advanced past the message's iteration.
	key, ok = receiver.SenderKey(group, participant)
	if !ok || key.Iteration != 6 {
		t.Fatalf("advanced key = %+v", key)
	}
}

// TestGroupMessageWithoutSenderKeyIsDropped keeps the failure honest: a
// group ciphertext with no key produces nothing and does not create state.
func TestGroupMessageWithoutSenderKeyIsDropped(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	receiver, err := NewReceiver(bus, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	message, err := hex.DecodeString(skMessage)
	if err != nil {
		t.Fatal(err)
	}
	node := &binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id": "G3", "from": "120363046767601853@g.us", "type": "text",
			"participant": "200506840473775@lid",
		},
		Children: []binary.Node{{
			Tag: "enc", Attrs: binary.Attrs{"v": "2", "type": stanza.CarrierSKMsg}, Bytes: message,
		}},
	}
	if err := receiver.HandleFrame(context.Background(), encodeNode(t, node)); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("unexpected event: %#v", ev)
	case <-time.After(100 * time.Millisecond):
	}
	if entries := receiver.SenderKeyEntries(); len(entries) != 0 {
		t.Fatalf("sender keys = %#v", entries)
	}
}

// TestSenderKeyTamperIsRefused keeps the signature decision load-bearing: a
// modified group message must not reach the application.
func TestSenderKeyTamperIsRefused(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	receiver, err := NewReceiver(bus, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	group := "120363046767601853@g.us"
	participant := "200506840473775@lid"
	chain, _ := hex.DecodeString(skChainKey)
	pub, _ := hex.DecodeString(skSigningPub)
	var key SenderKey
	key.ID = 123456
	copy(key.ChainKey[:], chain)
	copy(key.SigningKey[:], pub[1:])
	if err := receiver.SetSenderKey(group, participant, &key); err != nil {
		t.Fatal(err)
	}

	message, err := hex.DecodeString(skMessage)
	if err != nil {
		t.Fatal(err)
	}
	message[len(message)-1] ^= 0x01 // signature byte
	node := &binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id": "G4", "from": group, "type": "text", "participant": participant,
		},
		Children: []binary.Node{{
			Tag: "enc", Attrs: binary.Attrs{"v": "2", "type": stanza.CarrierSKMsg}, Bytes: message,
		}},
	}
	if err := receiver.HandleFrame(context.Background(), encodeNode(t, node)); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("tampered message published: %#v", ev)
	case <-time.After(100 * time.Millisecond):
	}
	// The key must not have advanced on a refused message.
	stored, _ := receiver.SenderKey(group, participant)
	if stored.Iteration != 0 {
		t.Fatalf("key advanced on a refused message: %+v", stored)
	}
}

// TestSenderKeyEntriesAndObserver pins the persistence hooks: entries are
// sorted and the observer fires on install and on advance.
func TestSenderKeyEntriesAndObserver(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	receiver, err := NewReceiver(bus, "s")
	if err != nil {
		t.Fatal(err)
	}
	var observed []string
	receiver.SetSenderKeyObserver(func(group, sender string, key *SenderKey) {
		observed = append(observed, group+"|"+sender+"|"+itoa(key.Iteration))
	})
	for _, entry := range []struct{ group, sender string }{
		{"120363046767601853@g.us", "200506840473775@lid"},
		{"120363046767601853@g.us", "99999999999999@lid"},
		{"120363000000000000@g.us", "200506840473775@lid"},
	} {
		if err := receiver.SetSenderKey(entry.group, entry.sender, &SenderKey{ID: 1}); err != nil {
			t.Fatal(err)
		}
		receiver.observeKey(entry.group, entry.sender)
	}
	entries := receiver.SenderKeyEntries()
	if len(entries) != 3 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Group != "120363000000000000@g.us" {
		t.Fatalf("entries not sorted: %#v", entries)
	}
	if len(observed) != 3 {
		t.Fatalf("observer calls = %v", observed)
	}
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	pos := len(buf)
	for v > 0 {
		pos--
		buf[pos] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[pos:])
}
