package messaging

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/core/events"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// encryptedFrame builds the inbound wire shape: the service stamps "from"
// (the sender, who owns the session) and omits "to" — the PF-087 queue replay
// carried no "to" at all.
func encryptedFrame(t *testing.T, id, from string, ciphertext []byte, carrier string, timestamp int64) []byte {
	t.Helper()
	node, err := stanza.BuildEncryptedText(stanza.EncryptedText{
		ID: id, To: stanza.JID{User: mustUser(from), Server: mustServer(from)},
		Carrier: carrier, Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	delete(node.Attrs, "to")
	node.Attrs["from"] = from
	if timestamp != 0 {
		node.Attrs["t"] = strconv.FormatInt(timestamp, 10)
	}
	return encodeNode(t, node)
}

func mustUser(jid string) string {
	return jid[:bytes.IndexByte([]byte(jid), '@')]
}

func mustServer(jid string) string {
	return jid[bytes.IndexByte([]byte(jid), '@')+1:]
}

func newDecryptFixture(t *testing.T) (alice, bob *signal.State, aliceID, bobID [32]byte) {
	t.Helper()
	return newPeerPair(t)
}

func TestReceiverDecryptsEncryptedMessage(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	alice, bob, aliceID, bobID := newDecryptFixture(t)
	peer := "628123@s.whatsapp.net"

	receiver, err := NewReceiver(bus, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	receiver.SetReceiverIdentity(bobID)
	if err := receiver.SetReceiverPeer(peer, &PeerSession{PeerIdentity: aliceID, State: bob}); err != nil {
		t.Fatal(err)
	}

	payload, err := stanza.EncodeTextMessage("terenkripsi")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := alice.Encrypt(stanza.PadMessage(payload), aliceID, bobID)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.HandleFrame(context.Background(), encryptedFrame(t, "E1", peer, ciphertext, stanza.CarrierMsg, 0)); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-sub.C:
		if ev.Type != events.TypeMessage || ev.Message == nil {
			t.Fatalf("event = %#v", ev)
		}
		if ev.Message.ID != "E1" || ev.Message.Text != "terenkripsi" ||
			ev.Message.Direction != events.DirectionIncoming {
			t.Fatalf("message = %#v", ev.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event published")
	}
	nextPayload, err := stanza.EncodeTextMessage("next")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Encrypt(nextPayload, bobID, aliceID); err != nil {
		t.Fatalf("ratchet not advanced: %v", err)
	}
}

func TestReceiverEncryptedDrops(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	alice, bob, aliceID, bobID := newDecryptFixture(t)
	peer := "628123@s.whatsapp.net"
	receiver, _ := NewReceiver(bus, "s")
	receiver.SetReceiverIdentity(bobID)
	if err := receiver.SetReceiverPeer(peer, &PeerSession{PeerIdentity: aliceID, State: bob}); err != nil {
		t.Fatal(err)
	}

	secretPayload, err := stanza.EncodeTextMessage("secret")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := alice.Encrypt(stanza.PadMessage(secretPayload), aliceID, bobID)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0x01

	frames := [][]byte{
		encryptedFrame(t, "E2", "unknown@s.whatsapp.net", ciphertext, stanza.CarrierMsg, 0),
		encryptedFrame(t, "E3", peer, tampered, stanza.CarrierMsg, 0),
		encryptedFrame(t, "E4", peer, ciphertext, stanza.CarrierPKMsg, 0),
	}
	for _, frame := range frames {
		if err := receiver.HandleFrame(context.Background(), frame); err != nil {
			t.Fatalf("HandleFrame: %v", err)
		}
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("unexpected event: %#v", ev)
	default:
	}

	// A failed decrypt must not have advanced the live ratchet: the original
	// ciphertext still decrypts.
	if err := receiver.HandleFrame(context.Background(), encryptedFrame(t, "E5", peer, ciphertext, stanza.CarrierMsg, 0)); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		if ev.Message == nil || ev.Message.Text != "secret" {
			t.Fatalf("message = %#v", ev.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid message was not published after earlier failures")
	}
}

func TestReceiverEncryptedValidation(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	receiver, _ := NewReceiver(bus, "s")
	if err := receiver.SetReceiverPeer("", &PeerSession{}); err == nil {
		t.Fatal("empty peer must fail")
	}
	if err := receiver.SetReceiverPeer("p", nil); err == nil {
		t.Fatal("nil session must fail")
	}
	if err := receiver.SetReceiverPeer("p", &PeerSession{}); err == nil {
		t.Fatal("nil state must fail")
	}
}

// TestReceiverDecryptsMediaOnEstablishedSession pins the msg-carrier half of
// the media path: after the first message the ratchet continues with msg
// carriers, and a sticker arriving that way used to decrypt and then vanish
// because only text was decoded on that path.
func TestReceiverDecryptsMediaOnEstablishedSession(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	alice, bob, aliceID, bobID := newDecryptFixture(t)
	peer := "628123@s.whatsapp.net"
	receiver, err := NewReceiver(bus, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	receiver.SetReceiverIdentity(bobID)
	if err := receiver.SetReceiverPeer(peer, &PeerSession{PeerIdentity: aliceID, State: bob}); err != nil {
		t.Fatal(err)
	}

	sticker, err := proto.Marshal(&protobuf.Message{
		StickerMessage: &protobuf.StickerMessage{
			Url:           proto.String("https://mmg.whatsapp.net/x"),
			DirectPath:    proto.String("/v/t62/x"),
			Mimetype:      proto.String("image/webp"),
			FileLength:    proto.Uint64(51_000),
			MediaKey:      bytes.Repeat([]byte{0x07}, 32),
			FileSHA256:    bytes.Repeat([]byte{0x08}, 32),
			FileEncSHA256: bytes.Repeat([]byte{0x09}, 32),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := alice.Encrypt(stanza.PadMessage(sticker), aliceID, bobID)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.HandleFrame(context.Background(), encryptedFrame(t, "M1", peer, ciphertext, stanza.CarrierMsg, 0)); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-sub.C:
		if ev.Message == nil || ev.Message.Media == nil {
			t.Fatalf("message = %#v", ev.Message)
		}
		if ev.Message.Media.Kind != string(stanza.PayloadSticker) ||
			ev.Message.Media.DirectPath != "/v/t62/x" || ev.Message.Media.FileLength != 51_000 {
			t.Fatalf("media = %#v", ev.Message.Media)
		}
		if ev.Message.Chat != peer || ev.Message.Direction != events.DirectionIncoming {
			t.Fatalf("chat = %q direction = %q", ev.Message.Chat, ev.Message.Direction)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event published")
	}
}

// TestReceiverPublishesOwnDeviceCopyInItsDestinationChat pins the device-sent
// copy: another device of this account sent the message, so it belongs to the
// chat it names, as outgoing — not to a chat with the sending device.
func TestReceiverPublishesOwnDeviceCopyInItsDestinationChat(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	alice, bob, aliceID, bobID := newDecryptFixture(t)
	phone := "266988689592415:39@lid"
	destination := "628555@s.whatsapp.net"
	receiver, err := NewReceiver(bus, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	receiver.SetReceiverIdentity(bobID)
	if err := receiver.SetReceiverPeer(phone, &PeerSession{PeerIdentity: aliceID, State: bob}); err != nil {
		t.Fatal(err)
	}

	wrapped, err := stanza.EncodeDeviceSentMessage(destination, "dari hp")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := alice.Encrypt(stanza.PadMessage(wrapped), aliceID, bobID)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.HandleFrame(context.Background(), encryptedFrame(t, "D1", phone, ciphertext, stanza.CarrierMsg, 0)); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-sub.C:
		if ev.Message == nil {
			t.Fatalf("event = %#v", ev)
		}
		if ev.Message.Text != "dari hp" {
			t.Fatalf("text = %q", ev.Message.Text)
		}
		if ev.Message.Chat != destination {
			t.Fatalf("chat = %q, want %q", ev.Message.Chat, destination)
		}
		if ev.Message.Direction != events.DirectionOutgoing {
			t.Fatalf("direction = %q, want outgoing", ev.Message.Direction)
		}
		if ev.Message.Sender != phone {
			t.Fatalf("sender = %q, want the sending device", ev.Message.Sender)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event published")
	}
}
