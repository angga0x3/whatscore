package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/angga0x3/whatscore/core/events"
	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// TestInboundPreKeyMessageBecomesText is the receive path end to end: a peer
// fetches our published bundle, encrypts to it, and the receiver turns the
// envelope into the original text.
//
// It exists because the live backlog could not be opened — the pairing run had
// thrown away the signed prekey's private half. This proves the pipeline itself
// is sound and isolates the loss to the key, not the code.
func TestInboundPreKeyMessageBecomesText(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	signed, err := signal.GenerateSignedPreKey(1, signal.XEdDSASigner{Private: identity.Private})
	if err != nil {
		t.Fatalf("signed prekey: %v", err)
	}
	oneTime, err := signal.GeneratePreKey(1)
	if err != nil {
		t.Fatalf("one-time prekey: %v", err)
	}

	source := &preKeyStore{
		identity: identity,
		signed:   signed,
		oneTime:  map[uint32]signal.PreKey{oneTime.ID: oneTime},
	}

	// The peer side: exactly what a sender does with the bundle we published.
	peer, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("peer: %v", err)
	}
	bundle := signal.PreKeyBundle{
		IdentityKey:           identity.Public,
		SignedPreKeyID:        signed.ID,
		SignedPreKey:          signed.Pair.Public,
		SignedPreKeySignature: signed.Signature,
		OneTimePreKeyID:       oneTime.ID,
		OneTimePreKey:         &oneTime.Pair.Public,
	}
	initiator, err := signal.Initiate(peer, bundle)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	state, err := signal.NewInitiator(initiator.Keys.RootKey, bundle.SignedPreKey, initiator.Keys.ChainKey)
	if err != nil {
		t.Fatalf("initiator state: %v", err)
	}

	payload, err := encodeText("halo dari peer")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := state.Encrypt(payload, peer.Public, identity.Public)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	wire, err := initiator.BuildPreKeyMessage(peer.Public, 4242, ciphertext)
	if err != nil {
		t.Fatalf("prekey message: %v", err)
	}

	// The receiver side, wired the way runListen wires it.
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	receiver, err := coremessaging.NewReceiver(bus, "probe")
	if err != nil {
		t.Fatal(err)
	}
	receiver.SetReceiverIdentity(identity.Public)
	receiver.SetPreKeySource(source)

	node := preKeyNode(wire)
	if err := receiver.HandleFrame(context.Background(), node); err != nil {
		t.Fatalf("handle frame: %v", err)
	}

	select {
	case ev := <-sub.C:
		if ev.Message == nil {
			t.Fatal("no message in event")
		}
		if ev.Message.Text != "halo dari peer" {
			t.Fatalf("text = %q", ev.Message.Text)
		}
	default:
		t.Fatal("receiver published nothing")
	}
}

// TestKeyFileRoundTripsSignedPreKey pins that the private half survives a save
// and load. That is the whole point of the file.
func TestKeyFileRoundTripsSignedPreKey(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	signed, err := signal.GenerateSignedPreKey(7, signal.XEdDSASigner{Private: identity.Private})
	if err != nil {
		t.Fatalf("signed prekey: %v", err)
	}

	path := t.TempDir() + "/keys.json"
	file := &keyFile{NextOneTimeID: 1}
	file.addSigned(signed)
	if err := file.save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := loadKeyFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	back, err := loaded.signedPreKey()
	if err != nil {
		t.Fatalf("signedPreKey: %v", err)
	}
	if back.ID != signed.ID {
		t.Fatalf("id = %d, want %d", back.ID, signed.ID)
	}
	if back.Pair.Private != signed.Pair.Private {
		t.Fatal("private key did not survive the round trip")
	}
	if err := back.Verify(identity.Public); err != nil {
		t.Fatalf("reloaded signature does not verify: %v", err)
	}
}

// TestSeedFromRecordAdoptsThePairingKey pins the fix: the key the registration
// payload signed must become the key the receiver uses.
func TestSeedFromRecordAdoptsThePairingKey(t *testing.T) {
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	signed, err := signal.GenerateSignedPreKey(1, signal.XEdDSASigner{Private: identity.Private})
	if err != nil {
		t.Fatalf("signed prekey: %v", err)
	}

	record := &credentialRecord{
		SignedPreKey: signedPreKeyRec{
			ID:        signed.ID,
			Private:   append([]byte(nil), signed.Pair.Private[:]...),
			Public:    append([]byte(nil), signed.Pair.Public[:]...),
			Signature: append([]byte(nil), signed.Signature...),
		},
	}

	file := &keyFile{NextOneTimeID: 1}
	file.seedFromRecord(record)
	back, err := file.signedPreKey()
	if err != nil {
		t.Fatalf("signedPreKey: %v", err)
	}
	if back.Pair.Private != signed.Pair.Private {
		t.Fatal("pairing key was not adopted")
	}
	if file.NextSignedID != 2 {
		t.Fatalf("next signed id = %d, want 2", file.NextSignedID)
	}
}

// TestSeedFromRecordIgnoresAnOldRecord keeps a credentials file written before
// the key was stored from being adopted as if it were valid.
func TestSeedFromRecordIgnoresAnOldRecord(t *testing.T) {
	file := &keyFile{NextOneTimeID: 1}
	file.seedFromRecord(&credentialRecord{})
	if len(file.Signed.Signature) != 0 {
		t.Fatal("adopted an empty signed prekey")
	}
}

// encodeText is the sender-side payload the receive tests feed in.
func encodeText(text string) ([]byte, error) {
	return stanza.EncodeTextMessage(text)
}

// captureConn records every frame written to it, so a test can assert on the
// exact bytes the probe put on the wire.
type captureConn struct {
	written chan []byte
}

func newCaptureConn() *captureConn { return &captureConn{written: make(chan []byte, 8)} }

func (c *captureConn) ReadFrame(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *captureConn) WriteFrame(ctx context.Context, frame []byte) error {
	select {
	case c.written <- append([]byte(nil), frame...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *captureConn) Close() error { return nil }

func (c *captureConn) CipherSuiteName() string { return "test" }

// TestOfflineBatchRequestShape pins the node that un-freezes the server's
// offline queue. The shape is the whole fix for PF-087: an <ib> wrapper around
// one <offline_batch> naming a bounded count. A client that sends anything else
// — or nothing — gets a queue the server announces but never delivers.
func TestOfflineBatchRequestShape(t *testing.T) {
	conn := newCaptureConn()
	oq := newOfflineQueue(conn, wabinary.NewCodec(nil))

	preview := &wabinary.Node{Tag: "ib", Children: []wabinary.Node{
		{Tag: "offline_preview", Attrs: wabinary.Attrs{
			"count": "107", "message": "26", "receipt": "37", "notification": "26",
		}},
	}}
	oq.handle(context.Background(), preview)

	select {
	case frame := <-conn.written:
		node, err := wabinary.NewCodec(nil).Decode(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("decode written frame: %v", err)
		}
		if node.Tag != "ib" {
			t.Fatalf("outer tag = %q", node.Tag)
		}
		batch := child(node, "offline_batch")
		if batch == nil {
			t.Fatalf("no <offline_batch> child: %s", attrSummary(node))
		}
		if got := batch.Attrs["count"]; got != "100" {
			t.Fatalf("count = %q, want 100 (a bounded slice, not the queue size)", got)
		}
	default:
		t.Fatal("an offline_preview announcement earned no batch request on the wire")
	}
}

// TestOfflineQueueSurvivesRepeatedAnnouncements covers the session lifecycle:
// the server may re-announce or re-drain mid-session, and a second drain
// marker must not panic on an already-closed channel.
func TestOfflineQueueSurvivesRepeatedAnnouncements(t *testing.T) {
	conn := newCaptureConn()
	oq := newOfflineQueue(conn, wabinary.NewCodec(nil))

	preview := func() *wabinary.Node {
		return &wabinary.Node{Tag: "ib", Children: []wabinary.Node{{Tag: "offline_preview"}}}
	}
	drain := func() *wabinary.Node {
		return &wabinary.Node{Tag: "ib", Children: []wabinary.Node{{Tag: "offline"}}}
	}
	ctx := context.Background()

	if oq.announcedAndUndrained() {
		t.Fatal("nothing announced yet")
	}

	oq.handle(ctx, preview())
	if !oq.announcedAndUndrained() {
		t.Fatal("announced queue should be pending a drain marker")
	}

	oq.handle(ctx, drain())
	select {
	case <-oq.drained:
	default:
		t.Fatal("drain marker did not release the listener")
	}
	if oq.announcedAndUndrained() {
		t.Fatal("queue still marked undrained after the marker")
	}

	// A re-announcement after the drain is a fresh queue with its own marker.
	// None of this may panic.
	oq.handle(ctx, preview())
	oq.handle(ctx, drain())
	oq.handle(ctx, drain())
}

// TestOfflineBatchRequestIsSentRepeatedly pins that a second announcement gets
// a second batch request: the first batch may not cover the queue, and the
// reference clients keep asking until the marker arrives.
func TestOfflineBatchRequestIsSentRepeatedly(t *testing.T) {
	conn := newCaptureConn()
	oq := newOfflineQueue(conn, wabinary.NewCodec(nil))

	preview := &wabinary.Node{Tag: "ib", Children: []wabinary.Node{{Tag: "offline_preview"}}}
	oq.handle(context.Background(), preview)
	<-conn.written
	oq.handle(context.Background(), preview)
	select {
	case <-conn.written:
	default:
		t.Fatal("a re-announced queue earned no second batch request")
	}
}

// preKeyNode builds the raw frame a peer's prekey message arrives in, matching
// the live shape: <message id to type="text"><enc v="2" type="pkmsg">wire</enc>.
func preKeyNode(wire []byte) []byte {
	node := &wabinary.Node{
		Tag: "message",
		Attrs: wabinary.Attrs{
			"id": "TEST1", "to": "100000000000000:1@s.whatsapp.net", "type": "text",
		},
		Children: []wabinary.Node{{
			Tag:   "enc",
			Attrs: wabinary.Attrs{"v": "2", "type": "pkmsg"},
			Bytes: wire,
		}},
	}
	frame, err := wabinary.NewCodec(nil).Encode(node)
	if err != nil {
		panic(err)
	}
	return frame
}
