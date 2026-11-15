package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/protocol/media"

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
	ciphertext, err := state.Encrypt(stanza.PadMessage(payload), peer.Public, identity.Public)
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

// feedConn yields queued frames to the dispatcher's read loop, then blocks.
type feedConn struct {
	inbox chan []byte
}

func (c *feedConn) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case f := <-c.inbox:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *feedConn) WriteFrame(ctx context.Context, frame []byte) error { return nil }

func (c *feedConn) Close() error { return nil }

func (c *feedConn) CipherSuiteName() string { return "test" }

// routingDict builds a token table that knows the offline announcement's shape
// but not the counter values: exactly the live state that broke PF-087, where
// the counts ride dictionary slots the table has never observed.
func routingDict() *wabinary.Dictionary {
	d := wabinary.NewDictionary()
	_ = d.SetSingle(1, "ib")
	_ = d.SetSingle(2, "message")
	_ = d.SetDouble(0, 1, "offline_preview")
	_ = d.SetDouble(0, 2, "count")
	_ = d.SetDouble(0, 3, "known")
	return d
}

// runDispatcherOnce feeds one frame through a dispatcher wired like runListen's
// and reports what onNode saw, or nil if nothing fired within the deadline.
func runDispatcherOnce(t *testing.T, frame []byte, strict, hole *wabinary.Dictionary) *wabinary.Node {
	t.Helper()
	t.Chdir(t.TempDir()) // dumpFrame writes relative to undecoded/
	conn := &feedConn{inbox: make(chan []byte, 1)}
	conn.inbox <- frame
	d := newDispatcher(conn, wabinary.NewCodec(strict))
	d.holeCodec = wabinary.NewCodec(hole)

	fired := make(chan *wabinary.Node, 1)
	d.onNode = func(ctx context.Context, n *wabinary.Node) {
		select {
		case fired <- n:
		default:
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		d.run(ctx)
	}()

	var seen *wabinary.Node
	select {
	case seen = <-fired:
	case <-time.After(time.Second):
	}
	cancel()
	<-runDone
	return seen
}

// TestUndecodableIbRoutesByShape is the live PF-087 failure, pinned: the server
// announces its queue with counter values the token table has never observed,
// a strict decode fails the whole stanza, and a queue that was announced is
// never answered. The dispatcher's second chance must route <ib> on its shape
// with the holes named, because the answer depends on the shape alone.
func TestUndecodableIbRoutesByShape(t *testing.T) {
	hole := holeFilled(routingDict())
	strict := routingDict()

	preview := &wabinary.Node{
		Tag: "ib",
		Children: []wabinary.Node{{
			Tag: "offline_preview",
			Attrs: wabinary.Attrs{
				"count": "known", "message": "¿d1[158]", "receipt": "¿d2[126]",
			},
		}},
	}
	frame, err := wabinary.NewCodec(hole).Encode(preview)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// The strict table must refuse this frame, or the test proves nothing.
	if _, err := wabinary.NewCodec(strict).Decode(bytes.NewReader(frame)); err == nil {
		t.Fatal("the frame decodes strictly; the test no longer covers the failure")
	}

	seen := runDispatcherOnce(t, frame, strict, hole)
	if seen == nil {
		t.Fatal("an <ib> the table almost covers was not routed by shape")
	}
	if seen.Tag != "ib" || child(seen, "offline_preview") == nil {
		t.Fatalf("routed node lost its shape: %s", attrSummary(seen))
	}
	// The holes must survive as placeholders naming their slots, so the
	// operator can record exactly the entries the table is missing.
	p := child(seen, "offline_preview")
	if p.Attrs["message"] != "¿d1[158]" || p.Attrs["receipt"] != "¿d2[126]" {
		t.Fatalf("holes were not named: %v", p.Attrs)
	}
	if got := p.Attrs["count"]; got != "known" {
		t.Fatalf("known value corrupted: %q", got)
	}
	entries, err := os.ReadDir("undecoded")
	if err != nil || len(entries) == 0 {
		t.Fatalf("routed-by-shape frame was not kept for the table work: %v", err)
	}
}

// TestHoleFilledNonIbIsDropped keeps the loud failure for everything that is
// not server-state routing: a message stanza decoded with placeholder holes
// would carry fabricated values into the receiver.
func TestHoleFilledNonIbIsDropped(t *testing.T) {
	hole := holeFilled(routingDict())
	strict := routingDict()

	node := &wabinary.Node{
		Tag:   "message",
		Attrs: wabinary.Attrs{"count": "¿d2[126]"},
	}
	frame, err := wabinary.NewCodec(hole).Encode(node)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := wabinary.NewCodec(strict).Decode(bytes.NewReader(frame)); err == nil {
		t.Fatal("the frame decodes strictly; the test no longer covers the failure")
	}

	seen := runDispatcherOnce(t, frame, strict, hole)
	if seen != nil {
		t.Fatalf("a hole-decoded %q reached the receive path: %s", seen.Tag, attrSummary(seen))
	}
	entries, err := os.ReadDir("undecoded")
	if err != nil || len(entries) == 0 {
		t.Fatalf("dropped frame was not kept: %v", err)
	}
}

// preKeyNode builds the raw frame a peer's prekey message arrives in, matching
// the live shape: the service addresses inbound stanzas with "from" alone and
// omits "to" entirely (the queue replay carried none).
func preKeyNode(wire []byte) []byte {
	node := &wabinary.Node{
		Tag: "message",
		Attrs: wabinary.Attrs{
			"id": "TEST1", "from": "100000000000000:1@s.whatsapp.net", "type": "text",
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

// msgNode builds the raw frame a session's follow-up arrives in: the
// msg-carrier <enc> a sender uses after its first prekey message.
func msgNode(ciphertext []byte) []byte {
	node := &wabinary.Node{
		Tag: "message",
		Attrs: wabinary.Attrs{
			"id": "TEST2", "from": "100000000000000:1@s.whatsapp.net", "type": "text",
		},
		Children: []wabinary.Node{{
			Tag:   "enc",
			Attrs: wabinary.Attrs{"v": "2", "type": "msg"},
			Bytes: ciphertext,
		}},
	}
	frame, err := wabinary.NewCodec(nil).Encode(node)
	if err != nil {
		panic(err)
	}
	return frame
}

// waitForMessage reads one message event off the bus or fails.
func waitForMessage(t *testing.T, sub *events.Subscription) events.Event {
	t.Helper()
	select {
	case ev := <-sub.C:
		if ev.Message == nil {
			t.Fatalf("event = %#v", ev)
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no message event")
		return events.Event{}
	}
}

// TestSessionsPersistAcrossRuns pins the PF-087 redelivery fix: a session
// installed by a bootstrap in one run decrypts the msg-carrier follow-up in
// the next run, because the receiver's session observer wrote the ratchet
// state to disk and the next run restored it before reading.
func TestSessionsPersistAcrossRuns(t *testing.T) {
	t.Chdir(t.TempDir())
	storePath := sessionsPathFor("paired.keys.json")

	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	signed, err := signal.GenerateSignedPreKey(3, signal.XEdDSASigner{Private: identity.Private})
	if err != nil {
		t.Fatalf("signed prekey: %v", err)
	}
	oneTime, err := signal.GeneratePreKey(7)
	if err != nil {
		t.Fatalf("one-time prekey: %v", err)
	}
	source := &preKeyStore{
		identity: identity,
		signed:   signed,
		oneTime:  map[uint32]signal.PreKey{oneTime.ID: oneTime},
	}

	// The peer side, exactly what the phone does: fetch the bundle, start a
	// session with a prekey message, then continue it with msg carriers.
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
	first, err := encodeText("pertama dari phone")
	if err != nil {
		t.Fatal(err)
	}
	firstCipher, err := state.Encrypt(stanza.PadMessage(first), peer.Public, identity.Public)
	if err != nil {
		t.Fatalf("peer encrypt: %v", err)
	}
	firstWire, err := initiator.BuildPreKeyMessage(peer.Public, 4242, firstCipher)
	if err != nil {
		t.Fatalf("prekey message: %v", err)
	}

	// Run one: bootstrap, and the observer persists the installed session.
	sessions := &sessionsFile{Sessions: map[string]storedSession{}}
	runOne := func(frame []byte) events.Event {
		bus := events.NewBus()
		defer bus.Close()
		sub := bus.Subscribe()
		defer sub.Close()
		receiver, err := coremessaging.NewReceiver(bus, "run-one")
		if err != nil {
			t.Fatal(err)
		}
		receiver.SetReceiverIdentity(identity.Public)
		receiver.SetPreKeySource(source)
		receiver.SetSessionObserver(func(peer string, session *coremessaging.PeerSession) {
			if err := sessions.record(peer, session); err != nil {
				t.Errorf("record: %v", err)
			}
			if err := sessions.save(storePath); err != nil {
				t.Errorf("save: %v", err)
			}
		})
		if err := receiver.HandleFrame(context.Background(), frame); err != nil {
			t.Fatalf("handle frame: %v", err)
		}
		return waitForMessage(t, sub)
	}

	ev := runOne(preKeyNode(firstWire))
	if ev.Message.Text != "pertama dari phone" {
		t.Fatalf("first text = %q", ev.Message.Text)
	}

	// The state is on disk, or the next run proves nothing.
	if len(sessions.Sessions) == 0 {
		t.Fatal("observer recorded nothing")
	}
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("sessions file not written: %v", err)
	}

	// Run two: restore from disk, then the phone continues the ratchet with a
	// msg carrier — the shape every message after the first takes.
	restored, err := loadSessionsFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encodeText("kedua dari phone")
	if err != nil {
		t.Fatal(err)
	}
	secondCipher, err := state.Encrypt(stanza.PadMessage(second), peer.Public, identity.Public)
	if err != nil {
		t.Fatalf("peer encrypt: %v", err)
	}

	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()
	receiver, err := coremessaging.NewReceiver(bus, "run-two")
	if err != nil {
		t.Fatal(err)
	}
	receiver.SetReceiverIdentity(identity.Public)
	if err := restored.install(receiver, nil); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := receiver.HandleFrame(context.Background(), msgNode(secondCipher)); err != nil {
		t.Fatalf("handle follow-up: %v", err)
	}
	ev = waitForMessage(t, sub)
	if ev.Message.Text != "kedua dari phone" {
		t.Fatalf("follow-up text = %q", ev.Message.Text)
	}
}

// TestRetryReceiptShape pins the stanza that turns a message this device
// cannot open into one it can: the sender answers it by fetching a fresh
// bundle and re-encrypting (whatsmeow retry.go SendRetryReceipt).
func TestRetryReceiptShape(t *testing.T) {
	conn := newCaptureConn()
	orig := &wabinary.Node{
		Tag: "message",
		Attrs: wabinary.Attrs{
			"id": "3EB00120C39FC05B2F4CDB", "from": "266988689592415:35@lid",
			"t": "1794751484", "type": "text",
		},
	}
	const registrationID = uint32(884371735)
	if err := sendRetryReceipt(context.Background(), conn, wabinary.NewCodec(nil), orig, registrationID, 1, nil); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case frame := <-conn.written:
		node, err := wabinary.NewCodec(nil).Decode(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if node.Tag != "receipt" {
			t.Fatalf("tag = %q", node.Tag)
		}
		if node.Attrs["type"] != "retry" {
			t.Fatalf("type = %q, want retry", node.Attrs["type"])
		}
		if node.Attrs["to"] != orig.Attrs["from"] {
			t.Fatalf("to = %q, want the sender", node.Attrs["to"])
		}
		retry := child(node, "retry")
		if retry == nil {
			t.Fatal("no <retry> child")
		}
		for k, want := range map[string]string{
			"count": "1", "id": orig.Attrs["id"], "t": orig.Attrs["t"], "v": "1", "error": "0",
		} {
			if got := retry.Attrs[k]; got != want {
				t.Fatalf("retry.%s = %q, want %q", k, got, want)
			}
		}
		reg := childBytes(node, "registration")
		if len(reg) != 4 {
			t.Fatalf("registration is %d bytes, want 4", len(reg))
		}
		if got := binary.BigEndian.Uint32(reg); got != registrationID {
			t.Fatalf("registration = %d, want %d", got, registrationID)
		}
	default:
		t.Fatal("a decryption failure earned no retry receipt on the wire")
	}
}

// mediaConnStub answers the media_conn iq with one hostname, letting the
// download test point the CDN at a local httptest server.
type mediaConnStub struct {
	codec    wabinary.Codec
	inbox    chan []byte
	hostname string
}

func (c *mediaConnStub) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case f := <-c.inbox:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// WriteFrame captures the media_conn request, reuses its id, and queues the
// reply so the read loop resolves the waiting iq.
func (c *mediaConnStub) WriteFrame(ctx context.Context, frame []byte) error {
	req, err := c.codec.Decode(bytes.NewReader(frame))
	if err != nil {
		return err
	}
	if child(req, "media_conn") == nil {
		return fmt.Errorf("unexpected write: %s", attrSummary(req))
	}
	reply := &wabinary.Node{
		Tag: "iq", Attrs: wabinary.Attrs{"type": "result", "id": req.Attrs["id"]},
		Children: []wabinary.Node{{
			Tag: "media_conn", Attrs: wabinary.Attrs{"auth": "x", "ttl": "12345"},
			Children: []wabinary.Node{{Tag: "host", Attrs: wabinary.Attrs{"hostname": c.hostname}}},
		}},
	}
	out, err := c.codec.Encode(reply)
	if err != nil {
		return err
	}
	c.inbox <- out
	return nil
}

func (c *mediaConnStub) Close() error            { return nil }
func (c *mediaConnStub) CipherSuiteName() string { return "test" }

// TestDownloadMediaEndToEnd runs the media download path against a fake CDN:
// a blob encrypted with protocol/media (the exact shape the real CDN serves)
// served over HTTP, fetched, decrypted, hash-verified and written to disk.
func TestDownloadMediaEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())

	plaintext := []byte("PNGDATA-fake-image-bytes-for-the-test")
	mediaKeyBytes := []byte("0123456789abcdef0123456789abcdef")
	var mediaKey [32]byte
	copy(mediaKey[:], mediaKeyBytes)
	keys, err := media.DeriveKeys(mediaKey, media.TypeImage, 0)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	blob, err := media.Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	encSHA := sha256.Sum256(blob)
	fileSHA := sha256.Sum256(plaintext)

	var sawOrigin bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawOrigin = r.Header.Get("Origin") == mediaOrigin
		if !strings.HasPrefix(r.URL.Path, "/v/t62.7118-24/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("hash"); got != base64.URLEncoding.EncodeToString(encSHA[:]) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := r.URL.Query().Get("mms-type"); got != "image" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	info := &events.MediaAttachment{
		Kind:          "image",
		MimeType:      "image/jpeg",
		FileLength:    uint64(len(plaintext)),
		MediaKey:      mediaKeyBytes,
		FileSHA256:    fileSHA[:],
		FileEncSHA256: encSHA[:],
		DirectPath:    "/v/t62.7118-24/13124275_1.jpg?ccb=test",
		KeysType:      media.TypeImage,
	}

	codec := wabinary.NewCodec(nil)
	conn := &mediaConnStub{codec: codec, inbox: make(chan []byte, 4), hostname: strings.TrimPrefix(srv.URL, "http://")}
	d := newDispatcher(conn, codec)
	runDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(runDone)
		d.run(ctx)
	}()

	mediaURLScheme = "http"
	t.Cleanup(func() { mediaURLScheme = "https" })

	path, err := DownloadMedia(ctx, d, info, "media")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !sawOrigin {
		t.Fatal("the CDN request carried no Origin header")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("saved %d bytes, want the original %d", len(got), len(plaintext))
	}
	if !strings.HasSuffix(path, ".jpg") {
		t.Fatalf("extension missing: %s", path)
	}
	cancel()
	<-runDone
}

// TestDownloadMediaRejectsDigestMismatch keeps the verification honest: a
// blob whose plaintext does not hash to fileSHA256 must not land on disk.
func TestDownloadMediaRejectsDigestMismatch(t *testing.T) {
	t.Chdir(t.TempDir())

	plaintext := []byte("the real payload")
	tampered := []byte("the tampered payl0ad")
	var mediaKey [32]byte
	copy(mediaKey[:], []byte("0123456789abcdef0123456789abcdef"))
	keys, err := media.DeriveKeys(mediaKey, media.TypeImage, 0)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := media.Encrypt(tampered, keys)
	if err != nil {
		t.Fatal(err)
	}
	encSHA := sha256.Sum256(blob)
	fileSHA := sha256.Sum256(plaintext) // claims the original, serves the tampered one

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	codec := wabinary.NewCodec(nil)
	conn := &mediaConnStub{codec: codec, inbox: make(chan []byte, 4), hostname: strings.TrimPrefix(srv.URL, "http://")}
	d := newDispatcher(conn, codec)
	runDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(runDone)
		d.run(ctx)
	}()

	mediaURLScheme = "http"
	t.Cleanup(func() { mediaURLScheme = "https" })

	info := &events.MediaAttachment{
		Kind: "image", MimeType: "image/jpeg",
		MediaKey: mediaKey[:], FileSHA256: fileSHA[:], FileEncSHA256: encSHA[:],
		DirectPath: "/v/t62.7118-24/x.jpg?ccb=t", KeysType: media.TypeImage,
	}
	if _, err := DownloadMedia(ctx, d, info, "media"); err == nil {
		t.Fatal("a tampered media blob was accepted")
	}
	cancel()
	<-runDone
}
