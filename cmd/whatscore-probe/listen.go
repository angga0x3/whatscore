package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	gosignal "os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// preKeyStore holds the key material this device published, so an inbound
// prekey message can be bootstrapped.
//
// The published keys are regenerated per run, which means a peer can only
// bootstrap a session during the run that published them. That is a real
// limitation of a stateless probe, stated rather than hidden: persisting them is
// the difference between a probe and a client.
type preKeyStore struct {
	identity signal.KeyPair
	signed   signal.SignedPreKey
	oneTime  map[uint32]signal.PreKey
}

func (s *preKeyStore) Identity() signal.KeyPair { return s.identity }

func (s *preKeyStore) SignedPreKey(id uint32) (*signal.SignedPreKey, error) {
	if s.signed.ID != id {
		return nil, fmt.Errorf("signed prekey %d was not published by this run (have %d)", id, s.signed.ID)
	}
	out := s.signed
	return &out, nil
}

func (s *preKeyStore) OneTimePreKey(id uint32) (*signal.PreKey, error) {
	key, ok := s.oneTime[id]
	if !ok {
		return nil, fmt.Errorf("one-time prekey %d was not published by this run", id)
	}
	out := key
	return &out, nil
}

// runListen logs in, publishes prekeys, and decrypts inbound messages until the
// timeout or an interrupt.
func runListen(cfg sendConfig) error {
	record, err := loadCredentialRecord(cfg.CredPath)
	if err != nil {
		return err
	}
	login, err := parseLoginIdentity(record)
	if err != nil {
		return err
	}
	dict, err := loadDictionary(cfg.DictPath)
	if err != nil {
		return err
	}
	codec := wabinary.NewCodec(dict)

	ctx, stop := listenContext(cfg.Timeout)
	defer stop()

	sc, err := dialLogin(ctx, cfg.Endpoint, record, login)
	if err != nil {
		return err
	}
	defer func() { _ = sc.Close() }()

	// Key material must outlive the process: a prekey id the server has seen
	// can be encrypted to at any later point, and losing the private half makes
	// those messages unreadable for good.
	keys, err := loadKeyFile(cfg.KeyPath)
	if err != nil {
		return err
	}
	// Adopt the signed prekey pairing registered before generating anything:
	// the server already handed that key to peers.
	keys.seedFromRecord(record)
	identityPair := signal.KeyPair{Private: record.IdentityPriv, Public: record.IdentityPub}
	signer := signal.XEdDSASigner{Private: record.IdentityPriv}
	if _, err := keys.generate(preKeyBatch, signer); err != nil {
		return err
	}
	if err := keys.save(cfg.KeyPath); err != nil {
		return err
	}
	source, err := keys.store(identityPair)
	if err != nil {
		return err
	}

	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	// A silent logger turns every decryption failure into "no message arrived",
	// which is exactly the wrong answer when diagnosing a receive path.
	receiver, err := coremessaging.NewReceiver(bus, "probe",
		coremessaging.WithReceiverCodec(codec),
		coremessaging.WithReceiverLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	)
	if err != nil {
		return err
	}
	receiver.SetReceiverIdentity(record.IdentityPub)
	receiver.SetPreKeySource(source)
	receiver.SetPreKeyConsumer(func(id uint32) {
		// The key is spent; dropping it from disk is what stops a replay and
		// keeps the file from growing forever.
		keys.consume(id)
		if err := keys.save(cfg.KeyPath); err != nil {
			fmt.Printf("could not update key file after consuming %d: %v\n", id, err)
		}
	})

	d := newDispatcher(sc, codec)
	// Second chance for stanzas the table almost covers: without it the
	// offline announcement fails whole on unknown attribute tokens and the
	// queue it announces is never answered (PF-087).
	d.holeCodec = wabinary.NewCodec(holeFilled(dict))
	offline := newOfflineQueue(sc, codec)
	d.onNode = func(ctx context.Context, node *wabinary.Node) {
		// Trace every stanza before any interpretation. A receive path that only
		// prints what it successfully decrypted cannot distinguish "nothing
		// arrived" from "something arrived and was rejected".
		fmt.Printf("TRACE %s%s\n", node.Tag, attrSummary(node))
		switch node.Tag {
		case "ib":
			offline.handle(ctx, node)
			// Server-state routing only; nothing here is user data, and a
			// hole-decoded one carries placeholder values the strict codec
			// cannot re-encode for the receiver.
			return
		case "message":
			// A receipt goes back before decryption: a sender that never sees
			// one retries the same message.
			sendDeliveryReceipt(ctx, sc, codec, node)
		case "iq":
			if node.Attrs["xmlns"] == "urn:xmpp:ping" {
				answerPingNode(ctx, sc, codec, node)
			}
		}
		if err := receiver.HandleFrame(ctx, encodeForReceiver(codec, node)); err != nil {
			fmt.Printf("receiver: %v\n", err)
		}
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-sub.C:
				if !ok {
					return
				}
				if ev.Message == nil {
					continue
				}
				fmt.Printf("\nMESSAGE from=%s id=%s at=%s\n  text: %s\n",
					ev.Message.Sender, ev.Message.ID, ev.Message.Timestamp.Format(time.RFC3339), ev.Message.Text)
			}
		}
	}()

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		d.run(ctx)
	}()

	// The login verdict arrives through the same loop.
	if err := awaitSuccessVerdict(ctx, d); err != nil {
		d.shutdown()
		<-loopDone
		return err
	}

	// A freshly logged-in companion starts passive; the server only pushes
	// inbound traffic once it is told the device is active (PF-084).
	// Ask the server what it actually holds. Our key file saying "published"
	// only proves we sent the node.
	if n, err := diagPreKeyCount(ctx, d); err != nil {
		fmt.Printf("DIAG prekey count: %v\n", err)
	} else {
		fmt.Printf("DIAG server holds %d one-time prekeys\n", n)
	}

	if err := setActiveDispatcher(ctx, d); err != nil {
		d.shutdown()
		<-loopDone
		return fmt.Errorf("mark device active: %w", err)
	}
	fmt.Println("session: active")

	// whatsmeow marks the client available with a presence stanza right after
	// login; without it the server keeps the device passive and every stanza
	// this probe has ever seen was offline-queue replay, never live fan-out.
	if err := sendAvailablePresence(ctx, sc, codec); err != nil {
		fmt.Printf("presence: %v\n", err)
	} else {
		fmt.Println("presence: available")
	}

	if err := publishMissingKeys(ctx, d, record, keys, cfg.KeyPath); err != nil {
		d.shutdown()
		<-loopDone
		return fmt.Errorf("publish prekeys: %w", err)
	}
	signed, err := keys.signedPreKey()
	if err != nil {
		d.shutdown()
		<-loopDone
		return err
	}
	fmt.Printf("prekeys: %d one-time available (signed %d)\n", len(keys.OneTime), signed.ID)

	fmt.Println("\nlistening for inbound messages...")

	// Wait for the window to close or for the connection to end, whichever comes
	// first. Waiting only on the context made a dead socket look identical to a
	// quiet one: the process sat silent for the full timeout and then reported
	// "window ended", which is a false negative an operator cannot see through.
	// The offline drain gets its own grace beyond the window: the drain marker
	// is the moment live fan-out should start, so that is when watching is
	// worth extending for.
	offlineGrace := 5 * time.Minute
	select {
	case <-ctx.Done():
		d.shutdown()
		<-loopDone
		// A queue the server announced but never drained is the PF-087
		// observation. Saying so beats "window ended", which reads as healthy.
		if offline.announcedAndUndrained() {
			fmt.Println("\nlisten window ended: the queue was announced but the drain marker never came (PF-087)")
		} else {
			fmt.Println("\nlisten window ended")
		}
		return nil
	case <-loopDone:
		// The window's deadline fires on the socket at the same instant it
		// fires on the context; whichever wins, a read error from that race
		// is the window ending, not the connection dying.
		if ctx.Err() != nil {
			fmt.Println("\nlisten window ended")
			return nil
		}
		if err := d.readError(); err != nil {
			fmt.Printf("\nconnection ended: %v\n", err)
			return fmt.Errorf("connection ended while listening: %w", err)
		}
		fmt.Println("\nconnection closed by the server")
		return nil
	case <-offline.drained:
		fmt.Println("\noffline queue drained; live traffic should now flow")
		select {
		case <-ctx.Done():
			d.shutdown()
			<-loopDone
			fmt.Println("listen window ended")
			return nil
		case <-time.After(offlineGrace):
			d.shutdown()
			<-loopDone
			fmt.Println("listen window ended (post-drain grace elapsed)")
			return nil
		case <-loopDone:
			if ctx.Err() != nil {
				fmt.Println("listen window ended")
				return nil
			}
			if err := d.readError(); err != nil {
				fmt.Printf("\nconnection ended: %v\n", err)
				return fmt.Errorf("connection ended while listening: %w", err)
			}
			fmt.Println("\nconnection closed by the server")
			return nil
		}
	}
}

// offlineQueue owns the announcement/batch handshake over the shared read loop.
//
// The server freezes its offline queue until the client answers the
// announcement with a batch request, and keeps live traffic behind that queue.
// A client that never answers is a client the server never delivers to
// (PF-087). The server then streams the queue and closes it with the drain
// marker <ib><offline/>; only that marker means "drained" — the request going
// out proves nothing on its own.
type offlineQueue struct {
	sc    noise.SecureConn
	codec wabinary.Codec

	// drained closes exactly once, on the drain marker. The server may
	// re-announce or re-drain mid-session; neither may crash the process.
	drained   chan struct{}
	drainOnce sync.Once

	mu        sync.Mutex
	announced bool
}

func newOfflineQueue(sc noise.SecureConn, codec wabinary.Codec) *offlineQueue {
	return &offlineQueue{sc: sc, codec: codec, drained: make(chan struct{})}
}

// handle reacts to one <ib> stanza.
func (o *offlineQueue) handle(ctx context.Context, node *wabinary.Node) {
	// The queue stays frozen until the client names a batch size. Every
	// reference implementation sends the same node: one <offline_batch> asking
	// for a bounded slice, repeated if the drain marker has not arrived.
	if child(node, "offline_preview") != nil {
		o.mu.Lock()
		o.announced = true
		o.mu.Unlock()
		if err := o.requestBatch(ctx); err != nil {
			fmt.Printf("offline batch: %v\n", err)
		} else {
			fmt.Println("offline batch: requested")
		}
	}
	if child(node, "offline") != nil {
		fmt.Println("offline queue: drained")
		o.drainOnce.Do(func() { close(o.drained) })
	}
}

// announcedAndUndrained reports whether the server named a queue that never
// reached its drain marker inside the window.
func (o *offlineQueue) announcedAndUndrained() bool {
	select {
	case <-o.drained:
		return false
	default:
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.announced
}

// requestBatch answers the server's <ib><offline_preview/> with the batch
// request.
func (o *offlineQueue) requestBatch(ctx context.Context) error {
	batch := &wabinary.Node{
		Tag: "ib",
		Children: []wabinary.Node{{
			Tag: "offline_batch", Attrs: wabinary.Attrs{"count": "100"},
		}},
	}
	frame, err := o.codec.Encode(batch)
	if err != nil {
		return err
	}
	return o.sc.WriteFrame(ctx, frame)
}

// sendAvailablePresence marks the device available, the way whatsmeow's
// SendPresence does after login: <presence type="available" name="..."/>.
func sendAvailablePresence(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec) error {
	presence := &wabinary.Node{
		Tag:   "presence",
		Attrs: wabinary.Attrs{"type": "available", "name": "whatscore"},
	}
	frame, err := codec.Encode(presence)
	if err != nil {
		return err
	}
	return sc.WriteFrame(ctx, frame)
}

// awaitSuccessVerdict consumes the login verdict from the dispatcher's stream.
//
// It registers a catch-all: the success node has no id, so it cannot be routed
// as an iq reply.
func awaitSuccessVerdict(ctx context.Context, d *dispatcher) error {
	verdict := make(chan string, 1)
	inner := d.onNode
	d.onNode = func(ctx context.Context, node *wabinary.Node) {
		switch node.Tag {
		case "success":
			select {
			case verdict <- "":
			default:
			}
			return
		case "failure":
			select {
			case verdict <- node.Attrs["reason"]:
			default:
			}
			return
		}
		if inner != nil {
			inner(ctx, node)
		}
	}

	select {
	case reason := <-verdict:
		d.onNode = inner
		if reason != "" {
			return fmt.Errorf("login rejected: reason=%q", reason)
		}
		fmt.Println("login: ok")
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("no login verdict within 30s")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// setActiveDispatcher requests the active state through the dispatcher.
func setActiveDispatcher(ctx context.Context, d *dispatcher) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	_, err = d.request(ctx, &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to": serverJID, "type": "set", "xmlns": "passive", "id": id,
		},
		Children: []wabinary.Node{{Tag: "active"}},
	}, 20*time.Second)
	return err
}

// answerPingNode replies to a keepalive.
func answerPingNode(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, node *wabinary.Node) {
	pong := &wabinary.Node{Tag: "iq", Attrs: wabinary.Attrs{
		"to": serverJID, "type": "result", "id": node.Attrs["id"],
	}}
	if frame, err := codec.Encode(pong); err == nil {
		_ = sc.WriteFrame(ctx, frame)
	}
}

// encodeForReceiver re-encodes a decoded node so the receiver's own codec path
// sees the same bytes it would have read itself.
func encodeForReceiver(codec wabinary.Codec, node *wabinary.Node) []byte {
	frame, err := codec.Encode(node)
	if err != nil {
		return nil
	}
	return frame
}

// listenContext is a cancellable context that honours an optional timeout and
// SIGINT.
func listenContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, stop := gosignal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	if timeout <= 0 {
		return ctx, stop
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	return ctx, func() { cancel(); stop() }
}

// sendDeliveryReceipt tells the sender the message arrived (PF-035).
func sendDeliveryReceipt(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, node *wabinary.Node) {
	from := node.Attrs["from"]
	id := node.Attrs["id"]
	if from == "" || id == "" {
		return
	}
	receipt := &wabinary.Node{
		Tag:   "receipt",
		Attrs: wabinary.Attrs{"to": from, "id": id},
	}
	frame, err := codec.Encode(receipt)
	if err != nil {
		return
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		return
	}
	fmt.Printf("delivery receipt sent for %s\n", id)
}

// attrSummary renders the attributes that matter for routing, truncated so a
// long stanza cannot flood the terminal.
func attrSummary(node *wabinary.Node) string {
	keys := []string{"id", "from", "to", "type", "t", "notify", "xmlns", "class"}
	out := ""
	for _, k := range keys {
		if v := node.Attrs[k]; v != "" {
			out += " " + k + "=" + truncate(v, 40)
		}
	}
	if children := len(node.Children); children > 0 {
		out += fmt.Sprintf(" children=%d", children)
		for i := range node.Children {
			out += " <" + node.Children[i].Tag + ">"
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// diagPreKeyCount asks the server how many one-time prekeys it actually holds
// for this device.
//
// This is the question that decides whether an upload worked. Marking a key
// file "published" because we sent a node proves only that we sent it; the
// server's own count is the only authority, and without it "the server will not
// encrypt to us" and "we never published" look identical from the client side.
func diagPreKeyCount(ctx context.Context, d *dispatcher) (int, error) {
	id, err := randomID()
	if err != nil {
		return 0, err
	}
	reply, err := d.request(ctx, &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to": serverJID, "type": "get", "xmlns": "encrypt", "id": id,
		},
		Children: []wabinary.Node{{Tag: "count"}},
	}, 20*time.Second)
	if err != nil {
		return -1, err
	}
	count := child(reply, "count")
	if count == nil {
		return -1, fmt.Errorf("reply has no <count>: %s", attrSummary(reply))
	}
	value := count.Attrs["value"]
	if value == "" {
		return -1, fmt.Errorf("<count> has no value attribute: %s", attrSummary(count))
	}
	n := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return -1, fmt.Errorf("count value %q is not a number", value)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}
