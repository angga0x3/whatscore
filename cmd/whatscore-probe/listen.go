package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	gosignal "os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/signal"
	syncpkg "github.com/angga0x3/whatscore/protocol/sync"
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

	// Sessions must outlive the process like the keys do: the phone continues
	// a bootstrapped ratchet with msg-carrier messages, and a run that cannot
	// restore the state loses every one of them. Restored sessions are also
	// why a redelivered queue is not a second chance — the keys those
	// messages were encrypted to are already spent.
	sessionsPath := sessionsPathFor(cfg.KeyPath)
	sessions, err := loadSessionsFile(sessionsPath)
	if err != nil {
		return err
	}
	sender, senderErr := coremessaging.NewSender(frameWriter{sc: sc}, coremessaging.WithCodec(codec))
	if senderErr != nil {
		return senderErr
	}
	sender.SetIdentityPair(identityPair)
	if err := sessions.install(receiver, sender); err != nil {
		return err
	}
	if n := len(sessions.Sessions); n > 0 {
		fmt.Printf("sessions: %d restored from %s\n", n, sessionsPath)
	}
	receiver.SetSessionObserver(func(peer string, session *coremessaging.PeerSession) {
		if err := sessions.record(peer, session); err != nil {
			fmt.Printf("could not record session for %s: %v\n", peer, err)
		} else if err := sessions.save(sessionsPath); err != nil {
			fmt.Printf("could not save sessions: %v\n", err)
		}
		if err := sender.SetPeer(peer, session); err != nil {
			fmt.Printf("could not mirror session to the sender: %v\n", err)
		}
	})

	// A message that will not open is not a dead end: whatsmeow answers it
	// with a retry receipt, and the sender re-encrypts to a fresh bundle —
	// one that names keys this device actually holds. The cap stops a
	// permanently broken message from looping forever.
	retryMu := sync.Mutex{}
	retryCounts := map[string]int{}
	receiver.SetDecryptFailureHandler(func(node *wabinary.Node) {
		id := node.Attrs["id"]
		from := node.Attrs["from"]
		if id == "" || from == "" {
			return
		}
		retryMu.Lock()
		retryCounts[id]++
		count := retryCounts[id]
		retryMu.Unlock()
		if count > 3 {
			return
		}
		// The keys block goes on every attempt, not just the second: the
		// sender's re-encryption arrives under a new message id, which resets
		// any per-id count, so waiting for attempt two never fires. A fresh
		// one-time prekey per retry is cheap; the sender's cached bundle is
		// what produced the unreadable message.
		var keysBlock *wabinary.Node
		{
			block, err := retryKeysBlock(record, keys, signer)
			if err != nil {
				fmt.Printf("retry keys: %v\n", err)
			} else {
				keysBlock = block
				if err := keys.save(cfg.KeyPath); err != nil {
					fmt.Printf("could not save key file after retry keys: %v\n", err)
				}
			}
		}
		if err := sendRetryReceipt(ctx, sc, codec, node, record.RegistrationID, count, keysBlock); err != nil {
			fmt.Printf("retry receipt: %v\n", err)
		} else {
			fmt.Printf("retry receipt sent for %s (attempt %d)\n", id, count)
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
			// No receipt here. The receipt is the server's proof of delivery,
			// and a message this device cannot open must stay in its queue —
			// receipting it first is how a failed decrypt deletes the only
			// copy the server holds. Receipts go out from the event loop,
			// after a message actually decrypted.
		case "iq":
			if node.Attrs["xmlns"] == "urn:xmpp:ping" {
				answerPingNode(ctx, sc, codec, node)
			}
		}
		if err := receiver.HandleFrame(ctx, encodeForReceiver(codec, node)); err != nil {
			fmt.Printf("receiver: %v\n", err)
		}
	}

	// App state sync keys the phone shares (APP_STATE_SYNC_KEY_SHARE). Patch
	// MACs reference these ids; without them the app state patches cannot be
	// verified, and the phone holds the "keep both apps open" banner until
	// provisioning completes.
	var mu sync.Mutex
	appStateKeys := make(map[string][]byte)

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
				if ev.Message.Protocol != nil {
					if len(ev.Message.Protocol.AppKeys) > 0 {
						mu.Lock()
						for keyID, data := range ev.Message.Protocol.AppKeys {
							appStateKeys[keyID] = append([]byte(nil), data...)
						}
						count := len(appStateKeys)
						mu.Unlock()
						fmt.Printf("app state keys stored (total %d)\n", count)
						// Baileys: "app state sync key arrived, re-syncing
						// blocked collections" — the keys were missing when
						// the first request went out; with them the patches
						// verify. The re-request must not block the read loop.
						go requestAppStateSync(ctx, d, sc, codec, record, source, &mu, appStateKeys, sender, sessions, sessionsPath)
					}
					if ev.Message.Protocol.HistorySync {
						// The ack the phone's "keep both apps open" phase waits
						// for: history messages take type=hist_sync, not the
						// delivery receipt (Baileys getHistoryMsg).
						sendHistSyncReceipt(ctx, sc, codec, ev.Message.ID, ev.Message.Sender)
					}
					continue
				}
				fmt.Printf("\nMESSAGE from=%s id=%s at=%s\n  text: %s\n",
					ev.Message.Sender, ev.Message.ID, ev.Message.Timestamp.Format(time.RFC3339), ev.Message.Text)
				// The receipt follows the decrypt, not the stanza: the server
				// keeps a message it has no receipt for, so a failed decrypt
				// can be recovered instead of erased.
				if err := sendDeliveryReceipt(context.Background(), sc, codec, ev.Message.ID, ev.Message.Sender); err != nil {
					fmt.Printf("delivery receipt: %v\n", err)
				}
				if m := ev.Message.Media; m != nil {
					path, err := DownloadMedia(context.Background(), d, m, cfg.MediaDir)
					if err != nil {
						fmt.Printf("  media: kind=%s mime=%s bytes=%d download failed: %v\n",
							m.Kind, m.MimeType, m.FileLength, err)
					} else {
						fmt.Printf("  media: kind=%s mime=%s bytes=%d saved to %s\n",
							m.Kind, m.MimeType, m.FileLength, path)
					}
				}
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
		// An empty store is why senders drift to the signed prekey — and once
		// one of those messages bootstraps, the key is spent on our side and
		// every later message becomes unreadable. Top up now; whatsmeow
		// uploads whenever the count runs low, and the server's own count
		// re-tests the "repeat upload is refused" reading in PF-082.
		if n == 0 {
			if err := publishFreshBatch(ctx, d, record, keys, signer, cfg.KeyPath); err != nil {
				fmt.Printf("prekeys: top-up failed: %v\n", err)
			} else if n2, err2 := diagPreKeyCount(ctx, d); err2 != nil {
				fmt.Printf("DIAG prekey count after top-up: %v\n", err2)
			} else {
				fmt.Printf("DIAG server holds %d one-time prekeys after top-up\n", n2)
			}
		}
	}

	if err := setActiveDispatcher(ctx, d); err != nil {
		d.shutdown()
		<-loopDone
		return fmt.Errorf("mark device active: %w", err)
	}
	fmt.Println("session: active")

	// App state sync starts provisioning: the server answers with patches and
	// pushes key shares as protocol messages. WhatsApp Web and Baileys request
	// these right after login; skipping it leaves the phone in the "keep both
	// apps open" phase indefinitely.
	requestAppStateSync(ctx, d, sc, codec, record, source, &mu, appStateKeys, sender, sessions, sessionsPath)

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
	// worth extending for. Provisioning (key shares answering the app state
	// key request) lands in this window too, and the phone answers on its own
	// schedule — hence the generous ceiling.
	offlineGrace := 30 * time.Minute
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

// sendRetryReceipt asks the sender to re-encrypt a message this device could
// not open, shaped like whatsmeow's retry receipt (retry.go): the original
// receipt attrs with type="retry", a <retry count id t v=1> child naming the
// message, and the device's 4-byte registration id. On the second attempt and
// later the receipt carries a <keys> block, because the sender's cached bundle
// is exactly what produced the unreadable message — it needs the current key
// material inline, or it re-encrypts to the same spent key.
func sendRetryReceipt(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, node *wabinary.Node, registrationID uint32, count int, keysBlock *wabinary.Node) error {
	var reg [4]byte
	reg[0] = byte(registrationID >> 24)
	reg[1] = byte(registrationID >> 16)
	reg[2] = byte(registrationID >> 8)
	reg[3] = byte(registrationID)
	children := []wabinary.Node{
		// error="0" is what Baileys carries on every retry child; the official
		// clients expect the attribute alongside count/id/t/v.
		{Tag: "retry", Attrs: wabinary.Attrs{
			"count": strconv.Itoa(count),
			"id":    node.Attrs["id"],
			"t":     node.Attrs["t"],
			"v":     "1",
			"error": "0",
		}},
		{Tag: "registration", Bytes: reg[:]},
	}
	if keysBlock != nil {
		children = append(children, *keysBlock)
	}
	receipt := &wabinary.Node{
		Tag: "receipt",
		Attrs: wabinary.Attrs{
			"id":   node.Attrs["id"],
			"to":   node.Attrs["from"],
			"type": "retry",
		},
		Children: children,
	}
	frame, err := codec.Encode(receipt)
	if err != nil {
		return err
	}
	return sc.WriteFrame(ctx, frame)
}

// retryKeysBlock builds the inline key material of whatsmeow's retry receipt:
// a fresh one-time prekey (persisted before it goes on the wire), the signed
// prekey, the identity key, and the device identity this device registered
// with at pairing.
func retryKeysBlock(record *credentialRecord, keys *keyFile, signer signal.XEdDSASigner) (*wabinary.Node, error) {
	fresh, err := keys.generateFresh(1, signer)
	if err != nil {
		return nil, err
	}
	signed, err := keys.signedPreKey()
	if err != nil {
		return nil, err
	}
	deviceIdentity, err := deviceIdentityBytes(record)
	if err != nil {
		return nil, err
	}
	return &wabinary.Node{
		Tag: "keys",
		Children: []wabinary.Node{
			{Tag: "type", Bytes: []byte{5}},
			{Tag: "identity", Bytes: append([]byte(nil), record.IdentityPub[:]...)},
			// Key ids ride as 3 bytes on the wire — the upload path learned
			// this the hard way (PF-082); the retry keys block obeys the same
			// encoding.
			{Tag: "key", Children: []wabinary.Node{
				{Tag: "id", Bytes: []byte{byte(fresh[0].ID >> 16), byte(fresh[0].ID >> 8), byte(fresh[0].ID)}},
				{Tag: "value", Bytes: append([]byte(nil), fresh[0].Pair.Public[:]...)},
			}},
			{Tag: "skey", Children: []wabinary.Node{
				{Tag: "id", Bytes: []byte{byte(signed.ID >> 16), byte(signed.ID >> 8), byte(signed.ID)}},
				{Tag: "value", Bytes: append([]byte(nil), signed.Pair.Public[:]...)},
				{Tag: "signature", Bytes: append([]byte(nil), signed.Signature...)},
			}},
			{Tag: "device-identity", Bytes: deviceIdentity},
		},
	}, nil
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

// sendDeliveryReceipt tells the sender the message arrived (PF-035) — and
// tells the server to stop queueing it, which is why it must only fire after
// the message actually decrypted.
func sendDeliveryReceipt(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, id, from string) error {
	if from == "" || id == "" {
		return fmt.Errorf("receipt needs an id and a from")
	}
	receipt := &wabinary.Node{
		Tag:   "receipt",
		Attrs: wabinary.Attrs{"to": from, "id": id},
	}
	frame, err := codec.Encode(receipt)
	if err != nil {
		return err
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		return err
	}
	fmt.Printf("delivery receipt sent for %s\n", id)
	return nil
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

// appStateCollections is the full patch list WhatsApp Web syncs
// (Baileys ALL_WA_PATCH_NAMES).
var appStateCollections = []string{
	"critical_block",
	"critical_unblock_low",
	"regular_high",
	"regular_low",
	"regular",
}

// sendHistSyncReceipt acknowledges one history chunk. Without it the phone
// holds the "keep both apps open" banner indefinitely: the device never tells
// the server the chunk arrived.
func sendHistSyncReceipt(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, id, from string) {
	if id == "" || from == "" {
		return
	}
	receipt := &wabinary.Node{
		Tag:   "receipt",
		Attrs: wabinary.Attrs{"id": id, "to": from, "type": "hist_sync"},
	}
	frame, err := codec.Encode(receipt)
	if err != nil {
		return
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		fmt.Printf("hist_sync receipt: %v\n", err)
		return
	}
	fmt.Printf("hist_sync receipt sent for %s\n", id)
}

// requestAppStateSync fetches the app state patches for every collection.
// A fresh device has no stored versions, so every collection asks for a
// snapshot; mutations verify against the keys the phone shared.
func requestAppStateSync(ctx context.Context, d *dispatcher, sc noise.SecureConn, codec wabinary.Codec, record *credentialRecord, source *preKeyStore, mu *sync.Mutex, appStateKeys map[string][]byte, sender *coremessaging.Sender, sessions *sessionsFile, sessionsPath string) {
	mu.Lock()
	keyCount := len(appStateKeys)
	mu.Unlock()
	if keyCount == 0 {
		fmt.Println("app state sync: no keys yet; requesting anyway")
	}

	collections := make([]wabinary.Node, 0, len(appStateCollections))
	for _, name := range appStateCollections {
		collections = append(collections, wabinary.Node{
			Tag: "collection",
			Attrs: wabinary.Attrs{
				"name":            name,
				"return_snapshot": "true",
			},
		})
	}
	reply, err := d.request(ctx, &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to": serverJID, "type": "set", "xmlns": "w:sync:app:state", "id": mustRequestID(ctx),
		},
		Children: []wabinary.Node{{Tag: "sync", Children: collections}},
	}, 30*time.Second)
	if err != nil {
		fmt.Printf("app state sync request failed: %v\n", err)
		return
	}
	var syncNode *wabinary.Node
	for i := range reply.Children {
		if reply.Children[i].Tag == "sync" {
			syncNode = &reply.Children[i]
			break
		}
	}
	if syncNode == nil {
		fmt.Printf("app state reply has no <sync> (%d children)\n", len(reply.Children))
		return
	}
	patches, err := syncpkg.ParsePatches(syncNode)
	if err != nil {
		fmt.Printf("app state patches unreadable: %v\n", err)
		return
	}
	decoded, skipped := 0, 0
	var missing [][]byte
	seenMissing := make(map[string]bool)
	for _, patch := range patches {
		for _, mutation := range patch.Mutations {
			keyID := hex.EncodeToString(mutation.KeyID)
			mu.Lock()
			key, ok := appStateKeys[keyID]
			mu.Unlock()
			if !ok {
				if !seenMissing[keyID] {
					seenMissing[keyID] = true
					missing = append(missing, mutation.KeyID)
				}
				skipped++
				continue
			}
			expanded, err := syncpkg.ExpandKeys(key)
			if err != nil {
				continue
			}
			if _, err := syncpkg.DecodeMutation(mutation, expanded); err != nil {
				fmt.Printf("mutation decode failed: %v\n", err)
				continue
			}
			decoded++
		}
	}
	fmt.Printf("app state sync: %d patches, %d decoded, %d skipped (no key)\n", len(patches), decoded, skipped)

	// whatsmeow requestAppStateKeys: ask the phone for the missing ids. The
	// phone answers with an APP_STATE_SYNC_KEY_SHARE, whose storage already
	// triggers a re-request of the pending patches.
	if len(missing) > 0 && sender != nil {
		phonePeer := phonePeerFor(record.LID, sessions.Sessions)
		go func() {
			reqCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			if err := sendAppStateKeyRequest(reqCtx, sender, sessions, sessionsPath, phonePeer, missing); err != nil {
				fmt.Printf("app state key request failed: %v\n", err)
			}
		}()
	}
}

// mustRequestID builds a request id; on randomness failure it falls back to
// the clock, which is unique enough for one process.
func mustRequestID(ctx context.Context) string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return strconv.FormatUint(uint64(buf[0])<<24|uint64(buf[1])<<16|uint64(buf[2])<<8|uint64(buf[3]), 10)
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
