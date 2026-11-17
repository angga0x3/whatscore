package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/core/prekeys"
	"github.com/angga0x3/whatscore/core/signalsession"
	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
	syncpkg "github.com/angga0x3/whatscore/protocol/sync"
	storagecredentials "github.com/angga0x3/whatscore/storage/credentials"
)

// ServerJID is the WhatsApp service address client-facing stanzas address.
const serverJID = "s.whatsapp.net"

// sessionRuntime is the inbound brain of one server session: it turns raw
// frames from core/session into decoded stanzas, keeps the connection alive
// (pings), un-freezes the offline queue (PF-087), feeds the receiver, and
// answers decryption failures with retry receipts carrying inline keys.
//
// It exists because core/session reads frames and discards them by design:
// "message and Signal handling belong to the FrameHandler" — and without one,
// a connected server session hears nothing, which is exactly what the REST
// surface could not do until now.
//
// Lifecycle: created per session, attached to the session after construction
// (the write path is the session's own WriteFrame, routed through the actor),
// and its bus subscription lives as long as the process.
type sessionRuntime struct {
	id             string
	codec          binary.Codec
	logger         *slog.Logger
	receiver       *coremessaging.Receiver
	registrationID uint32
	preKeys        *prekeys.Manager

	mu      sync.Mutex
	waiters map[string]chan *binary.Node
	retries map[string]int
	// mediaSaved dedups the download goroutine across event redeliveries.
	mediaSaved map[string]bool
	// uploaded tracks the one-time prekey ids already pushed to the server,
	// so reconnects upload only the delta instead of repeating the pool.
	uploaded map[uint32]bool
	// identity is this device's full Signal identity key pair: the receiver
	// uses the public half, the sender signs with the private half.
	identity signal.KeyPair
	// sender delivers outbound text over the same write path.
	sender *coremessaging.Sender
	// mediaSaver stores decrypted inbound attachments; nil logs and drops.
	mediaSaver mediaSaver
	// appStateKeys holds the app state sync keys the phone shared, keyed by
	// the hex of the key id. Patch MACs reference these ids; without them the
	// patches cannot be verified.
	appStateKeysMu sync.Mutex
	appStateKeys   map[string][]byte
	// appStateKey names the vault record the keys live under. They are
	// secrets like any other: a file beside the process is not the vault.
	appStateKey string
	// secrets is the encrypted store every persisted record goes through.
	secrets signalsession.Store
	// deviceIdentity is the self-signed blob pairing produced; the retry
	// receipt's inline keys block carries it. Empty until paired.
	deviceIdentity []byte
	// ownLID is the account's LID: the own-device copy of a send is addressed
	// to the phone's session, which is the one whose user matches it.
	ownLID string
	// signals persists every peer ratchet this session installs or advances.
	// A restart without it is a one-way door: the peer continues the chain
	// with msg carriers and this device has no state to open them (PF-087).
	signals *signalStore

	// write is the session's WriteFrame, attached after construction because
	// the session needs the handler before it exists.
	muWrite sync.Once
	write   func(context.Context, []byte) error

	connectedOnce sync.Once
	stop          chan struct{}
}

// newSessionRuntime wires the receiver with the session's key material and
// starts the bus loop that answers message events with delivery receipts.
func newSessionRuntime(id string, codec binary.Codec, logger *slog.Logger, identity signal.KeyPair, preKeys *prekeys.Manager, registrationID uint32, account pairedAccount, media mediaSaver, bus *events.Bus, appStateKey string, signals *signalStore, secrets signalsession.Store) (*sessionRuntime, error) {
	receiver, err := coremessaging.NewReceiver(bus, id, coremessaging.WithReceiverCodec(codec))
	if err != nil {
		return nil, fmt.Errorf("cmd/whatscore: session %s: receiver: %w", id, err)
	}
	receiver.SetReceiverIdentity(identity.Public)
	receiver.SetPreKeySource(preKeys)
	receiver.SetPreKeyConsumer(func(id uint32) {
		// The key is spent; removing it is what stops a replay.
		if err := preKeys.ConsumeOneTimePreKey(context.Background(), id); err != nil {
			logger.Warn("could not consume one-time prekey", "session", id, "prekey", id, "error", err)
		}
	})
	r := &sessionRuntime{
		id:             id,
		codec:          codec,
		logger:         logger,
		receiver:       receiver,
		registrationID: registrationID,
		preKeys:        preKeys,
		waiters:        make(map[string]chan *binary.Node),
		retries:        make(map[string]int),
		appStateKeys:   make(map[string][]byte),
		mediaSaved:     make(map[string]bool),
		uploaded:       make(map[uint32]bool),
		identity:       identity,
		deviceIdentity: append([]byte(nil), account.SignedIdentity...),
		ownLID:         account.LID,
		mediaSaver:     media,
		signals:        signals,
		appStateKey:    appStateKey,
		secrets:        secrets,
		stop:           make(chan struct{}),
	}
	r.loadAppStateKeys()

	// A message the device cannot open must stay recoverable: the retry
	// receipt asks the sender to re-encrypt with the inline keys.
	receiver.SetDecryptFailureHandler(r.sendRetryReceipt)

	// The sender shares the runtime's write path and the receiver's peer
	// sessions: a session the receiver bootstrapped is one the sender can
	// continue, and a ratchet advance on either side updates both.
	sender, err := coremessaging.NewSender(&runtimeWrite{r: r}, coremessaging.WithCodec(codec))
	if err != nil {
		return nil, fmt.Errorf("cmd/whatscore: session %s: sender: %w", id, err)
	}
	sender.SetIdentityPair(identity)
	sender.SetPreKeyBundleSource(&runtimeBundles{r: r})
	r.sender = sender
	receiver.SetSessionObserver(func(peer string, ps *coremessaging.PeerSession) {
		if err := sender.SetPeer(peer, ps); err != nil {
			logger.Warn("could not mirror peer session to the sender", "session", id, "peer", peer, "error", err)
		}
		if err := r.persistSession(peer, ps); err != nil {
			logger.Warn("could not persist peer session", "session", id, "peer", peer, "error", err)
		}
	})
	if err := r.restoreSessions(); err != nil {
		return nil, fmt.Errorf("cmd/whatscore: session %s: restore sessions: %w", id, err)
	}

	// Delivery receipts follow the decrypt, not the stanza: the server keeps
	// a message it has no receipt for, so a failed decrypt can be recovered
	// instead of erased (the probe learned this the hard way).
	if bus != nil {
		sub := bus.Subscribe()
		go r.receiptLoop(sub)
	}
	return r, nil
}

// attach gives the runtime its write path. Called once, after the session
// exists: the session needs the handler first, the handler needs the session
// to write.
func (r *sessionRuntime) attach(sess writeFrameSession) {
	r.muWrite.Do(func() {
		r.write = sess.WriteFrame
	})
}

// writeFrameSession is the slice of *session.Session the runtime needs.
type writeFrameSession interface {
	WriteFrame(ctx context.Context, frame []byte) error
}

// runtimeWrite adapts the runtime's write path to core/messaging.FrameWriter.
// The writer is registered at attach time; before that, writes fail.
type runtimeWrite struct {
	r *sessionRuntime
}

func (w *runtimeWrite) WriteFrame(ctx context.Context, frame []byte) error {
	if w.r == nil || w.r.write == nil {
		return fmt.Errorf("runtime not attached to a session")
	}
	return w.r.write(ctx, frame)
}

// runtimeBundles serves peer prekey bundles from the runtime's iq path.
type runtimeBundles struct {
	r *sessionRuntime
}

func (b *runtimeBundles) PreKeyBundle(ctx context.Context, peer string) (*signal.PreKeyBundle, error) {
	if b.r == nil {
		return nil, fmt.Errorf("runtime not attached to a session")
	}
	return b.r.fetchPreKeyBundle(ctx, peer)
}

// receiptLoop answers every successfully decrypted message with a delivery
// receipt, until the bus closes (process shutdown) or the runtime stops.
func (r *sessionRuntime) receiptLoop(sub *events.Subscription) {
	defer sub.Close()
	for {
		select {
		case <-r.stop:
			return
		case ev, ok := <-sub.C:
			if !ok {
				return
			}
			if ev.SessionID != r.id {
				continue
			}
			if ev.Type == events.TypeConnected {
				r.markConnected()
				continue
			}
			if ev.Type != events.TypeMessage || ev.Message == nil {
				continue
			}
			if ev.Message.Protocol != nil && len(ev.Message.Protocol.AppKeys) > 0 {
				r.storeAppStateKeys(ev.Message.Protocol.AppKeys)
			}
			if ev.Message.Protocol != nil && ev.Message.Protocol.HistorySync {
				// The ack the phone's "keep both apps open" phase waits for:
				// history messages are acknowledged with type=hist_sync
				// (Baileys messages-recv.ts), not the delivery receipt.
				r.sendHistSyncReceipt(ev.Message.ID, ev.Message.Sender)
			} else if ev.Message.Media == nil && ev.Message.Direction != events.DirectionOutgoing {
				// A device-sent copy is this account's own message mirrored
				// from another device: there is nobody to receipt but
				// ourselves.
				r.sendDeliveryReceipt(ev.Message.ID, ev.Message.Sender)
			}
			if m := ev.Message.Media; m != nil {
				// The download must never block the event loop: one goroutine
				// per attachment, deduped by message id.
				r.mu.Lock()
				seen := r.mediaSaved[ev.Message.ID]
				if !seen {
					r.mediaSaved[ev.Message.ID] = true
				}
				r.mu.Unlock()
				if !seen {
					go r.handleMediaEvent(ev.Message.ID, m)
				}
			}
		}
	}
}

// HandleFrame decodes and routes one inbound frame. Decode failures are
// logged, not fatal: one garbled stanza must not tear the session down.
func (r *sessionRuntime) HandleFrame(ctx context.Context, frame []byte) error {
	node, err := r.codec.Decode(bytes.NewReader(frame))
	if err != nil {
		r.logger.Warn("undecodable stanza", "session", r.id, "bytes", len(frame), "error", err)
		return nil
	}
	// Trace at debug so an operator can see everything the server received.
	r.logger.Debug("stanza", "session", r.id, "tag", node.Tag, "from", node.Attrs["from"], "type", node.Attrs["type"])

	if node.Tag == "iq" && node.Attrs["id"] != "" {
		if r.deliverWaiter(node) {
			return nil
		}
	}
	switch node.Tag {
	case "ib":
		r.handleIB(ctx, node)
		return nil
	case "iq":
		if node.Attrs["xmlns"] == "urn:xmpp:ping" {
			r.answerPing(ctx, node)
			return nil
		}
	}
	return r.receiver.HandleFrame(ctx, frame)
}

// handleIB keeps the connection's server-side bookkeeping alive: answer the
// offline queue announcement (PF-087) and drain markers.
func (r *sessionRuntime) handleIB(ctx context.Context, node *binary.Node) {
	if child(node, "offline_preview") != nil {
		// The queue stays frozen until the client names a batch size.
		batch := &binary.Node{Tag: "ib", Children: []binary.Node{{
			Tag: "offline_batch", Attrs: binary.Attrs{"count": "100"},
		}}}
		if err := r.writeNode(ctx, batch); err != nil {
			r.logger.Warn("offline batch request failed", "session", r.id, "error", err)
		} else {
			r.logger.Info("offline batch requested", "session", r.id)
		}
	}
	if child(node, "offline") != nil {
		r.logger.Info("offline queue drained", "session", r.id)
	}
}

// answerPing replies to the server's keepalive.
func (r *sessionRuntime) answerPing(ctx context.Context, node *binary.Node) {
	pong := &binary.Node{
		Tag: "iq", Attrs: binary.Attrs{"to": serverJID, "type": "result", "id": node.Attrs["id"]},
	}
	if err := r.writeNode(ctx, pong); err != nil {
		r.logger.Warn("ping answer failed", "session", r.id, "error", err)
	}
}

// deliverWaiter resolves an iq wait, if one is registered for the id.
func (r *sessionRuntime) deliverWaiter(node *binary.Node) bool {
	r.mu.Lock()
	waiter, ok := r.waiters[node.Attrs["id"]]
	if ok {
		delete(r.waiters, node.Attrs["id"])
	}
	r.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case waiter <- node:
	default:
	}
	return true
}

// request writes an iq and waits for the reply with the same id. The write
// and the read share the session's write lock through WriteFrame, and the
// dispatcher semantics are the probe's: a reply with no waiter, or a waiter
// with no reply, is logged and dropped rather than fatal.
func (r *sessionRuntime) request(ctx context.Context, node *binary.Node, timeout time.Duration) (*binary.Node, error) {
	if node.Tag != "iq" || node.Attrs["id"] == "" {
		return nil, fmt.Errorf("runtime request needs an iq with an id")
	}
	waiter := make(chan *binary.Node, 1)
	r.mu.Lock()
	r.waiters[node.Attrs["id"]] = waiter
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.waiters, node.Attrs["id"])
		r.mu.Unlock()
	}()

	if err := r.writeNode(ctx, node); err != nil {
		return nil, fmt.Errorf("send iq: %w", err)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case reply := <-waiter:
		if reply.Attrs["type"] == "error" {
			return nil, fmt.Errorf("server rejected iq %s", node.Attrs["id"])
		}
		return reply, nil
	case <-timer.C:
		return nil, fmt.Errorf("no reply to iq %s within %s", node.Attrs["id"], timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// child returns the first child of node with tag, or nil.
func child(node *binary.Node, tag string) *binary.Node {
	for i := range node.Children {
		if node.Children[i].Tag == tag {
			return &node.Children[i]
		}
	}
	return nil
}

// writeNode writes through the attached session. Before attach, or while the
// session is disconnected, it fails without side effects.
func (r *sessionRuntime) writeNode(ctx context.Context, node *binary.Node) error {
	if r.write == nil {
		return fmt.Errorf("runtime not attached to a session")
	}
	frame, err := r.codec.Encode(node)
	if err != nil {
		return fmt.Errorf("encode %q: %w", node.Tag, err)
	}
	return r.write(ctx, frame)
}

// markConnected runs the post-connect sequence once per process per
// connection: mark the device active (PF-084), publish presence (live fan-out
// never starts without it), and top up the one-time prekey pool (PF-082
// re-tested: the server accepts the upload silently).
func (r *sessionRuntime) markConnected() {
	r.connectedOnce.Do(func() {
		go r.runConnectSequence()
	})
}

func (r *sessionRuntime) runConnectSequence() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	active := &binary.Node{
		Tag: "iq", Attrs: binary.Attrs{
			"to": serverJID, "type": "set", "xmlns": "passive", "id": r.newRequestID(),
		},
		Children: []binary.Node{{Tag: "active"}},
	}
	if _, err := r.request(ctx, active, 20*time.Second); err != nil {
		r.logger.Warn("mark active failed", "session", r.id, "error", err)
	} else {
		r.logger.Info("session active", "session", r.id)
	}

	presence := &binary.Node{Tag: "presence", Attrs: binary.Attrs{"type": "available", "name": "whatscore"}}
	if err := r.writeNode(ctx, presence); err != nil {
		r.logger.Warn("presence failed", "session", r.id, "error", err)
	}

	// The app state sync request is what starts provisioning: the server
	// answers with patches (and pushes key shares when needed). WhatsApp Web
	// requests these right after login; skipping it leaves the phone in the
	// "keep both apps open" phase indefinitely.
	r.requestAppStateSync(ctx)

	r.topUpPreKeys(ctx)
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

// requestAppStateSync fetches the app state patches for every collection.
// A fresh device has no stored versions, so every collection asks for a
// snapshot; mutations verify against the shared app state keys.
func (r *sessionRuntime) requestAppStateSync(ctx context.Context) {
	r.appStateKeysMu.Lock()
	keyCount := len(r.appStateKeys)
	r.appStateKeysMu.Unlock()
	if keyCount == 0 {
		// Without keys the patch MACs cannot be verified. The key shares
		// arrive as protocol messages; ask the server anyway — it pushes
		// shares when the request arrives.
		r.logger.Info("app state sync: no keys yet; requesting anyway", "session", r.id)
	}

	collections := make([]binary.Node, 0, len(appStateCollections))
	for _, name := range appStateCollections {
		collections = append(collections, binary.Node{
			Tag: "collection",
			Attrs: binary.Attrs{
				"name":            name,
				"return_snapshot": "true",
			},
		})
	}
	reply, err := r.request(ctx, &binary.Node{
		Tag: "iq",
		Attrs: binary.Attrs{
			"to": serverJID, "type": "set", "xmlns": "w:sync:app:state", "id": r.newRequestID(),
		},
		Children: []binary.Node{{Tag: "sync", Children: collections}},
	}, 30*time.Second)
	if err != nil {
		r.logger.Warn("app state sync request failed", "session", r.id, "error", err)
		return
	}
	syncNode := child(reply, "sync")
	if syncNode == nil {
		r.logger.Warn("app state reply has no <sync>", "session", r.id, "children", len(reply.Children))
		return
	}
	patches, err := syncpkg.ParsePatches(syncNode)
	if err != nil {
		r.logger.Warn("app state patches unreadable", "session", r.id, "error", err)
		return
	}
	decoded, skipped := 0, 0
	for _, patch := range patches {
		for _, mutation := range patch.Mutations {
			r.appStateKeysMu.Lock()
			key, ok := r.appStateKeys[hex.EncodeToString(mutation.KeyID)]
			r.appStateKeysMu.Unlock()
			if !ok {
				skipped++
				continue
			}
			expanded, err := syncpkg.ExpandKeys(key)
			if err != nil {
				continue
			}
			if _, err := syncpkg.DecodeMutation(mutation, expanded); err != nil {
				r.logger.Warn("mutation decode failed", "session", r.id, "error", err)
				continue
			}
			decoded++
		}
	}
	r.logger.Info("app state sync fetched", "session", r.id, "patches", len(patches), "decoded", decoded, "skipped-no-key", skipped)
}

// topUpPreKeys generates whatever the pool lacks and uploads the delta. The
// upload is answered with silence by design (PF-082); the count query is the
// only verdict, and it is advisory here — a silent upload has been observed
// landing anyway.
func (r *sessionRuntime) topUpPreKeys(ctx context.Context) {
	if err := r.preKeys.Replenish(ctx, 50); err != nil {
		r.logger.Warn("prekey replenish failed", "session", r.id, "error", err)
		return
	}
	pool := r.preKeys.OneTimePreKeys()
	var delta []prekeysSnapshot
	r.mu.Lock()
	for _, key := range pool {
		if !r.uploaded[key.ID] {
			delta = append(delta, prekeysSnapshot{id: key.ID, pub: key.Pair.Public})
			r.uploaded[key.ID] = true
		}
	}
	r.mu.Unlock()
	if len(delta) == 0 {
		return
	}
	bundle := r.preKeys.Bundle(false)
	upload := &binary.Node{
		Tag: "iq",
		Attrs: binary.Attrs{
			"to": serverJID, "type": "set", "xmlns": "encrypt", "id": r.newRequestID(),
		},
		Children: uploadChildren(r.registrationID, bundle.SignedPreKeyID, bundle.SignedPreKey, bundle.SignedPreKeySignature, delta),
	}
	// Silence is not fatal; the server never answers a repeat upload.
	if _, err := r.request(ctx, upload, 20*time.Second); err != nil {
		r.logger.Info("prekey upload not acknowledged", "session", r.id, "count", len(delta), "error", err)
	} else {
		r.logger.Info("prekeys uploaded", "session", r.id, "count", len(delta))
	}
}

// prekeysSnapshot is one uploadable one-time prekey.
type prekeysSnapshot struct {
	id  uint32
	pub [32]byte
}

// uploadChildren builds <registration><skey><key…> for the encrypt iq. Key
// ids ride as 3 bytes (PF-082).
func uploadChildren(registrationID uint32, signedID uint32, signedPub [32]byte, signature []byte, keys []prekeysSnapshot) []binary.Node {
	reg := []byte{byte(registrationID >> 24), byte(registrationID >> 16), byte(registrationID >> 8), byte(registrationID)}
	list := make([]binary.Node, 0, len(keys))
	for _, key := range keys {
		list = append(list, binary.Node{
			Tag: "key",
			Children: []binary.Node{
				{Tag: "id", Bytes: []byte{byte(key.id >> 16), byte(key.id >> 8), byte(key.id)}},
				{Tag: "value", Bytes: key.pub[:]},
			},
		})
	}
	var signedIDBytes [3]byte
	signedIDBytes[0] = byte(signedID >> 16)
	signedIDBytes[1] = byte(signedID >> 8)
	signedIDBytes[2] = byte(signedID)
	return []binary.Node{
		{Tag: "registration", Bytes: reg},
		{Tag: "skey", Children: []binary.Node{
			{Tag: "id", Bytes: signedIDBytes[:]},
			{Tag: "value", Bytes: signedPub[:]},
			{Tag: "signature", Bytes: signature},
		}},
		{Tag: "list", Children: list},
	}
}

// sendRetryReceipt answers an undecryptable message with the retry receipt
// (whatsmeow retry.go / Baileys messages-recv.ts shape), capped at three per
// message id.
func (r *sessionRuntime) sendRetryReceipt(node *binary.Node) {
	id := node.Attrs["id"]
	from := node.Attrs["from"]
	if id == "" || from == "" || r.write == nil {
		return
	}
	r.mu.Lock()
	r.retries[id]++
	count := r.retries[id]
	r.mu.Unlock()
	if count > 3 {
		return
	}

	// The inline keys block: a fresh one-time prekey, the signed prekey, the
	// identity key, and the device identity. Without it the sender re-encrypts
	// with the cached bundle — the very bundle that produced the failure.
	fresh := r.preKeys.OneTimePreKeys()
	var prekey *prekeysSnapshot
	r.mu.Lock()
	for i := range fresh {
		if !r.uploaded[fresh[i].ID] {
			prekey = &prekeysSnapshot{id: fresh[i].ID, pub: fresh[i].Pair.Public}
			r.uploaded[fresh[i].ID] = true
			break
		}
	}
	r.mu.Unlock()

	receipt := &binary.Node{
		Tag:   "receipt",
		Attrs: binary.Attrs{"id": id, "to": from, "type": "retry"},
		Children: []binary.Node{
			{Tag: "retry", Attrs: binary.Attrs{
				"count": strconv.Itoa(count), "id": id, "t": node.Attrs["t"], "v": "1", "error": "0",
			}},
			{Tag: "registration", Bytes: []byte{
				byte(r.registrationID >> 24), byte(r.registrationID >> 16), byte(r.registrationID >> 8), byte(r.registrationID),
			}},
		},
	}
	if prekey != nil {
		bundle := r.preKeys.Bundle(false)
		children := []binary.Node{
			{Tag: "type", Bytes: []byte{5}},
			{Tag: "identity", Bytes: r.identity.Public[:]},
			{Tag: "key", Children: []binary.Node{
				{Tag: "id", Bytes: []byte{byte(prekey.id >> 16), byte(prekey.id >> 8), byte(prekey.id)}},
				{Tag: "value", Bytes: prekey.pub[:]},
			}},
			{Tag: "skey", Children: []binary.Node{
				{Tag: "id", Bytes: []byte{byte(bundle.SignedPreKeyID >> 16), byte(bundle.SignedPreKeyID >> 8), byte(bundle.SignedPreKeyID)}},
				{Tag: "value", Bytes: bundle.SignedPreKey[:]},
				{Tag: "signature", Bytes: bundle.SignedPreKeySignature},
			}},
			// The device identity blob: pairing stored it in the vault.
			{Tag: "device-identity", Bytes: r.deviceIdentityBlob()},
		}
		receipt.Children = append(receipt.Children, binary.Node{Tag: "keys", Children: children})
	}
	if err := r.writeNode(context.Background(), receipt); err != nil {
		r.logger.Warn("retry receipt failed", "session", r.id, "error", err)
	} else {
		r.logger.Info("retry receipt sent", "session", r.id, "message", id, "attempt", count)
	}
}

// deviceIdentityBlob returns the stored pairing device identity, or nil when
// the session has not paired yet (retry receipts without it are still valid;
// Baileys sends them both ways).
func (r *sessionRuntime) deviceIdentityBlob() []byte {
	return r.deviceIdentity
}

// storeAppStateKeys keeps the phone-shared keys for patch verification and
// persists them across restarts next to the session store.
func (r *sessionRuntime) storeAppStateKeys(keys map[string][]byte) {
	r.appStateKeysMu.Lock()
	added := 0
	for id, data := range keys {
		if _, exists := r.appStateKeys[id]; !exists {
			r.appStateKeys[id] = append([]byte(nil), data...)
			added++
		}
	}
	r.appStateKeysMu.Unlock()
	if added > 0 {
		r.logger.Info("app state keys stored", "session", r.id, "count", added)
		if err := r.persistAppStateKeys(); err != nil {
			r.logger.Warn("could not persist app state keys", "session", r.id, "error", err)
		}
	}
}

// persistAppStateKeys writes the key map into the encrypted vault. These are
// keys the phone shared so this device can verify patches; a plaintext file
// beside the process would undo the vault every other secret goes through.
func (r *sessionRuntime) persistAppStateKeys() error {
	if r.appStateKey == "" || r.secrets == nil {
		return nil
	}
	r.appStateKeysMu.Lock()
	defer r.appStateKeysMu.Unlock()
	blob, err := json.Marshal(r.appStateKeys)
	if err != nil {
		return err
	}
	return r.secrets.Put(context.Background(), r.appStateKey, blob)
}

// loadAppStateKeys restores persisted keys at construction time.
func (r *sessionRuntime) loadAppStateKeys() {
	if r.appStateKey == "" || r.secrets == nil {
		return
	}
	blob, err := r.secrets.Get(context.Background(), r.appStateKey)
	if err != nil {
		// Nothing stored yet is the normal first-run case.
		if !errors.Is(err, storagecredentials.ErrNotFound) {
			r.logger.Warn("app state keys unreadable", "session", r.id, "error", err)
		}
		return
	}
	var keys map[string][]byte
	if err := json.Unmarshal(blob, &keys); err != nil {
		r.logger.Warn("app state key file unreadable", "session", r.id, "error", err)
		return
	}
	r.appStateKeysMu.Lock()
	r.appStateKeys = keys
	r.appStateKeysMu.Unlock()
	r.logger.Info("app state keys restored", "session", r.id, "count", len(keys))
}

// sendHistSyncReceipt acknowledges one history chunk. Without it the phone
// holds the "keep both apps open" banner indefinitely: the device never
// tells the server the chunk arrived.
func (r *sessionRuntime) sendHistSyncReceipt(id, from string) {
	if id == "" || from == "" || r.write == nil {
		return
	}
	receipt := &binary.Node{
		Tag:   "receipt",
		Attrs: binary.Attrs{"id": id, "to": from, "type": "hist_sync"},
	}
	if err := r.writeNode(context.Background(), receipt); err != nil {
		r.logger.Warn("hist_sync receipt failed", "session", r.id, "error", err)
	} else {
		r.logger.Info("hist_sync receipt sent", "session", r.id, "message", id)
	}
}

// sendDeliveryReceipt confirms one decrypted message to the sender.
func (r *sessionRuntime) sendDeliveryReceipt(id, from string) {
	if id == "" || from == "" || r.write == nil {
		return
	}
	receipt := &binary.Node{Tag: "receipt", Attrs: binary.Attrs{"id": id, "to": from}}
	if err := r.writeNode(context.Background(), receipt); err != nil {
		r.logger.Debug("delivery receipt failed", "session", r.id, "error", err)
	} else {
		r.logger.Debug("delivery receipt sent", "session", r.id, "message", id)
	}
}

func (r *sessionRuntime) newRequestID() string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Randomness is cosmetic for request ids; a counter would do.
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return strconv.FormatUint(uint64(buf[0])<<24|uint64(buf[1])<<16|uint64(buf[2])<<8|uint64(buf[3]), 10)
}

// DeliverText sends one text message. On an established session it continues
// the ratchet; on first contact it fetches the peer's bundle and initiates a
// prekey session, which is also installed for inbound decryption — the peer's
// next message rides the same chain.
func (r *sessionRuntime) DeliverText(ctx context.Context, to, text string) (string, error) {
	if r.write == nil {
		return "", fmt.Errorf("session %s: runtime not attached", r.id)
	}
	id, session, err := r.sender.SendEncryptedText(ctx, to, text)
	if errors.Is(err, coremessaging.ErrNoSession) {
		var peerSession *coremessaging.PeerSession
		id, peerSession, err = r.sender.SendPreKeyText(ctx, to, text, r.registrationID)
		if err == nil && peerSession != nil {
			// The initiator holds the same chain the peer's replies will ride.
			if err := r.receiver.SetReceiverPeer(to, peerSession); err != nil {
				r.logger.Warn("could not install the initiator session for inbound", "session", r.id, "peer", to, "error", err)
			}
			session = peerSession
		}
	}
	if err != nil {
		return "", fmt.Errorf("session %s: deliver: %w", r.id, err)
	}
	// The send advanced the ratchet and no observer fires for it: a restart
	// that reads the old state would encrypt from a chain the peer has left.
	if err := r.persistSession(to, session); err != nil {
		r.logger.Warn("could not persist the session after sending", "session", r.id, "peer", to, "error", err)
	}
	// The own-device copy is what makes the send appear on the phone. It is
	// best effort: the recipient's copy is already on the wire, and a phone
	// this device has never heard from has no ratchet to ride.
	r.sendOwnDeviceCopy(ctx, to, id, text)
	return id, nil
}

// restoreSessions loads every persisted peer ratchet into the receiver and
// the sender, so a restart continues the conversations the last process had
// instead of re-initiating them (which spends a prekey and orphans the chain
// the peer is answering on).
func (r *sessionRuntime) restoreSessions() error {
	if r.signals == nil {
		return nil
	}
	stored, err := r.signals.loadAll(context.Background())
	if err != nil {
		return err
	}
	restored := 0
	for peer, ps := range stored {
		if err := r.receiver.SetReceiverPeer(peer, ps); err != nil {
			return fmt.Errorf("install %s: %w", peer, err)
		}
		if err := r.sender.SetPeer(peer, ps); err != nil {
			return fmt.Errorf("install %s: %w", peer, err)
		}
		restored++
	}
	if restored > 0 {
		r.logger.Info("peer sessions restored", "session", r.id, "count", restored)
	}
	return nil
}

// persistSession writes one peer ratchet to the encrypted store.
func (r *sessionRuntime) persistSession(peer string, ps *coremessaging.PeerSession) error {
	if r.signals == nil || ps == nil || ps.State == nil {
		return nil
	}
	return r.signals.save(context.Background(), peer, ps)
}

// phonePeerFor finds the stored peer that belongs to the phone: its JID user
// matches the account's LID user, because the LID is account-scoped while the
// device suffix differs per device. An empty result means the phone has never
// written to this device, so no ratchet exists to carry the own-device copy.
func phonePeerFor(ownLID string, peers []string) string {
	if ownLID == "" {
		return ""
	}
	want := jidUser(ownLID)
	if want == "" {
		return ""
	}
	for _, peer := range peers {
		if jidUser(peer) == want {
			return peer
		}
	}
	return ""
}

// jidUser returns the user part of a JID, without the device or the server.
func jidUser(jid string) string {
	user := jid
	if at := strings.Index(user, "@"); at >= 0 {
		user = user[:at]
	}
	if colon := strings.Index(user, ":"); colon >= 0 {
		user = user[:colon]
	}
	return user
}

// sendOwnDeviceCopy sends the DeviceSentMessage copy of a 1:1 send to the
// phone, over the ratchet the phone's own messages bootstrapped. The copy
// carries the recipient copy's id — one logical message, two ciphertexts —
// so the phone renders one message in the destination chat as outgoing.
//
// A device that has never heard from the phone has no ratchet to ride, and the
// server serves no bundle for the account's own devices: the copy is skipped,
// not failed, and the recipient's copy has already gone out.
func (r *sessionRuntime) sendOwnDeviceCopy(ctx context.Context, to, id, text string) {
	if r.signals == nil || r.ownLID == "" {
		return
	}
	// A send to the account itself already reaches the phone as the
	// recipient's copy; a second copy would show the same message twice in
	// the self chat.
	if jidUser(to) == jidUser(r.ownLID) {
		return
	}
	peers, err := r.signals.peers(ctx)
	if err != nil {
		r.logger.Warn("could not list peers for the own-device copy", "session", r.id, "error", err)
		return
	}
	phone := phonePeerFor(r.ownLID, peers)
	if phone == "" {
		r.logger.Debug("no phone session; own-device copy skipped", "session", r.id)
		return
	}
	if phone == to {
		return
	}
	payload, err := stanza.EncodeDeviceSentMessage(to, text)
	if err != nil {
		r.logger.Warn("could not build the own-device copy", "session", r.id, "error", err)
		return
	}
	copyID, session, err := r.sender.SendEncryptedPayloadWithID(ctx, phone, id, payload)
	if err != nil {
		r.logger.Warn("own-device copy failed", "session", r.id, "phone", phone, "error", err)
		return
	}
	if err := r.persistSession(phone, session); err != nil {
		r.logger.Warn("could not persist the phone session after the copy", "session", r.id, "error", err)
	}
	r.logger.Info("own-device copy sent", "session", r.id, "id", copyID, "phone", phone)
}
