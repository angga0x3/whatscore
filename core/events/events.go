// Package events defines the normalized, protocol-neutral event taxonomy for
// WhatsCore and an in-process publish/subscribe bus.
//
// The bus is deliberately small: publishers call Publish, subscribers receive
// from a channel, and the bus never interprets event payloads. Protocol types
// must not appear in event values; sessions translate wire activity into the
// types defined here before publishing (technical specification §4.14).
//
// Guarantees:
//
//   - Ordering: events reach every subscriber in the order Publish accepted
//     them. Because one session is owned by one actor (§2 decision 3), the
//     events of a session are therefore delivered in the order the actor
//     produced them.
//   - Non-blocking fan-out: Publish never waits for a subscriber.
//   - Isolation: a slow or stalled subscriber cannot delay a publisher or
//     other subscribers.
//
// Slow subscribers: every subscription has a bounded buffer (DefaultBuffer
// unless WithBuffer overrides it). When a subscriber's buffer is full, the
// event is dropped for that subscriber only and its dropped counter is
// incremented; callers can read the counter through Subscription.Dropped.
// Gaps between the Seq values a subscription receives mean it dropped events
// or subscribed after earlier events were published.
package events

import (
	"sync"
	"sync/atomic"
	"time"
)

// Type identifies one kind of normalized event. Values are stable strings;
// transport and API adapters map them to their own wire names (for example the
// REST event catalog), which keeps core/events protocol-neutral.
type Type string

const (
	// TypeConnected reports that a transport connection was established.
	TypeConnected Type = "connected"
	// TypeDisconnected reports that the session lost or closed its connection.
	TypeDisconnected Type = "disconnected"
	// TypePairingCode reports a fresh pairing code available to the caller.
	TypePairingCode Type = "pairing_code"
	// TypeMessage reports an inbound or outbound message.
	TypeMessage Type = "message"
	// TypeReceipt reports a delivery, read, or played receipt.
	TypeReceipt Type = "receipt"
	// TypeGroupUpdate reports a group membership or metadata change.
	TypeGroupUpdate Type = "group_update"
	// TypeError reports a session operation failure. It is not emitted for
	// events that merely describe a failure, such as Disconnected.
	TypeError Type = "error"
)

// DefaultBuffer is the per-subscriber buffer size used by NewBus when no
// WithBuffer option is supplied.
const DefaultBuffer = 64

// Direction describes whether a message is inbound or outbound.
type Direction string

const (
	// DirectionIncoming marks a message received by this session.
	DirectionIncoming Direction = "incoming"
	// DirectionOutgoing marks a message sent by this session.
	DirectionOutgoing Direction = "outgoing"
)

// ReceiptStatus is the normalized state reported by a receipt.
type ReceiptStatus string

const (
	// ReceiptDelivered means the message reached the recipient's device.
	ReceiptDelivered ReceiptStatus = "delivered"
	// ReceiptRead means the recipient read the message.
	ReceiptRead ReceiptStatus = "read"
	// ReceiptPlayed means a voice or video message was played.
	ReceiptPlayed ReceiptStatus = "played"
)

// GroupChange identifies the kind of group update.
type GroupChange string

const (
	// GroupJoined means this session joined the group.
	GroupJoined GroupChange = "joined"
	// GroupLeft means this session or another participant left the group.
	GroupLeft GroupChange = "left"
	// GroupParticipantsAdded means participants were added.
	GroupParticipantsAdded GroupChange = "participants_added"
	// GroupParticipantsRemoved means participants were removed.
	GroupParticipantsRemoved GroupChange = "participants_removed"
	// GroupMetadataChanged means the subject, description, or settings changed.
	GroupMetadataChanged GroupChange = "metadata_changed"
)

// Event is one normalized session event. Type selects which payload field is
// non-nil; all other payload fields are nil.
//
// Event values and their payloads are read-only once published. The same
// value is fanned out to every subscriber, so a subscriber must not mutate a
// payload or a slice it contains.
type Event struct {
	Type      Type
	SessionID string
	// Timestamp is when the event was published. Publish fills it when zero.
	Timestamp time.Time
	// Seq is assigned by Bus.Publish and increases monotonically per bus.
	// Gaps mean the receiving subscriber dropped events or joined later (see
	// the package documentation on slow subscribers).
	Seq uint64

	Connected    *Connected
	Disconnected *Disconnected
	PairingCode  *PairingCode
	Message      *Message
	Receipt      *Receipt
	GroupUpdate  *GroupUpdate
	Error        *SessionError
}

// Connected announces an established connection. Reconnected is true when the
// session had been connected at least once before this event.
type Connected struct {
	Reconnected bool
}

// Disconnected announces a lost or closed connection. Reason is the transport
// error that caused the disconnect, ErrSessionClosed for shutdown, or nil when
// the caller requested it. WillReconnect reports whether the session intends to
// reconnect.
type Disconnected struct {
	Reason        error
	WillReconnect bool
}

// PairingCode carries a pairing code. Code values are short-lived credentials:
// callers must not log them.
type PairingCode struct {
	Code    string
	Expires time.Time
}

// Message is a normalized inbound or outbound message. It carries plaintext
// and identifiers only; no protocol node, ciphertext, or ratchet state.
type Message struct {
	ID        string
	Chat      string
	Sender    string
	Timestamp time.Time
	Direction Direction
	Text      string
	IsGroup   bool
	// Media is set when the message carries an attachment (image, sticker,
	// video, audio, document). Text is then its caption, if any.
	Media *MediaAttachment
	// Protocol is set on server-driven control messages (history sync
	// notifications, ephemeral settings). History sync ones must be
	// acknowledged with a hist_sync receipt.
	Protocol *ProtocolInfo
}

// ProtocolInfo mirrors a decrypted protocol message. HistorySync carries the
// CDN metadata of one history chunk; the ack for it is what the phone's
// "keep both apps open" phase waits for.
type ProtocolInfo struct {
	Type string
	// HistorySync marks a history-sync notification: the receipt it needs is
	// type=hist_sync, not the delivery receipt.
	HistorySync bool
	// AppKeys carries the app state sync keys from a key share, keyed by hex
	// key id.
	AppKeys map[string][]byte
}

// MediaAttachment carries everything a downloader needs to fetch and open one
// media item: the HKDF key type the mediaKey expands under, the digests the
// blob is verified against, and the direct path the CDN serves it from.
type MediaAttachment struct {
	Kind              string // "image", "sticker", "video", "audio", "document"
	MimeType          string
	Caption           string
	FileName          string
	FileLength        uint64
	MediaKey          []byte
	FileSHA256        []byte
	FileEncSHA256     []byte
	DirectPath        string
	MediaKeyTimestamp int64
	// KeysType is the HKDF info string for the media key ("WhatsApp Image
	// Keys" and friends); stickers expand under the image keys.
	KeysType string
}

// Receipt is a normalized receipt for a previously observed message.
type Receipt struct {
	MessageID string
	Chat      string
	Sender    string
	Status    ReceiptStatus
	Timestamp time.Time
}

// GroupUpdate describes a group membership or metadata change. Participants
// lists the subjects of the change, not the whole group.
type GroupUpdate struct {
	GroupID      string
	Change       GroupChange
	Actor        string
	Participants []string
}

// SessionError reports a failed session operation. Op names the operation
// (for example "connect" or "read"), Err is the underlying cause, and Fatal
// reports whether the session gave up instead of retrying.
type SessionError struct {
	Op    string
	Err   error
	Fatal bool
}

// Option configures a Bus.
type Option func(*Bus)

// WithBuffer sets the per-subscriber event buffer. Non-positive sizes are
// ignored; DefaultBuffer remains in effect.
func WithBuffer(size int) Option {
	return func(b *Bus) {
		if size > 0 {
			b.buffer = size
		}
	}
}

// Bus is a concurrency-safe in-process fan-out of Event values.
//
// Publish serializes the fan-out under a mutex, which is what gives every
// subscriber the same order. The per-subscriber sends are non-blocking, so the
// critical section never waits on a subscriber. The zero value is not usable;
// call NewBus.
type Bus struct {
	mu      sync.Mutex
	closed  bool
	nextSeq uint64
	buffer  int
	subs    map[*Subscription]struct{}
}

// NewBus returns a ready-to-use Bus. It is safe for concurrent use.
func NewBus(opts ...Option) *Bus {
	b := &Bus{
		buffer: DefaultBuffer,
		subs:   make(map[*Subscription]struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(b)
		}
	}
	return b
}

// Subscribe registers a new subscriber. The returned subscription's channel
// is closed by Unsubscribe, Subscription.Close, or Bus.Close.
//
// Subscribe after Close returns an already-closed subscription rather than
// failing, so callers can use a uniform receive loop.
func (b *Bus) Subscribe() *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan Event, b.buffer)
	sub := &Subscription{C: ch, ch: ch, bus: b}
	if b.closed {
		close(ch)
		return sub
	}
	b.subs[sub] = struct{}{}
	return sub
}

// Unsubscribe removes sub and closes its channel. It is idempotent and safe to
// call concurrently with Publish and Close. A nil or foreign subscription is
// ignored.
func (b *Bus) Unsubscribe(sub *Subscription) {
	if sub == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if sub.bus != b {
		return
	}
	if _, ok := b.subs[sub]; !ok {
		return
	}
	delete(b.subs, sub)
	close(sub.ch)
}

// Publish delivers ev to every current subscriber without blocking. It stamps
// ev.Seq (overwriting any prior value) and fills ev.Timestamp when zero.
//
// If a subscriber's buffer is full, ev is dropped for that subscriber and its
// dropped counter is incremented. Publishing after Close is a no-op.
func (b *Bus) Publish(ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	b.nextSeq++
	ev.Seq = b.nextSeq
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}

	for sub := range b.subs {
		select {
		case sub.ch <- ev:
		default:
			sub.dropped.Add(1)
		}
	}
}

// Close closes every subscription channel and rejects further publishes. It
// is idempotent. Subscriptions that were already closed by Unsubscribe are
// unaffected.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}
	b.closed = true
	for sub := range b.subs {
		delete(b.subs, sub)
		close(sub.ch)
	}
}

// Subscription is one subscriber's view of the bus. C is closed when the
// subscription ends, so a range loop terminates without extra coordination.
type Subscription struct {
	// C is the receive side of the subscription.
	C <-chan Event

	ch      chan Event
	bus     *Bus
	dropped atomic.Uint64
}

// Close unsubscribes. It is equivalent to Bus.Unsubscribe and is idempotent.
func (s *Subscription) Close() {
	if s == nil {
		return
	}
	s.bus.Unsubscribe(s)
}

// Dropped reports how many events were dropped for this subscriber because
// its buffer was full.
func (s *Subscription) Dropped() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}
