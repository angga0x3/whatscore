package api

// Messaging routes: send text, list messages, read one message.
//
// Contract notes:
//
//   - Delivery is not implemented. POST .../messages/text validates the body,
//     requires a CONNECTED session, records the message in the message store,
//     and answers 202 {"message_id": "...", "status": "queued"}. No WhatsApp
//     frame leaves the process yet; the 202 is a queue acknowledgement, not a
//     send confirmation.
//   - A session that exists but is not CONNECTED is 503 session_not_connected.
//     The OpenAPI contract says 409 for that case; 503 is deliberate (the
//     dependency, an active session, is unavailable), and clients should
//     retry after connecting.
//   - MessageView is the read shape. It carries the contract's id, session_id,
//     chat_id, direction, type, text, and created_at; status,
//     provider_message_id, payload, and updated_at are not tracked yet, and
//     text is top-level rather than nested under payload.
//   - Idempotency-Key is scoped to (session, key). The same key with the same
//     semantic body replays the stored 202 byte for byte; the same key with a
//     different body is 409 idempotency_conflict. Failed requests are not
//     cached, so a retry after connecting the session can succeed.
//
// Architecture: this file depends on the Service interface and the local
// MessageLister/MessageAppender/MessageGetter boundaries only. It must not
// import protocol/** or core/messaging.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	// DefaultMessageCapacity is the per-session ring-buffer size of
	// MemoryMessageStore.
	DefaultMessageCapacity = 1000
	// maxMessageTextBytes matches the OpenAPI SendTextRequest maxLength.
	maxMessageTextBytes = 65536
	// maxTextBodyBytes bounds the request body. JSON escaping can expand a
	// maximum-length text (up to \u00XX per rune), so the limit leaves room
	// for that instead of rejecting a valid 65536-byte text.
	maxTextBodyBytes = 6*maxMessageTextBytes + 4<<10
	// maxIdempotencyKeyBytes matches the OpenAPI IdempotencyKey maxLength.
	maxIdempotencyKeyBytes = 255
	// idempotencyCacheLimit bounds remembered keys per handler.
	idempotencyCacheLimit = 1024

	// MessageTypeText is the only message type this API records today.
	MessageTypeText = "text"

	// DirectionInbound marks a message received by the session.
	DirectionInbound = "INBOUND"
	// DirectionOutbound marks a message sent by the session.
	DirectionOutbound = "OUTBOUND"
)

// MessageView is the REST representation of a message. It follows the
// OpenAPI Message schema for the fields listed in the task contract: ID,
// SessionID, Chat (chat_id), Direction, Type, Text, and CreatedAt.
type MessageView struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	Chat      string    `json:"chat_id"`
	Sender    string    `json:"sender"`
	Direction string    `json:"direction"`
	Type      string    `json:"type"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

// MessageLister is the read boundary for stored messages. A session with no
// messages returns an empty slice. A non-empty cursor is the value returned
// as next_cursor by an earlier page and must be treated as opaque.
type MessageLister interface {
	ListMessages(ctx context.Context, sessionID string, limit int, cursor string) ([]MessageView, string, error)
}

// MessageGetter is the optional single-message read boundary. Handlers answer
// 501 when the configured MessageLister does not implement it.
type MessageGetter interface {
	GetMessage(ctx context.Context, sessionID, messageID string) (MessageView, error)
}

// MessageAppender is the optional write boundary. Handlers answer 501 when the
// configured MessageLister does not implement it.
type MessageAppender interface {
	Append(ctx context.Context, msg MessageView) (MessageView, error)
}

// MemoryMessageStore is a bounded in-process message store. Each session keeps
// at most capacity messages in a ring buffer; appending past the capacity
// drops the oldest message of that session. It is safe for concurrent use and
// meant for tests and single-process deployments.
type MemoryMessageStore struct {
	mu       sync.RWMutex
	capacity int
	sessions map[string]*messageRing
	nextSeq  uint64
	now      func() time.Time
	newID    func() (string, error)
}

type messageRing struct {
	items []storedMessage
}

type storedMessage struct {
	view MessageView
	seq  uint64
}

// NewMemoryMessageStore returns a store holding DefaultMessageCapacity
// messages per session.
func NewMemoryMessageStore() *MemoryMessageStore {
	return NewMemoryMessageStoreWithCapacity(DefaultMessageCapacity)
}

// NewMemoryMessageStoreWithCapacity returns a store with an explicit
// per-session capacity. Non-positive values fall back to
// DefaultMessageCapacity.
func NewMemoryMessageStoreWithCapacity(capacity int) *MemoryMessageStore {
	if capacity <= 0 {
		capacity = DefaultMessageCapacity
	}
	return &MemoryMessageStore{
		capacity: capacity,
		sessions: make(map[string]*messageRing),
		now:      time.Now,
		newID:    newUUID,
	}
}

// Append records msg. It fills ID and CreatedAt when they are zero and
// allocates the global sequence number used by cursors. A missing SessionID is
// rejected with ErrInvalidInput.
func (s *MemoryMessageStore) Append(_ context.Context, msg MessageView) (MessageView, error) {
	if msg.SessionID == "" {
		return MessageView{}, fmt.Errorf("%w: session id is required", ErrInvalidInput)
	}
	if msg.ID == "" {
		id, err := s.newID()
		if err != nil {
			return MessageView{}, fmt.Errorf("api: message id: %w", err)
		}
		msg.ID = id
	}
	if msg.CreatedAt.IsZero() {
		msg.CreatedAt = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextSeq++
	ring := s.sessions[msg.SessionID]
	if ring == nil {
		ring = &messageRing{}
		s.sessions[msg.SessionID] = ring
	}
	ring.items = append(ring.items, storedMessage{view: msg, seq: s.nextSeq})
	if overflow := len(ring.items) - s.capacity; overflow > 0 {
		ring.items = append(ring.items[:0], ring.items[overflow:]...)
	}
	return msg, nil
}

// ListMessages returns messages newest first. A non-empty cursor continues
// from the page it was issued for; the returned next cursor is empty on the
// last page. The cursor is based on the store's sequence number, so it keeps
// working while new messages arrive and old ones are evicted.
func (s *MemoryMessageStore) ListMessages(_ context.Context, sessionID string, limit int, cursor string) ([]MessageView, string, error) {
	if limit <= 0 {
		return nil, "", fmt.Errorf("%w: limit must be positive", ErrInvalidInput)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var beforeSeq uint64
	if cursor != "" {
		seq, err := decodeMessageCursor(cursor)
		if err != nil {
			return nil, "", err
		}
		beforeSeq = seq
	}

	ring := s.sessions[sessionID]
	if ring == nil {
		return []MessageView{}, "", nil
	}
	items := ring.items

	end := len(items)
	if beforeSeq != 0 {
		end = sort.Search(len(items), func(i int) bool { return items[i].seq >= beforeSeq })
	}

	out := make([]MessageView, 0, min(limit, end))
	var lastSeq uint64
	i := end - 1
	for ; i >= 0 && len(out) < limit; i-- {
		out = append(out, items[i].view)
		lastSeq = items[i].seq
	}
	next := ""
	if i >= 0 {
		next = encodeMessageCursor(lastSeq)
	}
	return out, next, nil
}

// GetMessage returns one message of the session.
func (s *MemoryMessageStore) GetMessage(_ context.Context, sessionID, messageID string) (MessageView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if ring := s.sessions[sessionID]; ring != nil {
		for i := len(ring.items) - 1; i >= 0; i-- {
			if ring.items[i].view.ID == messageID {
				return ring.items[i].view, nil
			}
		}
	}
	return MessageView{}, fmt.Errorf("%w: message %s", ErrNotFound, messageID)
}

const messageCursorPrefix = "m1:"

func encodeMessageCursor(seq uint64) string {
	raw := messageCursorPrefix + strconv.FormatUint(seq, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeMessageCursor(cursor string) (uint64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid cursor", ErrInvalidInput)
	}
	text := string(raw)
	if !strings.HasPrefix(text, messageCursorPrefix) {
		return 0, fmt.Errorf("%w: invalid cursor", ErrInvalidInput)
	}
	seq, err := strconv.ParseUint(strings.TrimPrefix(text, messageCursorPrefix), 10, 64)
	if err != nil || seq == 0 {
		return 0, fmt.Errorf("%w: invalid cursor", ErrInvalidInput)
	}
	return seq, nil
}

type sendTextRequest struct {
	To   string `json:"to"`
	Text string `json:"text"`
}

// queuedMessage is the 202 body. It is intentionally smaller than the
// OpenAPI Message schema: the contract's Message response is the read shape
// (see MessageView), and this ack only reports the new id and queue state.
type queuedMessage struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
}

type messageListResponse struct {
	Data       []MessageView `json:"data"`
	NextCursor *string       `json:"next_cursor"`
}

// messageStoreReady guards direct handler calls. Mount only registers the
// messaging routes when a store is configured, so normally /api/v1 falls back
// to the router's 501 not-implemented response instead.
func (h *Handler) messageStoreReady(w http.ResponseWriter) bool {
	if h.messages != nil {
		return true
	}
	writeError(w, http.StatusNotImplemented, "not_implemented", "messaging endpoints are not configured")
	return false
}

func (h *Handler) sendText(w http.ResponseWriter, r *http.Request) {
	if !h.messageStoreReady(w) {
		return
	}
	appender, ok := h.messages.(MessageAppender)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented", "the configured message store does not accept writes")
		return
	}

	sessionID := chi.URLParam(r, "sessionId")

	var req sendTextRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTextBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", `request body must be {"to":"<user>@<server>","text":"..."}`)
		return
	}
	if err := validateSendText(req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	key := r.Header.Get("Idempotency-Key")
	if len(key) > maxIdempotencyKeyBytes {
		writeError(w, http.StatusBadRequest, "validation_failed",
			fmt.Sprintf("Idempotency-Key must be at most %d bytes", maxIdempotencyKeyBytes))
		return
	}

	var entry *idempotencyEntry
	var scopedKey string
	if key != "" {
		scopedKey = sessionID + "\x00" + key
		fingerprint := messageFingerprint(req)

		for {
			e, owner := h.idempotency.begin(scopedKey, fingerprint)
			if owner {
				entry = e
				break
			}
			// The fingerprint is set at begin, so a conflicting body is
			// rejected immediately, even while the owner is still working.
			if e.fingerprint != fingerprint {
				writeError(w, http.StatusConflict, "idempotency_conflict",
					"this Idempotency-Key was already used with a different request body")
				return
			}
			select {
			case <-e.ready:
			case <-r.Context().Done():
				return
			}
			if e.status == 0 {
				// The request that owned this key failed and released it;
				// retry, which may make this caller the owner.
				continue
			}
			writeRawJSON(w, e.status, e.body)
			return
		}
	}

	discard := func() {
		if entry != nil {
			h.idempotency.discard(scopedKey, entry)
		}
	}

	session, err := h.service.GetSession(r.Context(), sessionID)
	if err != nil {
		discard()
		h.writeServiceError(w, err)
		return
	}
	if session.Status != "CONNECTED" {
		discard()
		writeError(w, http.StatusServiceUnavailable, "session_not_connected",
			fmt.Sprintf("the session is not connected (status %s)", session.Status))
		return
	}

	msg, err := appender.Append(r.Context(), MessageView{
		SessionID: sessionID,
		Chat:      req.To,
		Direction: DirectionOutbound,
		Type:      MessageTypeText,
		Text:      req.Text,
	})
	if err != nil {
		discard()
		h.writeMessageError(w, err)
		return
	}

	body, err := json.Marshal(queuedMessage{MessageID: msg.ID, Status: "queued"})
	if err != nil {
		// Marshalling two strings cannot fail in practice. The message is
		// already stored, so keep the key burned rather than risk a retry
		// appending a duplicate.
		if entry != nil {
			h.idempotency.complete(entry, http.StatusInternalServerError,
				[]byte(`{"error":{"code":"internal_error","message":"an unexpected error occurred"}}`))
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
		return
	}
	if entry != nil {
		h.idempotency.complete(entry, http.StatusAccepted, body)
	}
	writeRawJSON(w, http.StatusAccepted, body)
}

func (h *Handler) listMessages(w http.ResponseWriter, r *http.Request) {
	if !h.messageStoreReady(w) {
		return
	}
	sessionID := chi.URLParam(r, "sessionId")

	limit, err := parseMessageLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	// The contract's optional direction filter is accepted and validated but
	// not applied: MessageLister pages over the whole chat log, and this route
	// only records OUTBOUND messages.
	if direction := r.URL.Query().Get("direction"); direction != "" && direction != DirectionInbound && direction != DirectionOutbound {
		writeError(w, http.StatusBadRequest, "validation_failed", "direction must be INBOUND or OUTBOUND")
		return
	}

	if _, err := h.service.GetSession(r.Context(), sessionID); err != nil {
		h.writeServiceError(w, err)
		return
	}

	messages, next, err := h.messages.ListMessages(r.Context(), sessionID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		h.writeMessageError(w, err)
		return
	}
	resp := messageListResponse{Data: messages}
	if resp.Data == nil {
		resp.Data = []MessageView{}
	}
	if next != "" {
		resp.NextCursor = &next
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) getMessage(w http.ResponseWriter, r *http.Request) {
	if !h.messageStoreReady(w) {
		return
	}
	getter, ok := h.messages.(MessageGetter)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented", "the configured message store does not support message lookup")
		return
	}

	sessionID := chi.URLParam(r, "sessionId")
	if _, err := h.service.GetSession(r.Context(), sessionID); err != nil {
		h.writeServiceError(w, err)
		return
	}

	msg, err := getter.GetMessage(r.Context(), sessionID, chi.URLParam(r, "messageId"))
	if err != nil {
		h.writeMessageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

func (h *Handler) writeMessageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "the requested message does not exist")
	case errors.Is(err, ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
	}
}

// validateJID enforces the JID rule shared by the text and media routes:
// exactly one '@' with a non-empty user and server, at most 255 bytes, and no
// whitespace or control characters.
func validateJID(jid string) error {
	if jid == "" {
		return fmt.Errorf("%w: \"to\" is required", ErrInvalidInput)
	}
	if len(jid) > 255 {
		return fmt.Errorf("%w: \"to\" must be at most 255 bytes", ErrInvalidInput)
	}
	if strings.Count(jid, "@") != 1 {
		return fmt.Errorf("%w: \"to\" must contain exactly one '@' (user@server)", ErrInvalidInput)
	}
	user, server, _ := strings.Cut(jid, "@")
	if user == "" || server == "" {
		return fmt.Errorf("%w: \"to\" must have a non-empty user and server", ErrInvalidInput)
	}
	for i := 0; i < len(jid); i++ {
		if jid[i] <= 0x20 || jid[i] == 0x7f {
			return fmt.Errorf("%w: \"to\" must not contain whitespace or control characters", ErrInvalidInput)
		}
	}
	return nil
}

// validateSendText enforces the OpenAPI body constraints plus the JID rule
// validated by validateJID.
func validateSendText(req sendTextRequest) error {
	if err := validateJID(req.To); err != nil {
		return err
	}
	if req.Text == "" {
		return fmt.Errorf("%w: \"text\" must not be empty", ErrInvalidInput)
	}
	if len(req.Text) > maxMessageTextBytes {
		return fmt.Errorf("%w: \"text\" must be at most %d bytes", ErrInvalidInput, maxMessageTextBytes)
	}
	return nil
}

func parseMessageLimit(raw string) (int, error) {
	if raw == "" {
		return 20, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > 100 {
		return 0, fmt.Errorf("%w: limit must be an integer between 1 and 100", ErrInvalidInput)
	}
	return limit, nil
}

// messageFingerprint compares requests semantically, so reformatting JSON does
// not turn a retry into a conflict. The session id is part of the key, not the
// fingerprint.
func messageFingerprint(req sendTextRequest) string {
	sum := sha256.Sum256([]byte(req.To + "\x00" + req.Text))
	return hex.EncodeToString(sum[:])
}

// idempotencyEntry is one remembered response. fingerprint is set when the
// entry is created; status and body are set exactly once, just before ready is
// closed. A zero status means the owning request failed and released the key.
// finish makes complete/discard idempotent so a deferred cleanup cannot close
// ready twice.
type idempotencyEntry struct {
	fingerprint string
	ready       chan struct{}
	finish      sync.Once

	status int
	body   []byte
}

// idempotencyCache remembers POST responses by key. In-flight keys are
// visible to concurrent callers, which wait for the owner instead of appending
// twice. Completed entries are evicted oldest first.
type idempotencyCache struct {
	mu      sync.Mutex
	entries map[string]*idempotencyEntry
	order   []string
	limit   int
}

func newIdempotencyCache(limit int) *idempotencyCache {
	if limit <= 0 {
		limit = idempotencyCacheLimit
	}
	return &idempotencyCache{
		entries: make(map[string]*idempotencyEntry),
		limit:   limit,
	}
}

// begin returns the entry for key and whether the caller owns it. Owners must
// call complete or discard.
func (c *idempotencyCache) begin(key, fingerprint string) (*idempotencyEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[key]; ok {
		return entry, false
	}
	entry := &idempotencyEntry{fingerprint: fingerprint, ready: make(chan struct{})}
	c.entries[key] = entry
	c.order = append(c.order, key)
	c.evictLocked()
	return entry, true
}

func (c *idempotencyCache) evictLocked() {
	if len(c.entries) <= c.limit {
		return
	}
	kept := make([]string, 0, len(c.order))
	for _, key := range c.order {
		entry, ok := c.entries[key]
		if !ok {
			continue
		}
		if len(c.entries) <= c.limit {
			kept = append(kept, key)
			continue
		}
		select {
		case <-entry.ready:
			delete(c.entries, key)
		default:
			// Still in flight: never evict it, or a concurrent retry could
			// append a second time.
			kept = append(kept, key)
		}
	}
	c.order = kept
}

func (c *idempotencyCache) complete(entry *idempotencyEntry, status int, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry.finish.Do(func() {
		entry.status = status
		entry.body = append([]byte(nil), body...)
		close(entry.ready)
	})
}

// discard forgets a failed request so the key can be retried. Waiting callers
// see the closed ready channel with a zero status and retry begin.
func (c *idempotencyCache) discard(key string, entry *idempotencyEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry.finish.Do(func() {
		if current, ok := c.entries[key]; ok && current == entry {
			delete(c.entries, key)
			for i, candidate := range c.order {
				if candidate == key {
					c.order = append(c.order[:i], c.order[i+1:]...)
					break
				}
			}
		}
		close(entry.ready)
	})
}

func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
