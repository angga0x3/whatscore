package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/angga0x3/whatscore/server/http/handlers"
)

// newV1Router mirrors server/http/router.go: the caller owns /api/v1 and the
// unmounted paths keep answering 501.
func newV1Router(h *Handler) http.Handler {
	router := chi.NewRouter()
	router.Route("/api/v1", func(v1 chi.Router) {
		if h != nil {
			h.Mount(v1)
		}
		v1.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			handlers.WriteError(w, http.StatusNotImplemented, "not_implemented", "not mounted")
		})
		v1.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
			handlers.WriteError(w, http.StatusNotImplemented, "not_implemented", "not mounted")
		})
	})
	return router
}

// messagingFixture is a router with sessions, messaging, and webhooks wired.
type messagingFixture struct {
	router   http.Handler
	manager  *Manager
	store    *MemoryMessageStore
	webhooks *MemoryWebhookStore
	session  SessionView
}

func newMessagingFixture(t *testing.T) *messagingFixture {
	t.Helper()

	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryMessageStore()
	webhooks := NewMemoryWebhookStore()
	handler, err := NewHandlerWithWebhooks(manager, webhooks)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetMessages(store)

	session, err := manager.CreateSession(t.Context(), "primary")
	if err != nil {
		t.Fatal(err)
	}
	return &messagingFixture{
		router:   newV1Router(handler),
		manager:  manager,
		store:    store,
		webhooks: webhooks,
		session:  session,
	}
}

// connect puts the fixture session into CONNECTED.
func (f *messagingFixture) connect(t *testing.T) {
	t.Helper()
	if err := f.manager.ConnectSession(t.Context(), f.session.ID); err != nil {
		t.Fatal(err)
	}
}

func (f *messagingFixture) sendText(t *testing.T, sessionID, body, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sessionID+"/messages/text", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	body := decodeJSON[struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}](t, rec)
	return body.Error.Code
}

func TestSendTextRequiresConnectedSession(t *testing.T) {
	f := newMessagingFixture(t)

	rec := f.sendText(t, f.session.ID, `{"to":"6281234567890@s.whatsapp.net","text":"hi"}`, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if code := errorCode(t, rec); code != "session_not_connected" {
		t.Fatalf("code = %q", code)
	}

	// Nothing was stored, so the failed attempt is retryable.
	messages, _, err := f.store.ListMessages(t.Context(), f.session.ID, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 0 {
		t.Fatalf("messages = %#v, want none", messages)
	}

	f.connect(t)
	rec = f.sendText(t, f.session.ID, `{"to":"6281234567890@s.whatsapp.net","text":"hi"}`, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("after connect status = %d, body %s", rec.Code, rec.Body)
	}
}

func TestSendTextQueuedAndReadBack(t *testing.T) {
	f := newMessagingFixture(t)
	f.connect(t)

	rec := f.sendText(t, f.session.ID, `{"to":"6281234567890@s.whatsapp.net","text":"Halo WhatsCore!"}`, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	queued := decodeJSON[struct {
		MessageID string `json:"message_id"`
		Status    string `json:"status"`
	}](t, rec)
	if queued.Status != "queued" || queued.MessageID == "" {
		t.Fatalf("queued = %#v", queued)
	}
	if len(queued.MessageID) != 36 {
		t.Fatalf("message_id = %q, want a uuid", queued.MessageID)
	}

	rec = httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/sessions/"+f.session.ID+"/messages/"+queued.MessageID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body %s", rec.Code, rec.Body)
	}
	msg := decodeJSON[MessageView](t, rec)
	if msg.ID != queued.MessageID || msg.SessionID != f.session.ID {
		t.Fatalf("message = %#v", msg)
	}
	if msg.Chat != "6281234567890@s.whatsapp.net" || msg.Direction != DirectionOutbound ||
		msg.Type != MessageTypeText || msg.Text != "Halo WhatsCore!" || msg.CreatedAt.IsZero() {
		t.Fatalf("message = %#v", msg)
	}

	rec = httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+f.session.ID+"/messages", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	list := decodeJSON[messageListResponse](t, rec)
	if len(list.Data) != 1 || list.Data[0].ID != queued.MessageID {
		t.Fatalf("list = %#v", list)
	}
	if list.NextCursor != nil {
		t.Fatalf("next_cursor = %v, want null", *list.NextCursor)
	}
}

func TestSendTextValidation(t *testing.T) {
	f := newMessagingFixture(t)
	f.connect(t)

	longText := strings.Repeat("a", maxMessageTextBytes+1)
	cases := []struct {
		name string
		body string
	}{
		{"missing to", `{"text":"hi"}`},
		{"empty to", `{"to":"","text":"hi"}`},
		{"no at sign", `{"to":"6281234567890","text":"hi"}`},
		{"two at signs", `{"to":"a@b@c","text":"hi"}`},
		{"empty user", `{"to":"@s.whatsapp.net","text":"hi"}`},
		{"empty server", `{"to":"6281234567890@","text":"hi"}`},
		{"whitespace in to", `{"to":"628 123@s.whatsapp.net","text":"hi"}`},
		{"missing text", `{"to":"a@b"}`},
		{"empty text", `{"to":"a@b","text":""}`},
		{"text too long", fmt.Sprintf(`{"to":"a@b","text":%q}`, longText)},
		{"unknown field", `{"to":"a@b","text":"hi","caption":"x"}`},
		{"not json", `nope`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.sendText(t, f.session.ID, tc.body, "")
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body)
			}
			if code := errorCode(t, rec); code != "validation_failed" {
				t.Fatalf("code = %q", code)
			}
		})
	}

	// A maximum-length text is accepted.
	rec := f.sendText(t, f.session.ID,
		fmt.Sprintf(`{"to":"a@b","text":%q}`, strings.Repeat("a", maxMessageTextBytes)), "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("max text status = %d, body %s", rec.Code, rec.Body)
	}

	// A maximum-length text survives JSON escaping of multi-byte characters.
	rec = f.sendText(t, f.session.ID,
		`{"to":"a@b","text":"`+strings.Repeat(`\u0001`, maxMessageTextBytes)+`"}`, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("escaped max text status = %d, body %s", rec.Code, rec.Body)
	}

	// Oversized idempotency keys are rejected before any append.
	rec = f.sendText(t, f.session.ID, `{"to":"a@b","text":"hi"}`, strings.Repeat("k", 256))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("long key status = %d, body %s", rec.Code, rec.Body)
	}
}

func TestSendTextUnknownSession(t *testing.T) {
	f := newMessagingFixture(t)

	rec := f.sendText(t, "does-not-exist", `{"to":"a@b","text":"hi"}`, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if code := errorCode(t, rec); code != "not_found" {
		t.Fatalf("code = %q", code)
	}
}

func TestIdempotency(t *testing.T) {
	f := newMessagingFixture(t)
	f.connect(t)

	const body = `{"to":"6281234567890@s.whatsapp.net","text":"retry me"}`
	first := f.sendText(t, f.session.ID, body, "key-1")
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, body %s", first.Code, first.Body)
	}

	t.Run("same key same body replays the response", func(t *testing.T) {
		second := f.sendText(t, f.session.ID, body, "key-1")
		if second.Code != http.StatusAccepted {
			t.Fatalf("status = %d, body %s", second.Code, second.Body)
		}
		if second.Body.String() != first.Body.String() {
			t.Fatalf("replay = %q, want %q", second.Body, first.Body)
		}
		assertMessageCount(t, f, 1)
	})

	t.Run("same key different body is a conflict", func(t *testing.T) {
		second := f.sendText(t, f.session.ID, `{"to":"6281234567890@s.whatsapp.net","text":"different"}`, "key-1")
		if second.Code != http.StatusConflict {
			t.Fatalf("status = %d, body %s", second.Code, second.Body)
		}
		if code := errorCode(t, second); code != "idempotency_conflict" {
			t.Fatalf("code = %q", code)
		}
		assertMessageCount(t, f, 1)
	})

	t.Run("different key appends", func(t *testing.T) {
		second := f.sendText(t, f.session.ID, body, "key-2")
		if second.Code != http.StatusAccepted {
			t.Fatalf("status = %d, body %s", second.Code, second.Body)
		}
		if second.Body.String() == first.Body.String() {
			t.Fatal("different key reused the first message id")
		}
		assertMessageCount(t, f, 2)
	})

	t.Run("keys are scoped per session", func(t *testing.T) {
		other, err := f.manager.CreateSession(t.Context(), "secondary")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.manager.ConnectSession(t.Context(), other.ID); err != nil {
			t.Fatal(err)
		}
		rec := f.sendText(t, other.ID, body, "key-1")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
		}
		assertMessageCount(t, f, 2)
		messages, _, err := f.store.ListMessages(t.Context(), other.ID, 10, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(messages) != 1 {
			t.Fatalf("other session messages = %#v", messages)
		}
	})
}

func TestIdempotencyConcurrentSameKey(t *testing.T) {
	f := newMessagingFixture(t)
	f.connect(t)

	const body = `{"to":"a@b","text":"once"}`

	var wg sync.WaitGroup
	start := make(chan struct{})
	bodies := make([]string, 8)
	codes := make([]int, 8)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec := f.sendText(t, f.session.ID, body, "concurrent key")
			bodies[i] = rec.Body.String()
			codes[i] = rec.Code
		}(i)
	}
	close(start)
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusAccepted {
			t.Fatalf("request %d status = %d", i, code)
		}
		if bodies[i] != bodies[0] {
			t.Fatalf("request %d body = %q, want %q", i, bodies[i], bodies[0])
		}
	}
	assertMessageCount(t, f, 1)
}

func TestIdempotencyKeyFreedByFailedRequest(t *testing.T) {
	f := newMessagingFixture(t)

	const body = `{"to":"a@b","text":"retry"}`
	rec := f.sendText(t, f.session.ID, body, "retry-key")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disconnected status = %d", rec.Code)
	}

	f.connect(t)
	rec = f.sendText(t, f.session.ID, body, "retry-key")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("connected status = %d, body %s", rec.Code, rec.Body)
	}
	assertMessageCount(t, f, 1)
}

func assertMessageCount(t *testing.T, f *messagingFixture, want int) {
	t.Helper()
	messages, _, err := f.store.ListMessages(t.Context(), f.session.ID, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != want {
		t.Fatalf("stored messages = %d, want %d", len(messages), want)
	}
}

func TestListMessagesPagination(t *testing.T) {
	f := newMessagingFixture(t)
	ctx := t.Context()

	var ids []string
	for i := 0; i < 5; i++ {
		msg, err := f.store.Append(ctx, MessageView{
			SessionID: f.session.ID,
			Chat:      "a@b",
			Direction: DirectionOutbound,
			Type:      MessageTypeText,
			Text:      fmt.Sprintf("msg-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, msg.ID)
	}

	var collected []string
	cursor := ""
	pages := 0
	for {
		path := "/api/v1/sessions/" + f.session.ID + "/messages?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		rec := httptest.NewRecorder()
		f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d status = %d, body %s", pages, rec.Code, rec.Body)
		}
		page := decodeJSON[messageListResponse](t, rec)
		pages++
		for _, msg := range page.Data {
			collected = append(collected, msg.ID)
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}

	if pages != 3 {
		t.Fatalf("pages = %d, want 3", pages)
	}
	want := []string{ids[4], ids[3], ids[2], ids[1], ids[0]}
	if strings.Join(collected, ",") != strings.Join(want, ",") {
		t.Fatalf("collected = %v, want %v", collected, want)
	}
}

func TestListMessagesQueryValidation(t *testing.T) {
	f := newMessagingFixture(t)

	cases := []struct {
		query string
		want  int
	}{
		{"", http.StatusOK},
		{"?limit=1", http.StatusOK},
		{"?limit=100", http.StatusOK},
		{"?limit=0", http.StatusBadRequest},
		{"?limit=101", http.StatusBadRequest},
		{"?limit=abc", http.StatusBadRequest},
		{"?limit=-3", http.StatusBadRequest},
		{"?cursor=not-a-cursor", http.StatusBadRequest},
		{"?direction=INBOUND", http.StatusOK},
		{"?direction=outbound", http.StatusBadRequest},
		{"?direction=sideways", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
				"/api/v1/sessions/"+f.session.ID+"/messages"+tc.query, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

func TestListMessagesUnknownSession(t *testing.T) {
	f := newMessagingFixture(t)

	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions/nope/messages", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
}

func TestGetMessageMissing(t *testing.T) {
	f := newMessagingFixture(t)

	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/sessions/"+f.session.ID+"/messages/00000000-0000-4000-8000-000000000000", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if code := errorCode(t, rec); code != "not_found" {
		t.Fatalf("code = %q", code)
	}

	rec = httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions/nope/messages/whatever", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown session status = %d", rec.Code)
	}
}

func TestMessageRoutesUnmountedWithoutStore(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(manager)
	if err != nil {
		t.Fatal(err)
	}
	router := newV1Router(handler)

	session, err := manager.CreateSession(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
		"/api/v1/sessions/"+session.ID+"/messages/text", strings.NewReader(`{"to":"a@b","text":"hi"}`)))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+session.ID+"/messages", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("list status = %d", rec.Code)
	}
}

func TestSendTextNotImplementedWithoutAppender(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(manager)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetMessages(readOnlyLister{})
	router := newV1Router(handler)

	session, err := manager.CreateSession(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
		"/api/v1/sessions/"+session.ID+"/messages/text", strings.NewReader(`{"to":"a@b","text":"hi"}`)))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/api/v1/sessions/"+session.ID+"/messages/abc", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("get status = %d, body %s", rec.Code, rec.Body)
	}
}

// readOnlyLister implements MessageLister but neither MessageAppender nor
// MessageGetter.
type readOnlyLister struct{}

func (readOnlyLister) ListMessages(context.Context, string, int, string) ([]MessageView, string, error) {
	return []MessageView{}, "", nil
}

func TestMemoryMessageStoreRingBuffer(t *testing.T) {
	store := NewMemoryMessageStoreWithCapacity(3)
	ctx := t.Context()

	for i := 0; i < 5; i++ {
		if _, err := store.Append(ctx, MessageView{SessionID: "s", Text: fmt.Sprintf("%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	messages, next, err := store.ListMessages(ctx, "s", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 3 {
		t.Fatalf("len = %d, want 3", len(messages))
	}
	if messages[0].Text != "4" || messages[2].Text != "2" {
		t.Fatalf("messages = %#v", messages)
	}
	if next != "" {
		t.Fatalf("next = %q, want empty", next)
	}

	// Eviction keeps cursors valid: the oldest surviving message is still the
	// page boundary.
	_, cursor, err := store.ListMessages(ctx, "s", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	page, _, err := store.ListMessages(ctx, "s", 10, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[0].Text != "3" {
		t.Fatalf("second page = %#v", page)
	}
}

func TestMemoryMessageStoreEmptyAndUnknown(t *testing.T) {
	store := NewMemoryMessageStore()

	messages, next, err := store.ListMessages(t.Context(), "missing", 20, "")
	if err != nil {
		t.Fatal(err)
	}
	if messages == nil || len(messages) != 0 || next != "" {
		t.Fatalf("messages = %#v, next = %q", messages, next)
	}

	if _, err := store.GetMessage(t.Context(), "missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, err := store.Append(t.Context(), MessageView{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
	if _, _, err := store.ListMessages(t.Context(), "s", 0, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestMemoryMessageStoreConcurrentAppend(t *testing.T) {
	store := NewMemoryMessageStoreWithCapacity(100)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := store.Append(context.Background(), MessageView{SessionID: "s", Text: fmt.Sprintf("%d", i)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()

	messages, _, err := store.ListMessages(t.Context(), "s", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 50 {
		t.Fatalf("len = %d, want 50", len(messages))
	}
}

func TestSessionsAndWebhookRoutesStillWork(t *testing.T) {
	f := newMessagingFixture(t)

	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("sessions status = %d, body %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+f.session.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get session status = %d", rec.Code)
	}

	rec = doRequest(t, f.router, http.MethodPost, "/api/v1/webhooks",
		`{"url":"https://example.com/hooks","events":["message.received"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("webhook create status = %d, body %s", rec.Code, rec.Body)
	}
	created := decodeJSON[WebhookCreatedView](t, rec)
	if created.ID == "" || created.Secret == "" {
		t.Fatalf("webhook = %#v", created)
	}

	rec = doRequest(t, f.router, http.MethodGet, "/api/v1/webhooks/"+created.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook get status = %d", rec.Code)
	}
}

func TestIdempotencyCacheEvictsCompletedEntries(t *testing.T) {
	cache := newIdempotencyCache(2)

	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("k%d", i)
		entry, owner := cache.begin(key, "fp")
		if !owner {
			t.Fatalf("key %s not owned", key)
		}
		cache.complete(entry, http.StatusAccepted, []byte(`{"status":"queued"}`))
	}
	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()
	if size != 2 {
		t.Fatalf("cached entries = %d, want 2", size)
	}
}

func TestMessageCursorRoundTrip(t *testing.T) {
	for _, seq := range []uint64{1, 42, 1 << 40} {
		cursor := encodeMessageCursor(seq)
		got, err := decodeMessageCursor(cursor)
		if err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		if got != seq {
			t.Fatalf("seq %d round-tripped to %d", seq, got)
		}
	}
	for _, bad := range []string{"!!!", encodeMessageCursor(1) + "x", "bTIxOjA"} {
		if _, err := decodeMessageCursor(bad); err == nil {
			t.Fatalf("cursor %q decoded, want error", bad)
		}
	}
}
