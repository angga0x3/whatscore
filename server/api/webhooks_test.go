package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newWebhookTestRouter mounts sessions and webhooks over an in-memory store.
func newWebhookTestRouter(t *testing.T) (http.Handler, *MemoryWebhookStore) {
	t.Helper()
	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryWebhookStore()
	handler, err := NewHandlerWithWebhooks(manager, store)
	if err != nil {
		t.Fatal(err)
	}
	return chiNewRouter(handler), store
}

func doRequest(t *testing.T, router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body)
	}
	return out
}

// assertNoSecret fails when raw contains anything secret-shaped for created.
func assertNoSecret(t *testing.T, label string, raw []byte, secret string) {
	t.Helper()
	text := string(raw)
	if secret != "" && strings.Contains(text, secret) {
		t.Fatalf("%s leaked the signing secret: %s", label, text)
	}
	if strings.Contains(text, `"secret"`) {
		t.Fatalf("%s contains a secret field: %s", label, text)
	}
	if strings.Contains(text, "whsec_") {
		t.Fatalf("%s contains a secret-shaped value: %s", label, text)
	}
}

func TestWebhookCRUD(t *testing.T) {
	router, store := newWebhookTestRouter(t)

	// Create.
	rec := doRequest(t, router, http.MethodPost, "/api/v1/webhooks",
		`{"url":"https://example.com/hooks/one","events":["message.received","message.sent"],"enabled":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body %s", rec.Code, rec.Body)
	}
	created := decodeJSON[WebhookCreatedView](t, rec)
	if created.ID == "" || len(created.ID) != 36 {
		t.Fatalf("id = %q, want a uuid", created.ID)
	}
	if created.URL != "https://example.com/hooks/one" {
		t.Fatalf("url = %q", created.URL)
	}
	if len(created.Events) != 2 || created.Events[0] != "message.received" || created.Events[1] != "message.sent" {
		t.Fatalf("events = %#v", created.Events)
	}
	if !created.Active {
		t.Fatal("enabled = false, want true")
	}
	if len(created.Secret) < minWebhookSecretBytes {
		t.Fatalf("secret = %q, want at least %d bytes", created.Secret, minWebhookSecretBytes)
	}
	if !strings.HasPrefix(created.Secret, "whsec_") {
		t.Fatalf("secret = %q, want a whsec_ prefix", created.Secret)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("timestamps = %v / %v", created.CreatedAt, created.UpdatedAt)
	}
	secret := created.Secret

	// Create a second endpoint so ordering and scoping are observable.
	rec = doRequest(t, router, http.MethodPost, "/api/v1/webhooks",
		`{"url":"http://127.0.0.1:9000/hook","events":["session.created"],"secret":"0123456789abcdef"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("second create status = %d, body %s", rec.Code, rec.Body)
	}
	second := decodeJSON[WebhookCreatedView](t, rec)
	if second.Secret != "0123456789abcdef" {
		t.Fatalf("explicit secret = %q", second.Secret)
	}

	// List: bare array per the OpenAPI schema, never the secret.
	rec = doRequest(t, router, http.MethodGet, "/api/v1/webhooks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	assertNoSecret(t, "list response", rec.Body.Bytes(), secret)
	hooks := decodeJSON[[]WebhookView](t, rec)
	if len(hooks) != 2 {
		t.Fatalf("list length = %d, want 2", len(hooks))
	}
	// List is ordered by id, which is random, so assert membership and order.
	if hooks[0].ID > hooks[1].ID {
		t.Fatalf("list is not sorted by id: %q then %q", hooks[0].ID, hooks[1].ID)
	}
	seenIDs := map[string]bool{hooks[0].ID: true, hooks[1].ID: true}
	if !seenIDs[created.ID] || !seenIDs[second.ID] {
		t.Fatalf("list ids = %#v, want %q and %q", seenIDs, created.ID, second.ID)
	}
	for _, hook := range hooks {
		if hook.Secret != "" {
			t.Fatalf("list item carries a secret: %#v", hook)
		}
	}

	// Get.
	rec = doRequest(t, router, http.MethodGet, "/api/v1/webhooks/"+created.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d", rec.Code)
	}
	assertNoSecret(t, "get response", rec.Body.Bytes(), secret)
	got := decodeJSON[WebhookView](t, rec)
	if got.ID != created.ID || got.URL != created.URL || !got.Active {
		t.Fatalf("get = %#v", got)
	}

	// PATCH one field at a time, then verify nothing else moved.
	rec = doRequest(t, router, http.MethodPatch, "/api/v1/webhooks/"+created.ID,
		`{"url":"https://example.com/hooks/renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch url status = %d, body %s", rec.Code, rec.Body)
	}
	assertNoSecret(t, "patch response", rec.Body.Bytes(), secret)
	patched := decodeJSON[WebhookView](t, rec)
	if patched.URL != "https://example.com/hooks/renamed" {
		t.Fatalf("patched url = %q", patched.URL)
	}
	if len(patched.Events) != 2 || !patched.Active {
		t.Fatalf("unrelated fields changed: %#v", patched)
	}
	if !patched.UpdatedAt.After(created.UpdatedAt) {
		t.Fatalf("updated_at = %v, want after %v", patched.UpdatedAt, created.UpdatedAt)
	}

	rec = doRequest(t, router, http.MethodPatch, "/api/v1/webhooks/"+created.ID,
		`{"events":["message.read"],"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch events status = %d, body %s", rec.Code, rec.Body)
	}
	assertNoSecret(t, "patch events response", rec.Body.Bytes(), secret)
	patched = decodeJSON[WebhookView](t, rec)
	if len(patched.Events) != 1 || patched.Events[0] != "message.read" {
		t.Fatalf("patched events = %#v", patched.Events)
	}
	if patched.Active {
		t.Fatal("enabled = true, want false")
	}
	if patched.URL != "https://example.com/hooks/renamed" {
		t.Fatalf("url after events patch = %q", patched.URL)
	}

	// Rotating the secret keeps it out of the response.
	rec = doRequest(t, router, http.MethodPatch, "/api/v1/webhooks/"+created.ID,
		`{"secret":"rotated-secret-0123456789"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch secret status = %d, body %s", rec.Code, rec.Body)
	}
	assertNoSecret(t, "patch secret response", rec.Body.Bytes(), secret)
	assertNoSecret(t, "patch secret response", rec.Body.Bytes(), "rotated-secret-0123456789")
	stored, err := store.Get(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Secret != "rotated-secret-0123456789" {
		t.Fatalf("stored secret = %q, want the rotated value", stored.Secret)
	}

	// Delete.
	rec = doRequest(t, router, http.MethodDelete, "/api/v1/webhooks/"+created.ID, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("delete body = %q, want empty", rec.Body)
	}

	rec = doRequest(t, router, http.MethodGet, "/api/v1/webhooks/"+created.ID, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete status = %d", rec.Code)
	}
	rec = doRequest(t, router, http.MethodDelete, "/api/v1/webhooks/"+created.ID, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("double delete status = %d", rec.Code)
	}

	// The surviving endpoint is untouched.
	rec = doRequest(t, router, http.MethodGet, "/api/v1/webhooks/"+second.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("survivor status = %d", rec.Code)
	}
}

func TestWebhookCreateDefaults(t *testing.T) {
	router, _ := newWebhookTestRouter(t)

	rec := doRequest(t, router, http.MethodPost, "/api/v1/webhooks",
		`{"url":"https://example.com/hooks","events":["message.received"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body %s", rec.Code, rec.Body)
	}
	created := decodeJSON[WebhookCreatedView](t, rec)
	if !created.Active {
		t.Fatal("enabled defaults to false, want true")
	}

	// Duplicate events are collapsed, not rejected.
	rec = doRequest(t, router, http.MethodPost, "/api/v1/webhooks",
		`{"url":"https://example.com/hooks","events":["message.received","message.received","session.qr"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("duplicate events status = %d, body %s", rec.Code, rec.Body)
	}
	dup := decodeJSON[WebhookCreatedView](t, rec)
	if len(dup.Events) != 2 {
		t.Fatalf("events = %#v, want duplicates collapsed", dup.Events)
	}
}

func TestWebhookValidation(t *testing.T) {
	router, _ := newWebhookTestRouter(t)

	create := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		return doRequest(t, router, http.MethodPost, "/api/v1/webhooks", body)
	}

	cases := []struct {
		name string
		body string
		want int
	}{
		{"empty url", `{"url":"","events":["message.received"]}`, http.StatusBadRequest},
		{"missing url", `{"events":["message.received"]}`, http.StatusBadRequest},
		{"relative url", `{"url":"/hooks/whatscore","events":["message.received"]}`, http.StatusBadRequest},
		{"ftp scheme", `{"url":"ftp://example.com/hook","events":["message.received"]}`, http.StatusBadRequest},
		{"empty host", `{"url":"https:///hook","events":["message.received"]}`, http.StatusBadRequest},
		{"unparseable url", `{"url":"https://exa mple.com/%zz","events":["message.received"]}`, http.StatusBadRequest},
		{"empty events", `{"url":"https://example.com/hook","events":[]}`, http.StatusBadRequest},
		{"missing events", `{"url":"https://example.com/hook"}`, http.StatusBadRequest},
		{"unknown event", `{"url":"https://example.com/hook","events":["message.exploded"]}`, http.StatusBadRequest},
		{"one unknown event", `{"url":"https://example.com/hook","events":["message.received","session.nope"]}`, http.StatusBadRequest},
		{"short secret", `{"url":"https://example.com/hook","events":["message.received"],"secret":"short"}`, http.StatusBadRequest},
		{"empty secret value", `{"url":"https://example.com/hook","events":["message.received"],"secret":""}`, http.StatusCreated},
		{"min length secret", `{"url":"https://example.com/hook","events":["message.received"],"secret":"0123456789abcdef"}`, http.StatusCreated},
		{"session scoped", `{"session_id":"e8b8c2c0-0f6b-4a88-a4b1-1f1a12345678","url":"https://example.com/hook","events":["message.received"]}`, http.StatusBadRequest},
		{"unknown field", `{"url":"https://example.com/hook","events":["message.received"],"nama":"x"}`, http.StatusBadRequest},
		{"not json", `nope`, http.StatusBadRequest},
		{"empty body", ``, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := create(t, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
			if tc.want >= 400 {
				body := decodeJSON[struct {
					Error struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}](t, rec)
				if body.Error.Code != "validation_failed" {
					t.Fatalf("error.code = %q, want validation_failed", body.Error.Code)
				}
				if body.Error.Message == "" {
					t.Fatal("error.message is empty")
				}
			}
		})
	}
}

func TestWebhookUpdateValidation(t *testing.T) {
	router, _ := newWebhookTestRouter(t)

	rec := doRequest(t, router, http.MethodPost, "/api/v1/webhooks",
		`{"url":"https://example.com/hook","events":["message.received"]}`)
	created := decodeJSON[WebhookCreatedView](t, rec)

	cases := []struct {
		name string
		body string
	}{
		{"bad url", `{"url":"gopher://example.com"}`},
		{"empty events", `{"events":[]}`},
		{"unknown event", `{"events":["nope"]}`},
		{"short secret", `{"secret":"tiny"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, router, http.MethodPatch, "/api/v1/webhooks/"+created.ID, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body)
			}
		})
	}

	// A rejected patch leaves the endpoint unchanged.
	rec = doRequest(t, router, http.MethodGet, "/api/v1/webhooks/"+created.ID, "")
	got := decodeJSON[WebhookView](t, rec)
	if got.URL != "https://example.com/hook" {
		t.Fatalf("url = %q, want the original", got.URL)
	}
	if len(got.Events) != 1 || got.Events[0] != "message.received" {
		t.Fatalf("events = %#v, want the original", got.Events)
	}
	if !got.Active {
		t.Fatal("enabled changed by a rejected patch")
	}
}

func TestWebhookNotFound(t *testing.T) {
	router, _ := newWebhookTestRouter(t)

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/webhooks/does-not-exist", ""},
		{http.MethodPatch, "/api/v1/webhooks/does-not-exist", `{"enabled":false}`},
		{http.MethodDelete, "/api/v1/webhooks/does-not-exist", ""},
		{http.MethodGet, "/api/v1/webhooks/does-not-exist/deliveries", ""},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := doRequest(t, router, tc.method, tc.path, tc.body)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body)
			}
			body := decodeJSON[struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}](t, rec)
			if body.Error.Code != "not_found" {
				t.Fatalf("error.code = %q, want not_found", body.Error.Code)
			}
		})
	}
}

func TestWebhookDeliveries(t *testing.T) {
	router, _ := newWebhookTestRouter(t)

	rec := doRequest(t, router, http.MethodPost, "/api/v1/webhooks",
		`{"url":"https://example.com/hook","events":["message.received"]}`)
	created := decodeJSON[WebhookCreatedView](t, rec)

	rec = doRequest(t, router, http.MethodGet, "/api/v1/webhooks/"+created.ID+"/deliveries", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("deliveries status = %d, body %s", rec.Code, rec.Body)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Fatalf("deliveries body = %q, want an empty array", got)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

// TestWebhookRoutesOptional proves the dependency extension is additive:
// NewHandler alone keeps sessions working and leaves webhooks unmounted.
func TestWebhookRoutesOptional(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(manager)
	if err != nil {
		t.Fatal(err)
	}
	router := chiNewRouter(handler)

	rec := doRequest(t, router, http.MethodGet, "/api/v1/sessions", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("sessions status = %d, body %s", rec.Code, rec.Body)
	}
	rec = doRequest(t, router, http.MethodGet, "/api/v1/webhooks", "")
	if rec.Code == http.StatusOK {
		t.Fatalf("webhooks answered 200 without a store: %s", rec.Body)
	}

	// SetWebhooks before Mount enables the routes.
	second, err := NewHandlerWithWebhooks(manager, nil)
	if err != nil {
		t.Fatal(err)
	}
	second.SetWebhooks(NewMemoryWebhookStore())
	router = chiNewRouter(second)
	rec = doRequest(t, router, http.MethodGet, "/api/v1/webhooks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("webhooks after SetWebhooks status = %d, body %s", rec.Code, rec.Body)
	}
}

func TestHandlerNilServiceStillRejected(t *testing.T) {
	if _, err := NewHandler(nil); err == nil {
		t.Fatal("NewHandler(nil) must fail")
	}
	if _, err := NewHandlerWithWebhooks(nil, NewMemoryWebhookStore()); err == nil {
		t.Fatal("NewHandlerWithWebhooks(nil, store) must fail")
	}
}

// TestSessionsStillWorkWithWebhooks is the regression guard for the shared
// /api/v1 subrouter: mounting webhooks must not shadow or break sessions.
func TestSessionsStillWorkWithWebhooks(t *testing.T) {
	router, _ := newWebhookTestRouter(t)

	rec := doRequest(t, router, http.MethodPost, "/api/v1/sessions", `{"name":"primary"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create session status = %d, body %s", rec.Code, rec.Body)
	}
	created := decodeJSON[SessionView](t, rec)

	rec = doRequest(t, router, http.MethodGet, "/api/v1/sessions/"+created.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get session status = %d, body %s", rec.Code, rec.Body)
	}
	rec = doRequest(t, router, http.MethodPost, "/api/v1/sessions/"+created.ID+"/connect", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("connect status = %d, body %s", rec.Code, rec.Body)
	}
	rec = doRequest(t, router, http.MethodGet, "/api/v1/sessions?status=BOGUS", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad filter status = %d, want 400", rec.Code)
	}

	// And a webhook create still works on the same router.
	rec = doRequest(t, router, http.MethodPost, "/api/v1/webhooks",
		`{"url":"https://example.com/hook","events":["session.created"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create webhook status = %d, body %s", rec.Code, rec.Body)
	}
}

func TestWebhookStoreConcurrentUse(t *testing.T) {
	store := NewMemoryWebhookStore()
	ctx := t.Context()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := store.Create(ctx, WebhookInput{
				URL:    "https://example.com/hook",
				Events: []string{"message.received"},
			})
			if err != nil {
				t.Errorf("create: %v", err)
				return
			}
			if _, err := store.List(ctx); err != nil {
				t.Errorf("list: %v", err)
			}
			next, err := store.Update(ctx, created.ID, WebhookPatch{Enabled: boolPtr(false)})
			if err != nil {
				t.Errorf("update: %v", err)
				return
			}
			if next.Active {
				t.Errorf("enabled = true after update")
			}
			if err := store.Delete(ctx, created.ID); err != nil {
				t.Errorf("delete: %v", err)
			}
		}()
	}
	wg.Wait()

	hooks, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 0 {
		t.Fatalf("registry has %d leftover endpoints", len(hooks))
	}
}

// TestWebhookStoreViewIsolation makes sure callers cannot mutate stored state
// through the events slice they receive.
func TestWebhookStoreViewIsolation(t *testing.T) {
	store := NewMemoryWebhookStore()
	ctx := t.Context()

	created, err := store.Create(ctx, WebhookInput{
		URL:    "https://example.com/hook",
		Events: []string{"message.received"},
	})
	if err != nil {
		t.Fatal(err)
	}
	created.Events[0] = "message.read"

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Events[0] != "message.received" {
		t.Fatalf("stored events = %#v; caller mutated them through the view", got.Events)
	}
}

func boolPtr(v bool) *bool { return &v }
