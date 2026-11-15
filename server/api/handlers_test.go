package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(manager)
	if err != nil {
		t.Fatal(err)
	}
	return chiNewRouter(handler)
}

func TestCreateAndListSessions(t *testing.T) {
	router := newTestRouter(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(`{"name":"primary"}`))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body %s", rec.Code, rec.Body)
	}
	var created SessionView
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Name != "primary" || created.Status != "STOPPED" {
		t.Fatalf("created = %#v", created)
	}
	if len(created.ID) != 36 {
		t.Fatalf("id = %q, want a uuid", created.ID)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var list struct {
		Data []SessionView `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 1 || list.Data[0].ID != created.ID {
		t.Fatalf("list = %#v", list.Data)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions?status=CONNECTED", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 0 {
		t.Fatalf("filtered = %#v", list.Data)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions?status=BOGUS", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad filter status = %d", rec.Code)
	}
}

func TestSessionLifecycle(t *testing.T) {
	router := newTestRouter(t)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(`{"name":"lifecycle"}`)))
	var created SessionView
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+created.ID+"/connect", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("connect status = %d, body %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+created.ID, nil))
	var current SessionView
	if err := json.Unmarshal(rec.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	if current.Status != "CONNECTED" {
		t.Fatalf("status = %q", current.Status)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+created.ID+"/disconnect", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("disconnect status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+created.ID, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+created.ID, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("after delete status = %d", rec.Code)
	}
}

func TestSessionValidation(t *testing.T) {
	router := newTestRouter(t)
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
	}{
		{"empty name", http.MethodPost, "/api/v1/sessions", `{"name":""}`, http.StatusBadRequest},
		{"unknown field", http.MethodPost, "/api/v1/sessions", `{"nama":"x"}`, http.StatusBadRequest},
		{"not json", http.MethodPost, "/api/v1/sessions", `nope`, http.StatusBadRequest},
		{"long name", http.MethodPost, "/api/v1/sessions", `{"name":"` + strings.Repeat("a", 101) + `"}`, http.StatusBadRequest},
		{"missing session", http.MethodGet, "/api/v1/sessions/does-not-exist", "", http.StatusNotFound},
		{"connect missing", http.MethodPost, "/api/v1/sessions/does-not-exist/connect", "", http.StatusNotFound},
		{"delete missing", http.MethodDelete, "/api/v1/sessions/does-not-exist", "", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
			if tc.want >= 400 {
				var body map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("error body is not JSON: %v", err)
				}
				if _, ok := body["error"]; !ok {
					t.Fatalf("missing error envelope: %s", rec.Body)
				}
			}
		})
	}
}

func TestNewHandlerValidation(t *testing.T) {
	if _, err := NewHandler(nil); err == nil {
		t.Fatal("nil service must fail")
	}
	if _, err := NewManager(WithSessionFactory(nil)); err == nil {
		t.Fatal("nil factory must fail")
	}
}

func TestManagerStatusTransitions(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	created, err := manager.CreateSession(ctx, "s")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ConnectSession(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	got, err := manager.GetSession(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "CONNECTED" {
		t.Fatalf("status = %q", got.Status)
	}
	if err := manager.DisconnectSession(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = manager.GetSession(ctx, created.ID)
	if got.Status != "DISCONNECTED" {
		t.Fatalf("status = %q", got.Status)
	}
}
