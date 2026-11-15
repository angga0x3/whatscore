package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/angga0x3/whatscore/buildinfo"
	"github.com/angga0x3/whatscore/server/api"
)

func newTestRouter() http.Handler {
	return NewRouter(Deps{
		Logger:  slog.New(slog.DiscardHandler),
		AppName: "WhatsCore",
		Build:   buildinfo.Info{Version: "test", Commit: "test", Date: "test"},
	})
}

func TestRouterHealthEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health: status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("X-Request-Id header is missing; RequestID middleware not applied")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestRouterNotFoundReturnsErrorEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Error.Code != "not_found" {
		t.Errorf("error.code = %q, want not_found", body.Error.Code)
	}
}

func TestRouterMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/health", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestRouterAPIV1NotImplemented(t *testing.T) {
	tests := []struct {
		path   string
		method string
	}{
		{"/api/v1/sessions", http.MethodGet},
		{"/api/v1/sessions", http.MethodPost},
		{"/api/v1/sessions/abc/messages/text", http.MethodPost},
		{"/api/v1/does-not-exist", http.MethodGet},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newTestRouter().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))

			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
			}
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}
			if body.Error.Code != "not_implemented" {
				t.Errorf("error.code = %q, want not_implemented", body.Error.Code)
			}
		})
	}
}

type staticMounter struct{ mounted *bool }

func (s staticMounter) Mount(v1 chi.Router) {
	v1.Get("/sessions", func(w http.ResponseWriter, _ *http.Request) {
		*s.mounted = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestRouterMountsAPI(t *testing.T) {
	mounted := false
	router := NewRouter(Deps{
		Logger: slog.New(slog.DiscardHandler),
		Build:  buildinfo.Info{},
		API:    staticMounter{mounted: &mounted},
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))
	if rec.Code != http.StatusOK || !mounted {
		t.Fatalf("status = %d, mounted = %v", rec.Code, mounted)
	}

	// Unmounted paths keep the 501 contract.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/webhooks", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("unmounted status = %d", rec.Code)
	}
}

// TestRouterMountsRealAPIService guards the wiring itself: a stub mounter
// cannot catch a prefix clash between the router and the API handler.
func TestRouterMountsRealAPIService(t *testing.T) {
	manager, err := api.NewManager()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := api.NewHandler(manager)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(Deps{Logger: slog.New(slog.DiscardHandler), Build: buildinfo.Info{}, API: handler})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("sessions status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/messages", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("unimplemented path status = %d", rec.Code)
	}
}
