package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/angga0x3/whatscore/buildinfo"
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
