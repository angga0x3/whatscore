package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/angga0x3/whatscore/buildinfo"
	"github.com/angga0x3/whatscore/server/api"
	"github.com/angga0x3/whatscore/server/middleware"
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

// TestRouterRateLimitOnlyAppliesToAPI proves the probes stay reachable while a
// client is throttled, and that /api/v1 is actually limited.
func TestRouterRateLimitOnlyAppliesToAPI(t *testing.T) {
	limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
		Rate: 0.001, Burst: 1, IdleTTL: time.Minute,
	})
	mounted := false
	router := NewRouter(Deps{
		Logger:    slog.New(slog.DiscardHandler),
		Build:     buildinfo.Info{},
		API:       staticMounter{mounted: &mounted},
		RateLimit: limiter,
	})

	// Spend the single API token.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("first /api/v1 request status = %d, want 200", rec.Code)
	}

	// System probes are unlimited: many requests, all still served.
	for _, path := range []string{"/health", "/ready", "/version"} {
		for i := 0; i < 20; i++ {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s #%d status = %d, want 200 (probes must never be limited)", path, i, rec.Code)
			}
			if rec.Header().Get("X-RateLimit-Limit") != "" {
				t.Fatalf("GET %s has rate-limit headers; probes are not supposed to be limited", path)
			}
		}
	}

	// The API is limited, including its 501 catch-all.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/sessions"},
		{http.MethodGet, "/api/v1/does-not-exist"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s %s status = %d, want 429", tc.method, tc.path, rec.Code)
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s %s: Retry-After header missing", tc.method, tc.path)
		}
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: body is not JSON: %v", tc.method, tc.path, err)
		}
		if body.Error.Code != "rate_limited" {
			t.Errorf("%s %s: error.code = %q, want rate_limited", tc.method, tc.path, body.Error.Code)
		}
	}

	// A nil RateLimit disables limiting entirely.
	router = NewRouter(Deps{Logger: slog.New(slog.DiscardHandler), Build: buildinfo.Info{}, API: staticMounter{mounted: &mounted}})
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("nil RateLimit: request #%d status = %d, want 200 (limiting must be disabled)", i, rec.Code)
		}
	}
}

// TestRouterRateLimitPerKeyIsolation ensures one throttled API key does not
// block another, which is the point of keying by identity.
func TestRouterRateLimitPerKeyIsolation(t *testing.T) {
	limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
		Rate: 0.001, Burst: 1, IdleTTL: time.Minute,
	})
	router := NewRouter(Deps{Logger: slog.New(slog.DiscardHandler), Build: buildinfo.Info{}, RateLimit: limiter})

	do := func(key string) int {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		r.RemoteAddr = "203.0.113.10:1234"
		r.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		return rec.Code
	}

	if c := do("wc_live_alpha"); c != http.StatusNotImplemented && c != http.StatusOK {
		t.Fatalf("alpha first request status = %d, want served", c)
	}
	if c := do("wc_live_alpha"); c != http.StatusTooManyRequests {
		t.Fatalf("alpha second request status = %d, want 429", c)
	}
	if c := do("wc_live_beta"); c == http.StatusTooManyRequests {
		t.Fatalf("beta was throttled by alpha's bucket (status %d)", c)
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
