package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/angga0x3/whatscore/buildinfo"
)

func TestHealthHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)

	NewHealthHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
}

type fakeChecker struct {
	name string
	err  error
}

func (f fakeChecker) Name() string { return f.name }

func (f fakeChecker) Check(_ context.Context) error { return f.err }

func TestReadinessHandlerAllUp(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)

	h := NewReadinessHandler([]Checker{fakeChecker{name: "database"}}, nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body readinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	if check, ok := body.Checks["database"]; !ok || check.Status != "up" {
		t.Errorf("checks[database] = %+v, want status up", check)
	}
}

func TestReadinessHandlerDependencyDown(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)

	h := NewReadinessHandler([]Checker{
		fakeChecker{name: "database", err: errors.New("connection refused")},
	}, nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	var body readinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Status != "unavailable" {
		t.Errorf("status = %q, want unavailable", body.Status)
	}
	if body.Checks["database"].Status != "down" {
		t.Errorf("checks[database].status = %q, want down", body.Checks["database"].Status)
	}
	if body.Checks["database"].Error == "" {
		t.Error("checks[database].error is empty, want the check error")
	}
}

func TestReadinessHandlerShuttingDown(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)

	h := NewReadinessHandler([]Checker{fakeChecker{name: "database"}}, func() bool { return true })
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	var body readinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Status != "shutting_down" {
		t.Errorf("status = %q, want shutting_down", body.Status)
	}
}

func TestVersionHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/version", nil)

	build := buildinfo.Info{Version: "v0.1.0", Commit: "abc123", Date: "2026-11-15T00:00:00Z"}
	NewVersionHandler("WhatsCore", build).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body versionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Name != "WhatsCore" || body.Version != "v0.1.0" || body.Commit != "abc123" {
		t.Errorf("unexpected body: %+v", body)
	}
	if body.GoVersion == "" {
		t.Error("go_version is empty")
	}
}
