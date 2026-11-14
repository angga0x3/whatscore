package handlers

import (
	"context"
	"net/http"
	"time"
)

// Checker is the readiness contract implemented by dependencies (PostgreSQL
// today, the WhatsApp engine in upcoming milestones).
type Checker interface {
	Name() string
	Check(ctx context.Context) error
}

// checkResult is the per-dependency entry in the /ready response.
type checkResult struct {
	Status    string  `json:"status"`
	LatencyMS float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}

// readinessResponse is the /ready response body.
type readinessResponse struct {
	Status string                 `json:"status"`
	Checks map[string]checkResult `json:"checks,omitempty"`
}

const checkTimeout = 2 * time.Second

// ReadinessHandler verifies that every dependency the process needs is
// reachable before the endpoint answers 200. It also starts failing during
// graceful shutdown so load balancers drain the instance first.
type ReadinessHandler struct {
	checkers     []Checker
	shuttingDown func() bool
}

// NewReadinessHandler constructs the readiness handler. shuttingDown may be
// nil; when non-nil it must return true once the process started draining.
func NewReadinessHandler(checkers []Checker, shuttingDown func() bool) *ReadinessHandler {
	return &ReadinessHandler{checkers: checkers, shuttingDown: shuttingDown}
}

// ServeHTTP implements http.Handler.
func (h *ReadinessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.shuttingDown != nil && h.shuttingDown() {
		WriteJSON(w, http.StatusServiceUnavailable, readinessResponse{Status: "shutting_down"})
		return
	}

	checks := make(map[string]checkResult, len(h.checkers))
	ready := true

	for _, checker := range h.checkers {
		ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
		start := time.Now()
		err := checker.Check(ctx)
		cancel()

		result := checkResult{
			Status:    "up",
			LatencyMS: float64(time.Since(start).Microseconds()) / 1000.0,
		}
		if err != nil {
			ready = false
			result.Status = "down"
			result.Error = err.Error()
		}
		checks[checker.Name()] = result
	}

	status := "ready"
	code := http.StatusOK
	if !ready {
		status = "unavailable"
		code = http.StatusServiceUnavailable
	}
	WriteJSON(w, code, readinessResponse{Status: status, Checks: checks})
}
