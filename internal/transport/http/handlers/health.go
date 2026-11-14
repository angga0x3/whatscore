package handlers

import (
	"net/http"
)

// healthResponse is the /health response body.
type healthResponse struct {
	Status string `json:"status"`
}

// HealthHandler implements the liveness probe. It must not touch any
// dependency: a process that can answer is alive, by definition. Dependency
// checks belong to /ready.
type HealthHandler struct{}

// NewHealthHandler constructs the liveness handler.
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// ServeHTTP implements http.Handler.
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}
