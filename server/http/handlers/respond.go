// Package handlers implements the HTTP endpoints defined by the WhatsCore
// API contract (api/openapi.yaml).
package handlers

import (
	"encoding/json"
	"net/http"
)

// WriteJSON renders v as a JSON response body.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		// Headers are already sent; nothing safe left to do but log is not
		// reachable here without coupling handlers to a logger. Encoding of
		// our own structs never fails in practice.
		_ = err
	}
}

// ErrorBody is the single error envelope used by every WhatsCore endpoint.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrorResponse wraps ErrorBody in the documented envelope shape.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// WriteError responds with the standard error envelope.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorResponse{Error: ErrorBody{Code: code, Message: message}})
}
