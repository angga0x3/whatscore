package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/angga0x3/whatscore/server/http/handlers"
)

// Handler serves the /api/v1 routes over a Service.
type Handler struct {
	service Service
}

// NewHandler returns a handler over service.
func NewHandler(service Service) (*Handler, error) {
	if service == nil {
		return nil, errors.New("api: nil service")
	}
	return &Handler{service: service}, nil
}

// Mount registers the routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/sessions", h.listSessions)
		r.Post("/sessions", h.createSession)
		r.Route("/sessions/{sessionId}", func(r chi.Router) {
			r.Get("/", h.getSession)
			r.Delete("/", h.deleteSession)
			r.Post("/connect", h.connectSession)
			r.Post("/disconnect", h.disconnectSession)
		})
	})
}

type createSessionRequest struct {
	Name string `json:"name"`
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status != "" && !validStatus(status) {
		writeError(w, http.StatusBadRequest, "validation_failed", "unknown status filter")
		return
	}
	sessions, err := h.service.ListSessions(r.Context(), status)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": sessions})
}

func (h *Handler) createSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "request body must be {\"name\": \"...\"}")
		return
	}
	session, err := h.service.CreateSession(r.Context(), req.Name)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, session)
}

func (h *Handler) getSession(w http.ResponseWriter, r *http.Request) {
	session, err := h.service.GetSession(r.Context(), chi.URLParam(r, "sessionId"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, session)
}

func (h *Handler) deleteSession(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DeleteSession(r.Context(), chi.URLParam(r, "sessionId")); err != nil {
		h.writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) connectSession(w http.ResponseWriter, r *http.Request) {
	if err := h.service.ConnectSession(r.Context(), chi.URLParam(r, "sessionId")); err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "CONNECTING"})
}

func (h *Handler) disconnectSession(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DisconnectSession(r.Context(), chi.URLParam(r, "sessionId")); err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "DISCONNECTED"})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "the requested session does not exist")
	case errors.Is(err, ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
	}
}

const maxBodyBytes = 64 << 10

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, handlers.ErrorResponse{Error: handlers.ErrorBody{Code: code, Message: message}})
}

func validStatus(status string) bool {
	switch status {
	case "STOPPED", "CONNECTING", "QR_PENDING", "CONNECTED", "DISCONNECTED", "LOGGED_OUT", "ERROR":
		return true
	default:
		return false
	}
}
