package api

// Chat-action boundaries: the optional send side of read receipts and typing
// indicators. Both are no-ops on the wire when nil — the routes answer 501
// instead, the same pattern the text deliverer uses.

import (
	"context"
	"encoding/json"

	"github.com/go-chi/chi/v5"
	"net/http"
)

// ChatActions is the optional chat-action boundary: read receipts and typing
// indicators, delivered over the session connection.
type ChatActions interface {
	// MarkRead marks the given message ids in a chat as read — the blue
	// ticks.
	MarkRead(ctx context.Context, sessionID, chat string, ids []string) error
	// SendTyping sets or clears the typing indicator for a chat.
	SendTyping(ctx context.Context, sessionID, chat string, composing bool) error
}

// SetChatActions installs the chat-action boundary. Nil answers 501 on the
// routes.
func (h *Handler) SetChatActions(actions ChatActions) {
	h.chatActions = actions
}

// chatActionsReady guards direct handler calls.
func (h *Handler) chatActionsReady(w http.ResponseWriter) bool {
	if h.chatActions != nil {
		return true
	}
	writeError(w, http.StatusNotImplemented, "not_implemented",
		"chat actions are not configured for this deployment")
	return false
}

type markReadRequest struct {
	Chat string   `json:"chat"`
	IDs  []string `json:"ids"`
}

// markRead implements POST /sessions/{sessionId}/messages/read.
func (h *Handler) markRead(w http.ResponseWriter, r *http.Request) {
	if !h.chatActionsReady(w) {
		return
	}
	sessionID := chi.URLParam(r, "sessionId")
	var req markReadRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTextBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed",
			`request body must be {"chat":"<user>@<server>","ids":["<id>", ...]}`)
		return
	}
	if req.Chat == "" || len(req.IDs) == 0 {
		writeError(w, http.StatusBadRequest, "validation_failed",
			"chat and at least one id are required")
		return
	}
	if err := h.chatActions.MarkRead(r.Context(), sessionID, req.Chat, req.IDs); err != nil {
		writeError(w, http.StatusBadGateway, "mark_read_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Chat string   `json:"chat"`
		IDs  []string `json:"ids"`
	}{Chat: req.Chat, IDs: req.IDs})
}

type typingRequest struct {
	Chat      string `json:"chat"`
	Composing bool   `json:"composing"`
}

// sendTyping implements POST /sessions/{sessionId}/typing.
func (h *Handler) sendTyping(w http.ResponseWriter, r *http.Request) {
	if !h.chatActionsReady(w) {
		return
	}
	sessionID := chi.URLParam(r, "sessionId")
	var req typingRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTextBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed",
			`request body must be {"chat":"<user>@<server>","composing":true|false}`)
		return
	}
	if req.Chat == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "chat is required")
		return
	}
	if err := h.chatActions.SendTyping(r.Context(), sessionID, req.Chat, req.Composing); err != nil {
		writeError(w, http.StatusBadGateway, "typing_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Chat      string `json:"chat"`
		Composing bool   `json:"composing"`
	}{Chat: req.Chat, Composing: req.Composing})
}
