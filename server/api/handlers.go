package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/server/http/handlers"
)

// Handler serves the /api/v1 routes over a Service plus optional messaging
// and streaming dependencies.
type Handler struct {
	service Service
	// webhooks is optional: when it is nil the webhook routes are not mounted
	// and /api/v1 keeps answering 501 for them.
	webhooks WebhookStore
	// messages is optional: when it is nil the messaging routes are not
	// mounted and /api/v1 keeps answering 501 for them.
	messages MessageLister
	// textDeliverer is the optional send boundary; nil records only.
	textDeliverer TextDeliverer
	// chatActions is the optional read-receipt/typing boundary; nil answers
	// 501 on those routes.
	chatActions ChatActions
	// mediaDeliverer is the optional attachment send boundary; nil stores
	// the encrypted blob only.
	mediaDeliverer MediaDeliverer
	// media is optional: when it is nil the media routes are not mounted and
	// /api/v1 keeps answering 501 for them.
	media MediaStore
	// mediaMaxRequest overrides the multipart request cap. It exists for
	// tests; a non-positive value restores maxMediaRequestBytes.
	mediaMaxRequest int64
	// bus is optional: when it is nil the SSE routes are not mounted and
	// /api/v1 keeps answering 501 for them.
	bus *events.Bus
	// heartbeat is a test seam for the SSE heartbeat interval.
	heartbeat time.Duration

	idempotency *idempotencyCache
}

// NewHandler returns a handler over service. Webhook routes stay unmounted;
// enable them with NewHandlerWithWebhooks or SetWebhooks.
func NewHandler(service Service) (*Handler, error) {
	if service == nil {
		return nil, errors.New("api: nil service")
	}
	return &Handler{service: service, idempotency: newIdempotencyCache(idempotencyCacheLimit)}, nil
}

// NewHandlerWithWebhooks returns a handler over service and webhooks. It is
// additive on purpose: NewHandler keeps its one-argument signature so existing
// callers and tests compile unchanged, and a webhook store stays a separate
// dependency instead of widening the Service interface. A nil store behaves
// like NewHandler.
func NewHandlerWithWebhooks(service Service, webhooks WebhookStore) (*Handler, error) {
	h, err := NewHandler(service)
	if err != nil {
		return nil, err
	}
	h.webhooks = webhooks
	return h, nil
}

// SetWebhooks installs the webhook store after construction. Mount must be
// called afterwards for the routes to be registered.
func (h *Handler) SetWebhooks(webhooks WebhookStore) {
	h.webhooks = webhooks
}

// SetMessages installs the message store after construction. Mount must be
// called afterwards for the messaging routes to be registered.
func (h *Handler) SetMessages(messages MessageLister) {
	h.messages = messages
}

// SetTextDeliverer installs the send boundary. Nil keeps the record-only
// behavior.
func (h *Handler) SetTextDeliverer(d TextDeliverer) {
	h.textDeliverer = d
}

// SetMediaDeliverer installs the attachment send boundary. Nil keeps the
// record-only behavior.
func (h *Handler) SetMediaDeliverer(d MediaDeliverer) {
	h.mediaDeliverer = d
}

// SetMedia installs the media store after construction. Mount must be called
// afterwards for the media routes to be registered. A nil store leaves the
// routes unmounted, so they keep answering 501.
func (h *Handler) SetMedia(store MediaStore) {
	h.media = store
}

// SetMediaRequestLimit overrides the multipart request cap. It exists for tests
// so the 413 boundary can be exercised without a 68 MiB body; a non-positive
// value restores maxMediaRequestBytes.
func (h *Handler) SetMediaRequestLimit(limit int64) {
	if limit <= 0 {
		limit = maxMediaRequestBytes
	}
	h.mediaMaxRequest = limit
}

// SetBus installs the event bus used by the SSE routes after construction.
// Mount must be called afterwards for the stream routes to be registered.
func (h *Handler) SetBus(bus *events.Bus) {
	h.bus = bus
}

// SetHeartbeatInterval overrides the SSE heartbeat interval. It exists for
// tests; a non-positive value restores DefaultHeartbeatInterval.
func (h *Handler) SetHeartbeatInterval(interval time.Duration) {
	h.heartbeat = interval
}

// Mount registers the versioned routes on a router already scoped to the
// /api/v1 prefix. The caller owns that prefix so the 501 fallback for
// unimplemented paths can live next to these routes. Optional areas (webhooks,
// messaging, SSE) register only when their dependency is configured.
func (h *Handler) Mount(v1 chi.Router) {
	v1.Get("/sessions", h.listSessions)
	v1.Post("/sessions", h.createSession)
	v1.Route("/sessions/{sessionId}", func(r chi.Router) {
		r.Get("/", h.getSession)
		r.Delete("/", h.deleteSession)
		r.Post("/connect", h.connectSession)
		r.Post("/disconnect", h.disconnectSession)
		if h.messages != nil {
			r.Post("/messages/text", h.sendText)
			r.Post("/messages/read", h.markRead)
			r.Post("/typing", h.sendTyping)
			r.Get("/messages", h.listMessages)
			r.Get("/messages/{messageId}", h.getMessage)
		}
		if h.media != nil {
			r.Post("/messages/image", h.sendImage)
			r.Post("/messages/document", h.sendDocument)
			r.Get("/media", h.listMedia)
			r.Get("/media/{mediaId}", h.getMedia)
		}
		if h.bus != nil {
			r.Get("/qr", h.streamQR)
			r.Get("/events", h.streamEvents)
		}
	})
	if h.webhooks != nil {
		v1.Get("/webhooks", h.listWebhooks)
		v1.Post("/webhooks", h.createWebhook)
		v1.Route("/webhooks/{webhookId}", func(r chi.Router) {
			r.Get("/", h.getWebhook)
			r.Patch("/", h.updateWebhook)
			r.Delete("/", h.deleteWebhook)
			r.Get("/deliveries", h.listWebhookDeliveries)
		})
	}
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
