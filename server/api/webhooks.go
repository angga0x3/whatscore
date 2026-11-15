package api

// Webhook endpoint CRUD over a WebhookStore. The routes live under the same
// /api/v1 prefix as sessions and reuse writeJSON/writeError, but they depend
// on a separate store instead of the Service interface so session and webhook
// wiring stay independent.
//
// Wire-format decisions:
//
//   - WebhookView.Secret is write-only. The field exists so a delivery worker
//     can sign envelopes, but its JSON tag is "-", so no read handler can leak
//     it by marshalling a view. The signing secret is returned exactly once,
//     by POST /api/v1/webhooks, through WebhookCreatedView. This matches the
//     OpenAPI note on WebhookEndpoint.secret ("Returned only on creation").
//   - The boolean flag is serialized as "enabled" (the OpenAPI WebhookEndpoint
//     field) even though the Go field is named Active.
//   - List responses are bare JSON arrays, as the contract specifies, rather
//     than the {"data": [...]} envelope the Sessions routes use.
//   - The registry is process-local and global. The contract's optional
//     session_id scoping is not implemented yet.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// minWebhookSecretBytes is the shortest accepted HMAC-SHA256 signing secret.
// Generation always produces a longer value.
const minWebhookSecretBytes = 16

// WebhookView is the registry representation of an endpoint: the OpenAPI
// WebhookEndpoint schema plus updated_at. Secret is never rendered as JSON.
type WebhookView struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	Secret    string    `json:"-"`
	Active    bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WebhookCreatedView is the POST /api/v1/webhooks response: the readable view
// plus the signing secret. It is the only representation that carries the
// secret, and only in the 201 response.
type WebhookCreatedView struct {
	WebhookView
	Secret string `json:"secret"`
}

// WebhookInput is the create body: the OpenAPI WebhookEndpointInput plus an
// optional secret. An empty Secret asks the registry to generate one; a nil
// Enabled defaults to true.
//
// SessionID is accepted so a contract-shaped body decodes, but every endpoint
// in this registry is global: a non-empty value is rejected with
// ErrInvalidInput rather than silently ignored.
type WebhookInput struct {
	SessionID *string  `json:"session_id,omitempty"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Secret    string   `json:"secret,omitempty"`
	Enabled   *bool    `json:"enabled,omitempty"`
}

// WebhookPatch is the PATCH body. Every field is optional; nil keeps the
// current value.
type WebhookPatch struct {
	SessionID *string   `json:"session_id,omitempty"`
	URL       *string   `json:"url,omitempty"`
	Events    *[]string `json:"events,omitempty"`
	Secret    *string   `json:"secret,omitempty"`
	Enabled   *bool     `json:"enabled,omitempty"`
}

// WebhookDeliveryView is one delivery record (OpenAPI WebhookDelivery). The
// in-memory registry has no delivery worker yet, so the deliveries route
// always answers with an empty list; the type documents the element shape.
type WebhookDeliveryView struct {
	ID           string     `json:"id"`
	EndpointID   string     `json:"endpoint_id"`
	EventID      string     `json:"event_id"`
	Status       string     `json:"status"`
	Attempts     int        `json:"attempts"`
	ResponseCode *int       `json:"response_code"`
	LastError    *string    `json:"last_error"`
	DeliveredAt  *time.Time `json:"delivered_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// WebhookStore is the persistence boundary for webhook endpoints. Errors must
// wrap ErrNotFound or ErrInvalidInput so the handlers can map them onto the
// shared /api/v1 error codes.
type WebhookStore interface {
	Create(ctx context.Context, input WebhookInput) (WebhookView, error)
	List(ctx context.Context) ([]WebhookView, error)
	Get(ctx context.Context, id string) (WebhookView, error)
	Update(ctx context.Context, id string, patch WebhookPatch) (WebhookView, error)
	Delete(ctx context.Context, id string) error
}

// MemoryWebhookStore keeps endpoints in process memory. It is safe for
// concurrent use and is meant for tests and single-process deployments; a
// database-backed store implements the same interface. Flattening the slice
// on the way out keeps callers from mutating stored state.
type MemoryWebhookStore struct {
	mu       sync.RWMutex
	webhooks map[string]WebhookView
}

// NewMemoryWebhookStore returns an empty registry.
func NewMemoryWebhookStore() *MemoryWebhookStore {
	return &MemoryWebhookStore{webhooks: make(map[string]WebhookView)}
}

// Create validates and registers an endpoint. An empty input.Secret is
// replaced by a generated whsec_-prefixed secret; provided secrets must be at
// least minWebhookSecretBytes long.
func (s *MemoryWebhookStore) Create(_ context.Context, input WebhookInput) (WebhookView, error) {
	if err := rejectSessionScope(input.SessionID); err != nil {
		return WebhookView{}, err
	}
	if err := validateWebhookURL(input.URL); err != nil {
		return WebhookView{}, err
	}
	events, err := validateWebhookEvents(input.Events)
	if err != nil {
		return WebhookView{}, err
	}

	secret := input.Secret
	if secret == "" {
		secret, err = newWebhookSecret()
		if err != nil {
			return WebhookView{}, err
		}
	} else if err := validateWebhookSecret(secret); err != nil {
		return WebhookView{}, err
	}

	id, err := newUUID()
	if err != nil {
		return WebhookView{}, fmt.Errorf("api: webhook id: %w", err)
	}
	now := time.Now()
	view := WebhookView{
		ID:        id,
		URL:       input.URL,
		Events:    events,
		Secret:    secret,
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if input.Enabled != nil {
		view.Active = *input.Enabled
	}

	s.mu.Lock()
	s.webhooks[id] = view
	s.mu.Unlock()
	return cloneWebhook(view), nil
}

// List returns every endpoint in stable id order.
func (s *MemoryWebhookStore) List(_ context.Context) ([]WebhookView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]WebhookView, 0, len(s.webhooks))
	for _, view := range s.webhooks {
		out = append(out, cloneWebhook(view))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Get returns one endpoint.
func (s *MemoryWebhookStore) Get(_ context.Context, id string) (WebhookView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	view, ok := s.webhooks[id]
	if !ok {
		return WebhookView{}, fmt.Errorf("%w: webhook %s", ErrNotFound, id)
	}
	return cloneWebhook(view), nil
}

// Update applies a partial update. Validation happens before any field is
// changed, so a rejected patch leaves the stored endpoint untouched.
func (s *MemoryWebhookStore) Update(_ context.Context, id string, patch WebhookPatch) (WebhookView, error) {
	if err := rejectSessionScope(patch.SessionID); err != nil {
		return WebhookView{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	view, ok := s.webhooks[id]
	if !ok {
		return WebhookView{}, fmt.Errorf("%w: webhook %s", ErrNotFound, id)
	}

	changed := false
	if patch.URL != nil {
		if err := validateWebhookURL(*patch.URL); err != nil {
			return WebhookView{}, err
		}
		if view.URL != *patch.URL {
			view.URL = *patch.URL
			changed = true
		}
	}
	if patch.Events != nil {
		events, err := validateWebhookEvents(*patch.Events)
		if err != nil {
			return WebhookView{}, err
		}
		view.Events = events
		changed = true
	}
	if patch.Secret != nil {
		if err := validateWebhookSecret(*patch.Secret); err != nil {
			return WebhookView{}, err
		}
		view.Secret = *patch.Secret
		changed = true
	}
	if patch.Enabled != nil && view.Active != *patch.Enabled {
		view.Active = *patch.Enabled
		changed = true
	}
	if changed {
		view.UpdatedAt = time.Now()
	}

	s.webhooks[id] = view
	return cloneWebhook(view), nil
}

// Delete removes an endpoint.
func (s *MemoryWebhookStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.webhooks[id]; !ok {
		return fmt.Errorf("%w: webhook %s", ErrNotFound, id)
	}
	delete(s.webhooks, id)
	return nil
}

// writeWebhookError maps store errors onto the same codes as sessions but
// names webhooks in the 404 message.
func (h *Handler) writeWebhookError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "the requested webhook does not exist")
	case errors.Is(err, ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
	}
}

// webhookStoreReady guards direct handler calls. Mount only registers the
// webhook routes when a store is configured, so normally /api/v1 falls back to
// the router's 501 not-implemented response instead.
func (h *Handler) webhookStoreReady(w http.ResponseWriter) bool {
	if h.webhooks != nil {
		return true
	}
	writeError(w, http.StatusNotImplemented, "not_implemented", "webhook endpoints are not configured")
	return false
}

func (h *Handler) listWebhooks(w http.ResponseWriter, r *http.Request) {
	if !h.webhookStoreReady(w) {
		return
	}
	hooks, err := h.webhooks.List(r.Context())
	if err != nil {
		h.writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hooks)
}

func (h *Handler) createWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.webhookStoreReady(w) {
		return
	}
	var input WebhookInput
	if !decodeWebhookBody(w, r, &input, `request body must be {"url": "...", "events": ["..."]}`) {
		return
	}
	hook, err := h.webhooks.Create(r.Context(), input)
	if err != nil {
		h.writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, WebhookCreatedView{WebhookView: hook, Secret: hook.Secret})
}

func (h *Handler) getWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.webhookStoreReady(w) {
		return
	}
	hook, err := h.webhooks.Get(r.Context(), chi.URLParam(r, "webhookId"))
	if err != nil {
		h.writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hook)
}

func (h *Handler) updateWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.webhookStoreReady(w) {
		return
	}
	var patch WebhookPatch
	if !decodeWebhookBody(w, r, &patch, "request body must be a partial webhook endpoint") {
		return
	}
	hook, err := h.webhooks.Update(r.Context(), chi.URLParam(r, "webhookId"), patch)
	if err != nil {
		h.writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hook)
}

func (h *Handler) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.webhookStoreReady(w) {
		return
	}
	if err := h.webhooks.Delete(r.Context(), chi.URLParam(r, "webhookId")); err != nil {
		h.writeWebhookError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listWebhookDeliveries answers with an empty list until a delivery worker
// records attempts. The 404 for an unknown endpoint is still reported.
func (h *Handler) listWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	if !h.webhookStoreReady(w) {
		return
	}
	if _, err := h.webhooks.Get(r.Context(), chi.URLParam(r, "webhookId")); err != nil {
		h.writeWebhookError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, []WebhookDeliveryView{})
}

func decodeWebhookBody(w http.ResponseWriter, r *http.Request, dst any, message string) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", message)
		return false
	}
	return true
}

// webhookEventTypes is the EventType enum from docs/api/openapi.yaml. Unknown
// names are rejected at registration, so keep it in sync with the contract.
var webhookEventTypes = map[string]struct{}{
	"session.created":      {},
	"session.qr":           {},
	"session.connected":    {},
	"session.disconnected": {},
	"session.logged_out":   {},
	"message.received":     {},
	"message.sent":         {},
	"message.delivered":    {},
	"message.read":         {},
	"message.failed":       {},
}

// validateWebhookURL mirrors server/webhook.parseEndpoint, which is
// unexported: only absolute http(s) URLs with a non-empty host are accepted.
// Range policy (loopback, link-local, metadata) is a registration concern and
// is not applied by this in-memory registry yet.
func validateWebhookURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("%w: empty url", ErrInvalidInput)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid url: %v", ErrInvalidInput, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: url scheme %q is not http or https", ErrInvalidInput, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: url has an empty host", ErrInvalidInput)
	}
	return nil
}

// validateWebhookEvents enforces a non-empty subset of the EventType enum.
// The OpenAPI input schema also allows [] to mean "all events"; this registry
// requires explicit subscriptions, which is stricter but unambiguous.
func validateWebhookEvents(events []string) ([]string, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("%w: events must not be empty", ErrInvalidInput)
	}
	out := make([]string, 0, len(events))
	seen := make(map[string]struct{}, len(events))
	for _, name := range events {
		if _, ok := webhookEventTypes[name]; !ok {
			return nil, fmt.Errorf("%w: unknown event %q", ErrInvalidInput, name)
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

// rejectSessionScope fails when a caller asks for per-session scoping, which
// this global registry does not implement. Silently dropping the field would
// register a broader endpoint than the caller asked for.
func rejectSessionScope(sessionID *string) error {
	if sessionID != nil && *sessionID != "" {
		return fmt.Errorf("%w: session_id scoping is not supported; omit the field for a global webhook", ErrInvalidInput)
	}
	return nil
}

func validateWebhookSecret(secret string) error {
	if len(secret) < minWebhookSecretBytes {
		return fmt.Errorf("%w: secret must be at least %d bytes", ErrInvalidInput, minWebhookSecretBytes)
	}
	return nil
}

// newWebhookSecret returns a fresh 256-bit signing secret.
func newWebhookSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("api: webhook secret: %w", err)
	}
	return "whsec_" + hex.EncodeToString(raw[:]), nil
}

// cloneWebhook copies the events slice so stored state cannot be mutated
// through a returned view.
func cloneWebhook(view WebhookView) WebhookView {
	view.Events = append([]string(nil), view.Events...)
	return view
}
