package api

// Media routes: image and document upload, plus media metadata reads.
//
// Contract notes:
//
//   - Transport is multipart/form-data, not the JSON body the OpenAPI document
//     describes. Fields: `to` (JID-like, required), `file` (the payload,
//     required), and the optional `caption`, `file_name` and `mime_type`.
//     `messages/image` accepts only image/png, image/jpeg and image/webp;
//     `messages/document` accepts any MIME type. This is a deliberate
//     divergence from SendImageRequest/SendDocumentRequest (image_url /
//     document_url): those JSON bodies describe a URL a worker would fetch,
//     while these routes accept the bytes directly.
//   - The payload is encrypted with core/media.Encrypt before it is stored.
//     The store only ever holds the encrypted blob (ciphertext ‖ MAC) plus the
//     plaintext digest, never the plaintext. The media key is the one piece of
//     secret material in the descriptor: it is written once, in the create
//     response, and it is excluded from every read shape by construction
//     (MediaAttachment.MediaKey is `json:"-"`). A client that loses it cannot
//     decrypt the blob; a read can never leak it.
//   - Of the descriptor's two hashes, only SHA256(plaintext) is persisted.
//     EncSHA256(ciphertext ‖ MAC) is not stored: the envelope MAC already
//     authenticates the blob, and MediaAttachment's contract shape carries one
//     digest. A future download endpoint that wants core/media.Decrypt's
//     up-front blob check must add that field first.
//   - Delivery is not implemented, same as text: `202 {"status":"queued"}` is
//     a queue acknowledgement. No WhatsApp media frame leaves the process.
//     Media messages are not appended to the message log either — the media
//     store is the record, and `message_id` only links the two once a sender
//     exists.
//   - A session that exists but is not CONNECTED is 503
//     session_not_connected (the OpenAPI document only lists 400 for these
//     paths; 503 matches the text route and means "retry after connecting").
//     An unknown session is 404. Both checks run before the body is parsed, so
//     they win over a malformed body.
//   - `caption` is accepted and validated but not persisted: the media record
//     has no caption field yet. Sending a caption is not an error; it is
//     simply dropped.
//   - `Idempotency-Key` is not implemented on these routes. A retry uploads
//     and stores a second attachment; clients must not rely on replay
//     protection here until a content fingerprint covers multipart bodies.
//
// Limits: one payload may be at most core/media's MaxMediaSize (64 MiB), the
// whole multipart request is capped at that plus 4 MiB of field/header
// overhead, and the in-memory store keeps at most DefaultMediaPerSession (32)
// attachments per session and DefaultMediaTotalBytes (128 MiB) of encrypted
// blobs overall, evicting oldest first.
//
// Architecture: this file depends on the Service interface, the media store
// boundary declared here, and core/media for the envelope. It must not import
// protocol/**; the PF-041 media-type strings below are the only protocol
// values it needs and are duplicated as literals on purpose.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/angga0x3/whatscore/core/media"
)

const (
	// MediaKindImage marks an attachment uploaded through
	// /messages/image; MediaKindDocument marks one from /messages/document.
	MediaKindImage = "image"
	// MediaKindDocument marks a document attachment, which accepts any MIME
	// type.
	MediaKindDocument = "document"

	// DefaultMediaPerSession bounds how many attachments one session keeps in
	// MemoryMediaStore. The oldest attachment of that session is evicted when
	// a new one would exceed the bound.
	DefaultMediaPerSession = 32
	// DefaultMediaTotalBytes bounds the encrypted bytes MemoryMediaStore keeps
	// across all sessions. The globally oldest attachment is evicted first.
	DefaultMediaTotalBytes int64 = 128 << 20 // 128 MiB

	// maxMediaFileBytes is the per-payload cap. It matches the largest
	// plaintext core/media will encrypt.
	maxMediaFileBytes = media.MaxMediaSize
	// maxMediaCaptionBytes mirrors the text message limit.
	maxMediaCaptionBytes = maxMessageTextBytes
	// maxMediaFileNameBytes bounds the recorded file name.
	maxMediaFileNameBytes = 255
	// maxMediaRequestBytes bounds the multipart body: the payload cap plus
	// headroom for fields, part headers and the boundary.
	maxMediaRequestBytes int64 = int64(maxMediaFileBytes) + 4<<20
	// multipartMemoryBytes is how much of the multipart body stays in memory
	// before net/http spills parts to temporary files. The request cap above
	// is what actually bounds the upload.
	multipartMemoryBytes = 16 << 20
)

// PF-041 HKDF info strings accepted by core/media.Encrypt. server/api must not
// import protocol/media, so the values are repeated here; a typo fails closed
// because Encrypt rejects unknown strings.
const (
	mediaTypeImage    = "WhatsApp Image Keys"
	mediaTypeDocument = "WhatsApp Document Keys"
)

// Sentinel errors returned by the media store and the upload path. Handlers
// map them onto the error envelope with errors.Is.
var (
	// ErrPayloadTooLarge is returned when an upload or stored blob exceeds a
	// configured size cap.
	ErrPayloadTooLarge = errors.New("api: media payload too large")

	// ErrUnsupportedMediaType is returned when an image payload does not
	// claim one of the accepted image MIME types.
	ErrUnsupportedMediaType = errors.New("api: unsupported media type")
)

// MediaAttachment is the stored metadata of one uploaded payload.
//
// MediaKey is the base64 (standard encoding, with padding) form of the 32-byte
// core/media key. It is write-only: the field is excluded from JSON so list and
// get responses cannot leak it, and only the create response echoes it once.
//
// SHA256 is the digest of the plaintext payload, so a reader can verify a
// download without trusting the store. The descriptor's MediaType follows from
// Kind (image → "WhatsApp Image Keys", document → "WhatsApp Document Keys");
// the rest of the descriptor is transport metadata this API does not have yet.
type MediaAttachment struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	MessageID string    `json:"message_id"`
	Kind      string    `json:"kind"`
	FileName  string    `json:"file_name"`
	MimeType  string    `json:"mime_type"`
	Size      int       `json:"size"`
	SHA256    string    `json:"sha256"`
	MediaKey  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// MediaStore is the persistence boundary for encrypted media blobs.
//
// Save stores one attachment together with its payload, which is the encrypted
// blob produced by core/media.Encrypt, not plaintext. Get returns the metadata
// and the stored blob; callers that only need metadata should implement
// mediaMetadataReader as well. List returns attachments newest first. A store
// returns ErrNotFound for an unknown id and ErrPayloadTooLarge when a blob does
// not fit its caps.
type MediaStore interface {
	Save(ctx context.Context, attachment MediaAttachment, payload []byte) error
	Get(ctx context.Context, sessionID, id string) (MediaAttachment, []byte, error)
	List(ctx context.Context, sessionID string) ([]MediaAttachment, error)
}

// mediaMetadataReader is an optional fast path for handlers that do not need
// the blob. MemoryMediaStore implements it so a metadata read never copies the
// payload.
type mediaMetadataReader interface {
	GetMetadata(ctx context.Context, sessionID, id string) (MediaAttachment, error)
}

// MemoryMediaStore is a bounded in-process MediaStore for tests and
// single-process deployments.
//
// Eviction: Save first evicts the oldest attachment of the target session until
// that session holds fewer than maxPerSession records, then evicts the globally
// oldest attachment until the new blob fits under maxBytes. A payload larger
// than the whole byte cap is rejected instead of clearing the store. Restarting
// the process clears everything; blobs live in memory only.
type MemoryMediaStore struct {
	mu            sync.RWMutex
	maxPerSession int
	maxBytes      int64
	items         []*storedMedia // ascending insertion order
	counts        map[string]int
	bytes         int64
	now           func() time.Time
}

type storedMedia struct {
	attachment MediaAttachment
	payload    []byte
}

// NewMemoryMediaStore returns a store bounded by DefaultMediaPerSession and
// DefaultMediaTotalBytes.
func NewMemoryMediaStore() *MemoryMediaStore {
	return NewMemoryMediaStoreWithLimits(DefaultMediaPerSession, DefaultMediaTotalBytes)
}

// NewMemoryMediaStoreWithLimits returns a store with explicit caps. A
// non-positive perSession or totalBytes falls back to its default.
func NewMemoryMediaStoreWithLimits(perSession int, totalBytes int64) *MemoryMediaStore {
	if perSession <= 0 {
		perSession = DefaultMediaPerSession
	}
	if totalBytes <= 0 {
		totalBytes = DefaultMediaTotalBytes
	}
	return &MemoryMediaStore{
		maxPerSession: perSession,
		maxBytes:      totalBytes,
		counts:        make(map[string]int),
		now:           func() time.Time { return time.Now().UTC() },
	}
}

// Save stores attachment and its encrypted payload. A missing id or session id
// is ErrInvalidInput; an empty or oversized blob is rejected before eviction.
// The stored blob is a copy, so the caller may reuse its slice.
func (s *MemoryMediaStore) Save(_ context.Context, attachment MediaAttachment, payload []byte) error {
	if attachment.ID == "" || attachment.SessionID == "" {
		return fmt.Errorf("%w: media id and session id are required", ErrInvalidInput)
	}
	if len(payload) == 0 {
		return fmt.Errorf("%w: empty media payload", ErrInvalidInput)
	}
	if int64(len(payload)) > s.maxBytes {
		return fmt.Errorf("%w: %d bytes exceeds the %d-byte store cap",
			ErrPayloadTooLarge, len(payload), s.maxBytes)
	}
	if attachment.CreatedAt.IsZero() {
		attachment.CreatedAt = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.findLocked(attachment.SessionID, attachment.ID); err == nil {
		return fmt.Errorf("%w: media %s already exists", ErrInvalidInput, attachment.ID)
	}
	for s.counts[attachment.SessionID] >= s.maxPerSession {
		if !s.evictOldestLocked(attachment.SessionID) {
			break
		}
	}
	for s.bytes+int64(len(payload)) > s.maxBytes {
		if !s.evictOldestLocked("") {
			break
		}
	}

	stored := &storedMedia{
		attachment: attachment,
		payload:    append([]byte(nil), payload...),
	}
	s.items = append(s.items, stored)
	s.counts[attachment.SessionID]++
	s.bytes += int64(len(payload))
	return nil
}

// Get returns one attachment and a copy of its stored blob.
func (s *MemoryMediaStore) Get(_ context.Context, sessionID, id string) (MediaAttachment, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored, err := s.findLocked(sessionID, id)
	if err != nil {
		return MediaAttachment{}, nil, err
	}
	return stored.attachment, append([]byte(nil), stored.payload...), nil
}

// GetMetadata returns one attachment without copying its blob.
func (s *MemoryMediaStore) GetMetadata(_ context.Context, sessionID, id string) (MediaAttachment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored, err := s.findLocked(sessionID, id)
	if err != nil {
		return MediaAttachment{}, err
	}
	return stored.attachment, nil
}

// List returns the session's attachments newest first.
func (s *MemoryMediaStore) List(_ context.Context, sessionID string) ([]MediaAttachment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]MediaAttachment, 0, s.counts[sessionID])
	for i := len(s.items) - 1; i >= 0; i-- {
		if s.items[i].attachment.SessionID == sessionID {
			out = append(out, s.items[i].attachment)
		}
	}
	return out, nil
}

// findLocked returns the stored record for (sessionID, id). The caller holds at
// least a read lock.
func (s *MemoryMediaStore) findLocked(sessionID, id string) (*storedMedia, error) {
	for _, stored := range s.items {
		if stored.attachment.ID == id && stored.attachment.SessionID == sessionID {
			return stored, nil
		}
	}
	return nil, fmt.Errorf("%w: media %s", ErrNotFound, id)
}

// evictOldestLocked removes the oldest attachment of sessionID, or the oldest
// attachment overall when sessionID is empty. It reports whether it removed
// anything.
func (s *MemoryMediaStore) evictOldestLocked(sessionID string) bool {
	for i, stored := range s.items {
		if sessionID != "" && stored.attachment.SessionID != sessionID {
			continue
		}
		s.bytes -= int64(len(stored.payload))
		if remaining := s.counts[stored.attachment.SessionID] - 1; remaining > 0 {
			s.counts[stored.attachment.SessionID] = remaining
		} else {
			delete(s.counts, stored.attachment.SessionID)
		}
		s.items = append(s.items[:i], s.items[i+1:]...)
		return true
	}
	return false
}

// queuedMedia is the 202 body. media_key is the one-time write of the
// core/media key; every read shape omits it.
type queuedMedia struct {
	MessageID string `json:"message_id"`
	WireID    string `json:"wire_id,omitempty"`
	MediaID   string `json:"media_id"`
	Status    string `json:"status"`
	Size      int    `json:"size"`
	SHA256    string `json:"sha256"`
	MediaKey  string `json:"media_key"`
}

type mediaListResponse struct {
	Data []MediaAttachment `json:"data"`
}

// mediaUpload is the parsed multipart request. caption is validated and then
// dropped: the media record has no caption field yet.
type mediaUpload struct {
	to       string
	caption  string
	fileName string
	mimeType string
	payload  []byte
}

// imageMimeTypes is the allowlist for /messages/image. Everything else answers
// 415 unsupported_media_type.
var imageMimeTypes = map[string]struct{}{
	"image/png":  {},
	"image/jpeg": {},
	"image/webp": {},
}

func (h *Handler) sendImage(w http.ResponseWriter, r *http.Request) {
	h.sendMedia(w, r, MediaKindImage)
}

func (h *Handler) sendDocument(w http.ResponseWriter, r *http.Request) {
	h.sendMedia(w, r, MediaKindDocument)
}

// MediaDeliverer is the optional send boundary for attachments: when set, an
// upload is delivered over the session connection and the route reports the
// wire id; when nil, the route stores the encrypted blob and answers
// "queued" (the pre-delivery behavior).
type MediaDeliverer interface {
	DeliverMedia(ctx context.Context, sessionID, to, fileName, mimeType, caption string, data []byte) (string, error)
}

// sendMedia implements both upload routes. The session checks run before the
// body is parsed so 404/503 are not masked by a malformed body.
func (h *Handler) sendMedia(w http.ResponseWriter, r *http.Request, kind string) {
	if !h.mediaStoreReady(w) {
		return
	}
	sessionID := chi.URLParam(r, "sessionId")
	session, err := h.service.GetSession(r.Context(), sessionID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	if session.Status != "CONNECTED" {
		writeError(w, http.StatusServiceUnavailable, "session_not_connected",
			fmt.Sprintf("the session is not connected (status %s)", session.Status))
		return
	}

	upload, ok := h.readMediaUpload(w, r, kind)
	if !ok {
		return
	}

	// Delivery happens first: the stored id IS the wire id, so receipts and
	// events correlate with the REST entry. Without a deliverer the route
	// keeps its record-only behavior.
	status := "queued"
	wireID := ""
	if h.mediaDeliverer != nil {
		id, err := h.mediaDeliverer.DeliverMedia(r.Context(), sessionID, upload.to, upload.fileName, upload.mimeType, upload.caption, upload.payload)
		if err != nil {
			writeError(w, http.StatusBadGateway, "delivery_failed", err.Error())
			return
		}
		wireID = id
		status = "sent"
	}

	descriptor, blob, err := media.Encrypt(upload.payload, mediaTypeFor(kind), upload.fileName)
	if err != nil {
		if errors.Is(err, media.ErrPayloadTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("file must be at most %d bytes", maxMediaFileBytes))
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
		return
	}

	messageID, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
		return
	}
	mediaID, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
		return
	}

	if wireID != "" {
		messageID = wireID
	}
	attachment := MediaAttachment{
		ID:        mediaID,
		SessionID: sessionID,
		MessageID: messageID,
		Kind:      kind,
		FileName:  upload.fileName,
		MimeType:  upload.mimeType,
		Size:      descriptor.Size,
		SHA256:    hex.EncodeToString(descriptor.SHA256[:]),
		MediaKey:  base64.StdEncoding.EncodeToString(descriptor.MediaKey[:]),
		CreatedAt: time.Now().UTC(),
	}
	// Only the encrypted blob is persisted; the plaintext is dropped here.
	if err := h.media.Save(r.Context(), attachment, blob); err != nil {
		h.writeMediaError(w, err)
		return
	}

	writeJSON(w, http.StatusAccepted, queuedMedia{
		MessageID: attachment.MessageID,
		WireID:    wireID,
		MediaID:   attachment.ID,
		Status:    status,
		Size:      attachment.Size,
		SHA256:    attachment.SHA256,
		MediaKey:  attachment.MediaKey,
	})
}

func (h *Handler) listMedia(w http.ResponseWriter, r *http.Request) {
	if !h.mediaStoreReady(w) {
		return
	}
	sessionID := chi.URLParam(r, "sessionId")
	if _, err := h.service.GetSession(r.Context(), sessionID); err != nil {
		h.writeServiceError(w, err)
		return
	}

	attachments, err := h.media.List(r.Context(), sessionID)
	if err != nil {
		h.writeMediaError(w, err)
		return
	}
	if attachments == nil {
		attachments = []MediaAttachment{}
	}
	writeJSON(w, http.StatusOK, mediaListResponse{Data: attachments})
}

func (h *Handler) getMedia(w http.ResponseWriter, r *http.Request) {
	if !h.mediaStoreReady(w) {
		return
	}
	sessionID := chi.URLParam(r, "sessionId")
	if _, err := h.service.GetSession(r.Context(), sessionID); err != nil {
		h.writeServiceError(w, err)
		return
	}

	mediaID := chi.URLParam(r, "mediaId")
	var attachment MediaAttachment
	var err error
	if reader, ok := h.media.(mediaMetadataReader); ok {
		attachment, err = reader.GetMetadata(r.Context(), sessionID, mediaID)
	} else {
		attachment, _, err = h.media.Get(r.Context(), sessionID, mediaID)
	}
	if err != nil {
		h.writeMediaError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, attachment)
}

// mediaStoreReady guards direct handler calls. Mount only registers the media
// routes when a store is configured, so normally /api/v1 falls back to the
// router's 501 not-implemented response instead.
func (h *Handler) mediaStoreReady(w http.ResponseWriter) bool {
	if h.media != nil {
		return true
	}
	writeError(w, http.StatusNotImplemented, "not_implemented", "media endpoints are not configured")
	return false
}

// readMediaUpload parses and validates the multipart request. It writes the
// error response itself and reports whether the caller may continue.
func (h *Handler) readMediaUpload(w http.ResponseWriter, r *http.Request, kind string) (mediaUpload, bool) {
	limit := h.mediaMaxRequest
	if limit <= 0 {
		limit = maxMediaRequestBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	err := r.ParseMultipartForm(multipartMemoryBytes)
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("request body must be at most %d bytes", limit))
		case errors.Is(err, http.ErrNotMultipart):
			writeError(w, http.StatusBadRequest, "validation_failed",
				"request body must be multipart/form-data")
		default:
			writeError(w, http.StatusBadRequest, "validation_failed", "malformed multipart body")
		}
		return mediaUpload{}, false
	}

	upload := mediaUpload{
		to:      formValue(r.MultipartForm, "to"),
		caption: formValue(r.MultipartForm, "caption"),
	}
	if err := validateJID(upload.to); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return mediaUpload{}, false
	}
	if len(upload.caption) > maxMediaCaptionBytes {
		writeError(w, http.StatusBadRequest, "validation_failed",
			fmt.Sprintf("caption must be at most %d bytes", maxMediaCaptionBytes))
		return mediaUpload{}, false
	}

	headers := r.MultipartForm.File["file"]
	if len(headers) == 0 {
		writeError(w, http.StatusBadRequest, "validation_failed",
			`multipart field "file" is required`)
		return mediaUpload{}, false
	}
	// Only the first "file" part is used; extra ones are ignored.
	header := headers[0]
	file, err := header.Open()
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "the uploaded file could not be read")
		return mediaUpload{}, false
	}
	defer func() { _ = file.Close() }()

	payload, err := io.ReadAll(file)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("request body must be at most %d bytes", limit))
			return mediaUpload{}, false
		}
		writeError(w, http.StatusBadRequest, "validation_failed", "the uploaded file could not be read")
		return mediaUpload{}, false
	}
	if len(payload) == 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", `the "file" part must not be empty`)
		return mediaUpload{}, false
	}
	if len(payload) > maxMediaFileBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
			fmt.Sprintf("file must be at most %d bytes", maxMediaFileBytes))
		return mediaUpload{}, false
	}

	fileName, err := resolveMediaFileName(formValue(r.MultipartForm, "file_name"), header.Filename, kind)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return mediaUpload{}, false
	}
	mimeType, err := resolveMediaMimeType(kind, formValue(r.MultipartForm, "mime_type"),
		header.Header.Get("Content-Type"), payload)
	if err != nil {
		h.writeMediaError(w, err)
		return mediaUpload{}, false
	}

	upload.fileName = fileName
	upload.mimeType = mimeType
	upload.payload = payload
	return upload, true
}

// writeMediaError maps media errors onto the shared envelope. Size and type
// failures get a stable, client-facing message instead of the internal sentinel
// text.
func (h *Handler) writeMediaError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "the requested media does not exist")
	case errors.Is(err, ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
	case errors.Is(err, ErrPayloadTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
			fmt.Sprintf("file must be at most %d bytes and fit the media store", maxMediaFileBytes))
	case errors.Is(err, ErrUnsupportedMediaType):
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type",
			"images must be image/png, image/jpeg or image/webp")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
	}
}

// formValue returns the first value of a multipart text field, or "".
func formValue(form *multipart.Form, name string) string {
	if form == nil {
		return ""
	}
	values := form.Value[name]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func mediaTypeFor(kind string) string {
	if kind == MediaKindDocument {
		return mediaTypeDocument
	}
	return mediaTypeImage
}

// resolveMediaFileName prefers the explicit file_name field, then the part's
// filename, then the kind. Directory components are stripped so a client cannot
// record a traversal-shaped name.
func resolveMediaFileName(explicit, partName, kind string) (string, error) {
	name := strings.TrimSpace(explicit)
	if name == "" {
		name = strings.TrimSpace(partName)
	}
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(name)
	if name == "." || name == "/" || name == ".." {
		name = ""
	}
	if name == "" {
		name = kind
	}
	if len(name) > maxMediaFileNameBytes {
		return "", fmt.Errorf("%w: \"file_name\" must be at most %d bytes", ErrInvalidInput, maxMediaFileNameBytes)
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] == 0x7f {
			return "", fmt.Errorf("%w: \"file_name\" must not contain control characters", ErrInvalidInput)
		}
	}
	return name, nil
}

// resolveMediaMimeType picks the reported MIME type. An explicit mime_type
// field always wins, so a client that declares application/octet-stream for a
// document keeps that type. Otherwise the part header is used, but a generic
// application/octet-stream *part* header is treated as the wire default net/http
// clients emit and the payload is sniffed instead. Images must land in
// imageMimeTypes; documents keep whatever was declared.
func resolveMediaMimeType(kind, declared, partType string, payload []byte) (string, error) {
	candidate := normalizeMimeType(declared)
	if candidate == "" {
		candidate = normalizeMimeType(partType)
		if candidate == "application/octet-stream" {
			candidate = ""
		}
	}
	if candidate == "" {
		candidate = normalizeMimeType(http.DetectContentType(payload))
	}
	if candidate == "" {
		candidate = "application/octet-stream"
	}
	if kind == MediaKindImage {
		if _, ok := imageMimeTypes[candidate]; !ok {
			return "", fmt.Errorf("%w: images must be %s, %s or %s",
				ErrUnsupportedMediaType, "image/png", "image/jpeg", "image/webp")
		}
	}
	return candidate, nil
}

// normalizeMimeType lowercases a media type and drops parameters such as
// charset, so "image/PNG; charset=binary" and "image/png" compare equal.
func normalizeMimeType(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, _, err := mime.ParseMediaType(raw); err == nil {
		return strings.ToLower(parsed)
	}
	if i := strings.IndexByte(raw, ';'); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}
