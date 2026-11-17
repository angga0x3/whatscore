package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"testing"

	"github.com/angga0x3/whatscore/core/media"
)

// mediaFixture is a router with sessions, messaging, media, and webhooks wired.
type mediaFixture struct {
	router   http.Handler
	handler  *Handler
	manager  *Manager
	media    *MemoryMediaStore
	messages *MemoryMessageStore
	webhooks *MemoryWebhookStore
	session  SessionView
}

func newMediaFixture(t *testing.T) *mediaFixture {
	t.Helper()
	return newMediaFixtureWithStore(t, NewMemoryMediaStore())
}

func newMediaFixtureWithStore(t *testing.T, store *MemoryMediaStore) *mediaFixture {
	t.Helper()

	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	messages := NewMemoryMessageStore()
	webhooks := NewMemoryWebhookStore()
	handler, err := NewHandlerWithWebhooks(manager, webhooks)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetMessages(messages)
	handler.SetMedia(store)

	session, err := manager.CreateSession(t.Context(), "media")
	if err != nil {
		t.Fatal(err)
	}
	return &mediaFixture{
		router:   newV1Router(handler),
		handler:  handler,
		manager:  manager,
		media:    store,
		messages: messages,
		webhooks: webhooks,
		session:  session,
	}
}

func (f *mediaFixture) connect(t *testing.T) {
	t.Helper()
	if err := f.manager.ConnectSession(t.Context(), f.session.ID); err != nil {
		t.Fatal(err)
	}
}

// buildMediaMultipart assembles a real multipart/form-data body. fields are
// written in order so two calls with the same input produce identical bytes.
// A nil payload with an empty fileName omits the file part entirely.
func buildMediaMultipart(t *testing.T, fields [][2]string, fileName, partType string, payload []byte) ([]byte, string) {
	t.Helper()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	for _, field := range fields {
		if err := writer.WriteField(field[0], field[1]); err != nil {
			t.Fatal(err)
		}
	}
	if fileName != "" || payload != nil {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name="file"; filename=%q`, fileName))
		if partType != "" {
			header.Set("Content-Type", partType)
		}
		part, err := writer.CreatePart(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), writer.FormDataContentType()
}

func (f *mediaFixture) postMedia(t *testing.T, sessionID, kind string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/sessions/"+sessionID+"/messages/"+kind, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f *mediaFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// upload posts one attachment with as few knobs as possible.
func (f *mediaFixture) upload(t *testing.T, kind, fileName, mimeType string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	fields := [][2]string{{"to", "6281234567890@s.whatsapp.net"}}
	if mimeType != "" {
		fields = append(fields, [2]string{"mime_type", mimeType})
	}
	body, contentType := buildMediaMultipart(t, fields, fileName, mimeType, payload)
	return f.postMedia(t, f.session.ID, kind, body, contentType)
}

// tinyPNG is enough of a PNG for both a declared image/png and a content sniff.
var tinyPNG = append([]byte("\x89PNG\r\n\x1a\n"), []byte("IHDR....")...)

// tinyJPEG carries the JPEG SOI marker DetectContentType recognizes.
var tinyJPEG = append([]byte("\xff\xd8\xff\xe0"), []byte("JFIF....")...)

func mustQueuedMedia(t *testing.T, rec *httptest.ResponseRecorder) queuedMedia {
	t.Helper()
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	return decodeJSON[queuedMedia](t, rec)
}

func TestSendImageQueuedAndReadBack(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	payload := append(append([]byte(nil), tinyPNG...), []byte(" image body")...)
	queued := mustQueuedMedia(t, f.upload(t, MediaKindImage, "photo.png", "image/png", payload))

	if queued.Status != "queued" || queued.MessageID == "" || queued.MediaID == "" {
		t.Fatalf("queued = %#v", queued)
	}
	if len(queued.MessageID) != 36 || len(queued.MediaID) != 36 {
		t.Fatalf("ids = %q / %q, want uuids", queued.MessageID, queued.MediaID)
	}
	if queued.Size != len(payload) {
		t.Fatalf("size = %d, want %d", queued.Size, len(payload))
	}
	wantSHA := sha256.Sum256(payload)
	if queued.SHA256 != hex.EncodeToString(wantSHA[:]) {
		t.Fatalf("sha256 = %q, want %x", queued.SHA256, wantSHA)
	}
	key, err := base64.StdEncoding.DecodeString(queued.MediaKey)
	if err != nil || len(key) != 32 {
		t.Fatalf("media_key = %q (err %v), want 32 base64 bytes", queued.MediaKey, err)
	}

	// The store holds ciphertext, and the returned key is the one that
	// decrypts it back to the original bytes.
	attachment, blob, err := f.media.Get(t.Context(), f.session.ID, queued.MediaID)
	if err != nil {
		t.Fatal(err)
	}
	if attachment.MediaKey != queued.MediaKey {
		t.Fatal("stored attachment lost its media key")
	}
	if bytes.Contains(blob, payload) {
		t.Fatal("stored blob still contains the plaintext")
	}
	descriptor := &media.Descriptor{
		MediaType: mediaTypeFor(attachment.Kind),
		FileName:  attachment.FileName,
		Size:      attachment.Size,
		SHA256:    sha256.Sum256(payload),
		EncSHA256: sha256.Sum256(blob),
	}
	copy(descriptor.MediaKey[:], key)
	plaintext, err := media.Decrypt(blob, descriptor)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatal("decrypt did not round-trip the payload")
	}

	// List returns the metadata without the key.
	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body %s", rec.Code, rec.Body)
	}
	list := decodeJSON[mediaListResponse](t, rec)
	if len(list.Data) != 1 {
		t.Fatalf("list = %#v", list.Data)
	}
	listed := list.Data[0]
	if listed.ID != queued.MediaID || listed.MessageID != queued.MessageID ||
		listed.Kind != MediaKindImage || listed.MimeType != "image/png" ||
		listed.FileName != "photo.png" || listed.CreatedAt.IsZero() {
		t.Fatalf("listed = %#v", listed)
	}
	if listed.MediaKey != "" {
		t.Fatalf("listed media key = %q, want empty", listed.MediaKey)
	}
	raw := rec.Body.String()
	if strings.Contains(raw, "media_key") {
		t.Fatalf("list body has a media_key field: %s", raw)
	}
	if strings.Contains(raw, queued.MediaKey) {
		t.Fatalf("list body leaked the media key: %s", raw)
	}

	// Get returns the metadata, also without the key.
	rec = f.get(t, "/api/v1/sessions/"+f.session.ID+"/media/"+queued.MediaID)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body %s", rec.Code, rec.Body)
	}
	got := decodeJSON[MediaAttachment](t, rec)
	if got.ID != queued.MediaID || got.SHA256 != queued.SHA256 || got.MessageID != queued.MessageID {
		t.Fatalf("get = %#v", got)
	}
	if strings.Contains(rec.Body.String(), queued.MediaKey) {
		t.Fatalf("get body leaked the media key: %s", rec.Body)
	}
}

func TestSendDocumentAcceptsAnyType(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	cases := []struct {
		name     string
		file     string
		declared string
		payload  []byte
		want     string
	}{
		{"pdf", "report.pdf", "application/pdf", []byte("%PDF-1.7 contract"), "application/pdf"},
		{"csv", "rows.csv", "text/csv", []byte("a,b\n1,2\n"), "text/csv"},
		{"no declared type falls back to sniffing", "notes.txt", "", []byte("plain words"), "text/plain"},
		{"unknown but harmless type", "blob.bin", "application/x-whatscore", []byte{0x00, 0x01, 0x02}, "application/x-whatscore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			queued := mustQueuedMedia(t, f.upload(t, MediaKindDocument, tc.file, tc.declared, tc.payload))
			if queued.Size != len(tc.payload) {
				t.Fatalf("size = %d, want %d", queued.Size, len(tc.payload))
			}
			rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media/"+queued.MediaID)
			if rec.Code != http.StatusOK {
				t.Fatalf("get status = %d, body %s", rec.Code, rec.Body)
			}
			got := decodeJSON[MediaAttachment](t, rec)
			if got.Kind != MediaKindDocument {
				t.Fatalf("kind = %q", got.Kind)
			}
			if got.MimeType != tc.want {
				t.Fatalf("mime = %q, want %q", got.MimeType, tc.want)
			}
			if got.FileName != tc.file {
				t.Fatalf("file_name = %q, want %q", got.FileName, tc.file)
			}
		})
	}

	// A document may also carry an image type; the kind decides the route,
	// not the MIME allowlist.
	queued := mustQueuedMedia(t, f.upload(t, MediaKindDocument, "scan.png", "image/png", tinyPNG))
	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media/"+queued.MediaID)
	if got := decodeJSON[MediaAttachment](t, rec); got.Kind != MediaKindDocument {
		t.Fatalf("kind = %q", got.Kind)
	}
}

func TestSendImageSniffsUndeclaredType(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	// No mime_type field and an octet-stream part type: the PNG signature is
	// the only evidence, and it is accepted.
	fields := [][2]string{{"to", "6281234567890@s.whatsapp.net"}}
	body, contentType := buildMediaMultipart(t, fields, "photo.png", "application/octet-stream", tinyPNG)
	queued := mustQueuedMedia(t, f.postMedia(t, f.session.ID, MediaKindImage, body, contentType))
	if queued.Size != len(tinyPNG) {
		t.Fatalf("size = %d, want %d", queued.Size, len(tinyPNG))
	}
	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media/"+queued.MediaID)
	if got := decodeJSON[MediaAttachment](t, rec); got.MimeType != "image/png" {
		t.Fatalf("mime = %q, want image/png", got.MimeType)
	}

	// The JPEG signature sniffs to image/jpeg.
	body, contentType = buildMediaMultipart(t, fields, "photo.jpg", "", tinyJPEG)
	mustQueuedMedia(t, f.postMedia(t, f.session.ID, MediaKindImage, body, contentType))
}

func TestSendImageRejectsUnsupportedType(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	cases := []struct {
		name     string
		fileName string
		mimeType string
	}{
		{"gif", "anim.gif", "image/gif"},
		{"bmp", "image.bmp", "image/bmp"},
		{"svg", "vector.svg", "image/svg+xml"},
		{"document type on the image route", "doc.pdf", "application/pdf"},
		{"declared type wins over sniffing", "photo.png", "image/gif"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.upload(t, MediaKindImage, tc.fileName, tc.mimeType, []byte("not a real image"))
			if rec.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415 (body %s)", rec.Code, rec.Body)
			}
			if code := errorCode(t, rec); code != "unsupported_media_type" {
				t.Fatalf("code = %q", code)
			}
		})
	}

	// Nothing was stored by any rejected attempt.
	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media")
	if list := decodeJSON[mediaListResponse](t, rec); len(list.Data) != 0 {
		t.Fatalf("list = %#v, want empty", list.Data)
	}
}

func TestSendMediaValidation(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	to := [2]string{"to", "6281234567890@s.whatsapp.net"}
	cases := []struct {
		name string
		kind string
		body func(t *testing.T) ([]byte, string)
		want int
		code string
	}{
		{
			name: "missing to",
			kind: MediaKindImage,
			body: func(t *testing.T) ([]byte, string) {
				return buildMediaMultipart(t, nil, "a.png", "image/png", tinyPNG)
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
		{
			name: "empty to",
			kind: MediaKindImage,
			body: func(t *testing.T) ([]byte, string) {
				return buildMediaMultipart(t, [][2]string{{"to", ""}}, "a.png", "image/png", tinyPNG)
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
		{
			name: "to without at sign",
			kind: MediaKindDocument,
			body: func(t *testing.T) ([]byte, string) {
				return buildMediaMultipart(t, [][2]string{{"to", "6281234567890"}}, "a.pdf", "application/pdf", []byte("%PDF"))
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
		{
			name: "to with whitespace",
			kind: MediaKindDocument,
			body: func(t *testing.T) ([]byte, string) {
				return buildMediaMultipart(t, [][2]string{{"to", "628 123@s.whatsapp.net"}}, "a.pdf", "application/pdf", []byte("%PDF"))
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
		{
			name: "empty file",
			kind: MediaKindImage,
			body: func(t *testing.T) ([]byte, string) {
				return buildMediaMultipart(t, [][2]string{to}, "empty.png", "image/png", []byte{})
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
		{
			name: "missing file part",
			kind: MediaKindDocument,
			body: func(t *testing.T) ([]byte, string) {
				return buildMediaMultipart(t, [][2]string{to}, "", "", nil)
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
		{
			name: "caption too long",
			kind: MediaKindDocument,
			body: func(t *testing.T) ([]byte, string) {
				return buildMediaMultipart(t, [][2]string{to, {"caption", strings.Repeat("c", maxMediaCaptionBytes+1)}},
					"a.pdf", "application/pdf", []byte("%PDF"))
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
		{
			name: "file_name too long",
			kind: MediaKindDocument,
			body: func(t *testing.T) ([]byte, string) {
				return buildMediaMultipart(t, [][2]string{to, {"file_name", strings.Repeat("f", maxMediaFileNameBytes+1)}},
					"a.pdf", "application/pdf", []byte("%PDF"))
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
		{
			name: "not multipart",
			kind: MediaKindImage,
			body: func(_ *testing.T) ([]byte, string) {
				return []byte(`{"to":"a@b"}`), "application/json"
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
		{
			name: "truncated multipart",
			kind: MediaKindImage,
			body: func(t *testing.T) ([]byte, string) {
				body, contentType := buildMediaMultipart(t, [][2]string{to}, "a.png", "image/png", tinyPNG)
				return body[:len(body)/2], contentType
			},
			want: http.StatusBadRequest,
			code: "validation_failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, contentType := tc.body(t)
			rec := f.postMedia(t, f.session.ID, tc.kind, body, contentType)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
			if code := errorCode(t, rec); code != tc.code {
				t.Fatalf("code = %q, want %q", code, tc.code)
			}
		})
	}

	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media")
	if list := decodeJSON[mediaListResponse](t, rec); len(list.Data) != 0 {
		t.Fatalf("list = %#v, want empty", list.Data)
	}
}

func TestMediaRouteNamesAreSanitised(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	// A traversal-shaped part filename is reduced to its base name.
	fields := [][2]string{{"to", "a@b"}}
	body, contentType := buildMediaMultipart(t, fields, "../../etc/passwd", "text/plain", []byte("x"))
	queued := mustQueuedMedia(t, f.postMedia(t, f.session.ID, MediaKindDocument, body, contentType))

	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media/"+queued.MediaID)
	if got := decodeJSON[MediaAttachment](t, rec); got.FileName != "passwd" {
		t.Fatalf("file_name = %q, want passwd", got.FileName)
	}

	// An explicit file_name wins over the part filename.
	fields = append(fields, [2]string{"file_name", "quarterly report.pdf"})
	body, contentType = buildMediaMultipart(t, fields, "upload.pdf", "application/pdf", []byte("%PDF"))
	queued = mustQueuedMedia(t, f.postMedia(t, f.session.ID, MediaKindDocument, body, contentType))
	rec = f.get(t, "/api/v1/sessions/"+f.session.ID+"/media/"+queued.MediaID)
	if got := decodeJSON[MediaAttachment](t, rec); got.FileName != "quarterly report.pdf" {
		t.Fatalf("file_name = %q", got.FileName)
	}
}

func TestMediaUnknownSession(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	body, contentType := buildMediaMultipart(t, [][2]string{{"to", "a@b"}}, "a.png", "image/png", tinyPNG)
	for _, kind := range []string{MediaKindImage, MediaKindDocument} {
		rec := f.postMedia(t, "does-not-exist", kind, body, contentType)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404 (body %s)", kind, rec.Code, rec.Body)
		}
		if code := errorCode(t, rec); code != "not_found" {
			t.Fatalf("%s code = %q", kind, code)
		}
	}

	// The session is checked before the body, so a malformed body still 404s.
	rec := f.postMedia(t, "does-not-exist", MediaKindImage, []byte("nope"), "application/json")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("malformed body status = %d, want 404", rec.Code)
	}

	rec = f.get(t, "/api/v1/sessions/does-not-exist/media")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list status = %d, want 404", rec.Code)
	}
	rec = f.get(t, "/api/v1/sessions/does-not-exist/media/abc")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get status = %d, want 404", rec.Code)
	}
}

func TestMediaRequiresConnectedSession(t *testing.T) {
	f := newMediaFixture(t)

	body, contentType := buildMediaMultipart(t, [][2]string{{"to", "a@b"}}, "a.png", "image/png", tinyPNG)
	for _, kind := range []string{MediaKindImage, MediaKindDocument} {
		rec := f.postMedia(t, f.session.ID, kind, body, contentType)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status = %d, want 503 (body %s)", kind, rec.Code, rec.Body)
		}
		if code := errorCode(t, rec); code != "session_not_connected" {
			t.Fatalf("%s code = %q", kind, code)
		}
	}
	if list, err := f.media.List(t.Context(), f.session.ID); err != nil || len(list) != 0 {
		t.Fatalf("list = %#v, err %v; want empty", list, err)
	}

	// Reading metadata still works while disconnected; only uploads need a
	// live session.
	f.connect(t)
	queued := mustQueuedMedia(t, f.postMedia(t, f.session.ID, MediaKindImage, body, contentType))
	if err := f.manager.DisconnectSession(t.Context(), f.session.ID); err != nil {
		t.Fatal(err)
	}
	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media/"+queued.MediaID)
	if rec.Code != http.StatusOK {
		t.Fatalf("get while disconnected status = %d", rec.Code)
	}
}

func TestMediaGetNotFound(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media/00000000-0000-4000-8000-000000000000")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", rec.Code, rec.Body)
	}
	if code := errorCode(t, rec); code != "not_found" {
		t.Fatalf("code = %q", code)
	}

	// Ids are scoped per session: another session cannot read this one's
	// attachment even with the exact id.
	queued := mustQueuedMedia(t, f.upload(t, MediaKindImage, "photo.png", "image/png", tinyPNG))
	other, err := f.manager.CreateSession(t.Context(), "other")
	if err != nil {
		t.Fatal(err)
	}
	rec = f.get(t, "/api/v1/sessions/"+other.ID+"/media/"+queued.MediaID)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-session get status = %d, want 404", rec.Code)
	}
	if list := decodeJSON[mediaListResponse](t, f.get(t, "/api/v1/sessions/"+other.ID+"/media")); len(list.Data) != 0 {
		t.Fatalf("other session list = %#v, want empty", list.Data)
	}
}

func TestMediaListEmptyIsAnArray(t *testing.T) {
	f := newMediaFixture(t)

	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"data":[]}` {
		t.Fatalf("body = %s, want an empty array", got)
	}
}

func TestMediaRequestTooLarge(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	body, contentType := buildMediaMultipart(t, [][2]string{{"to", "a@b"}}, "a.png", "image/png", tinyPNG)

	// Exactly at the cap the request is still served.
	f.handler.SetMediaRequestLimit(int64(len(body)))
	rec := f.postMedia(t, f.session.ID, MediaKindImage, body, contentType)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("at cap status = %d, want 202 (body %s)", rec.Code, rec.Body)
	}

	// One byte over the cap is rejected before anything is stored.
	f.handler.SetMediaRequestLimit(int64(len(body)) - 1)
	rec = f.postMedia(t, f.session.ID, MediaKindImage, body, contentType)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over cap status = %d, want 413 (body %s)", rec.Code, rec.Body)
	}
	if code := errorCode(t, rec); code != "payload_too_large" {
		t.Fatalf("code = %q", code)
	}
	if list, err := f.media.List(t.Context(), f.session.ID); err != nil || len(list) != 1 {
		t.Fatalf("list = %#v, err %v; want the one accepted upload", list, err)
	}

	// The default limit leaves room for the largest payload plus the
	// multipart framing, so a maximum-size file is not rejected early.
	if maxMediaRequestBytes <= int64(maxMediaFileBytes) {
		t.Fatalf("request cap %d does not cover a %d-byte payload", maxMediaRequestBytes, maxMediaFileBytes)
	}
}

// TestMediaStoreCapAnswers413 covers the store's own byte cap, which the
// handler maps onto the same payload_too_large envelope.
func TestMediaStoreCapAnswers413(t *testing.T) {
	store := NewMemoryMediaStoreWithLimits(10, 64)
	f := newMediaFixtureWithStore(t, store)
	f.connect(t)

	rec := f.upload(t, MediaKindDocument, "a.bin", "application/octet-stream", bytes.Repeat([]byte("a"), 256))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body %s)", rec.Code, rec.Body)
	}
	if code := errorCode(t, rec); code != "payload_too_large" {
		t.Fatalf("code = %q", code)
	}
}

func TestMediaEvictionPerSession(t *testing.T) {
	store := NewMemoryMediaStoreWithLimits(2, DefaultMediaTotalBytes)
	f := newMediaFixtureWithStore(t, store)
	f.connect(t)

	var ids []string
	for i := 0; i < 3; i++ {
		queued := mustQueuedMedia(t, f.upload(t, MediaKindDocument,
			fmt.Sprintf("doc-%d.txt", i), "text/plain", []byte(fmt.Sprintf("payload-%d", i))))
		ids = append(ids, queued.MediaID)
	}

	list, err := store.List(t.Context(), f.session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("list = %d attachments, want 2", len(list))
	}
	// Newest first, and the oldest upload was evicted.
	if list[0].ID != ids[2] || list[1].ID != ids[1] {
		t.Fatalf("list ids = %q, want newest first", []string{list[0].ID, list[1].ID})
	}
	if _, _, err := store.Get(t.Context(), f.session.ID, ids[0]); err == nil {
		t.Fatal("oldest attachment was not evicted")
	}
	// The handler agrees: the evicted id is 404 now.
	rec := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media/"+ids[0])
	if rec.Code != http.StatusNotFound {
		t.Fatalf("evicted get status = %d, want 404", rec.Code)
	}

	// Eviction is per session: another session's attachments are untouched.
	other, err := f.manager.CreateSession(t.Context(), "other")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.ConnectSession(t.Context(), other.ID); err != nil {
		t.Fatal(err)
	}
	otherBody, otherType := buildMediaMultipart(t, [][2]string{{"to", "a@b"}},
		"other.txt", "text/plain", []byte("other payload"))
	otherQueued := mustQueuedMedia(t, f.postMedia(t, other.ID, MediaKindDocument, otherBody, otherType))
	if _, _, err := store.Get(t.Context(), other.ID, otherQueued.MediaID); err != nil {
		t.Fatalf("other session attachment: %v", err)
	}
}

func TestMediaEvictionTotalBytes(t *testing.T) {
	// Each 32-byte payload encrypts to 48 padded bytes plus a 10-byte MAC: 58
	// bytes per blob. A 150-byte cap holds two (116), and the third evicts the
	// globally oldest to make room.
	store := NewMemoryMediaStoreWithLimits(10, 150)
	f := newMediaFixtureWithStore(t, store)
	f.connect(t)

	payload := bytes.Repeat([]byte("p"), 32)
	var ids []string
	for i := 0; i < 3; i++ {
		queued := mustQueuedMedia(t, f.upload(t, MediaKindDocument, "d.bin", "application/octet-stream", payload))
		ids = append(ids, queued.MediaID)
	}

	list, err := store.List(t.Context(), f.session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("list = %d attachments, want 2 under the byte cap", len(list))
	}
	if list[0].ID != ids[2] {
		t.Fatalf("newest = %q, want %q", list[0].ID, ids[2])
	}
	if _, _, err := store.Get(t.Context(), f.session.ID, ids[0]); err == nil {
		t.Fatal("globally oldest attachment was not evicted")
	}
	if store.bytes > store.maxBytes {
		t.Fatalf("store bytes = %d, cap = %d", store.bytes, store.maxBytes)
	}
}

func TestMediaStoreSaveRejectsOversizedBlob(t *testing.T) {
	store := NewMemoryMediaStoreWithLimits(4, 16)
	err := store.Save(t.Context(), MediaAttachment{ID: "m1", SessionID: "s1"}, bytes.Repeat([]byte("a"), 17))
	if err == nil {
		t.Fatal("oversized blob was accepted")
	}
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
	}
	if list, _ := store.List(t.Context(), "s1"); len(list) != 0 {
		t.Fatalf("list = %#v, want empty", list)
	}
}

func TestMediaConcurrentUploads(t *testing.T) {
	store := NewMemoryMediaStoreWithLimits(64, DefaultMediaTotalBytes)
	f := newMediaFixtureWithStore(t, store)
	f.connect(t)

	const workers = 8
	var wg sync.WaitGroup
	codes := make([]int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("payload-%d", i))
			rec := f.upload(t, MediaKindDocument, fmt.Sprintf("f-%d.txt", i), "text/plain", payload)
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusAccepted {
			t.Fatalf("upload %d status = %d", i, code)
		}
	}
	list, err := store.List(t.Context(), f.session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != workers {
		t.Fatalf("list = %d attachments, want %d", len(list), workers)
	}
}

func TestMediaRoutesNotMountedWithoutStore(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(manager)
	if err != nil {
		t.Fatal(err)
	}
	router := newV1Router(handler)

	body, contentType := buildMediaMultipart(t, [][2]string{{"to", "a@b"}}, "a.png", "image/png", tinyPNG)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/x/messages/image", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 (body %s)", rec.Code, rec.Body)
	}
	if code := errorCode(t, rec); code != "not_implemented" {
		t.Fatalf("code = %q", code)
	}
}

// TestExistingRoutesStillWork is the regression guard for the shared handler:
// adding the media routes must not disturb sessions, text messages, or
// webhooks.
func TestExistingRoutesStillWork(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)

	// Sessions: create and list.
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/sessions",
		strings.NewReader(`{"name":"regression"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create session status = %d, body %s", rec.Code, rec.Body)
	}
	created := decodeJSON[SessionView](t, rec)

	rec = f.get(t, "/api/v1/sessions")
	if rec.Code != http.StatusOK {
		t.Fatalf("list sessions status = %d", rec.Code)
	}
	sessions := decodeJSON[struct {
		Data []SessionView `json:"data"`
	}](t, rec)
	if len(sessions.Data) != 2 {
		t.Fatalf("sessions = %#v", sessions.Data)
	}

	// Text messages: send, then read back.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+created.ID+"/messages/text",
		strings.NewReader(`{"to":"6281234567890@s.whatsapp.net","text":"halo"}`))
	req.Header.Set("Content-Type", "application/json")
	f.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("text on a stopped session status = %d, want 503", rec.Code)
	}

	rec = httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost,
		"/api/v1/sessions/"+f.session.ID+"/messages/text",
		strings.NewReader(`{"to":"6281234567890@s.whatsapp.net","text":"halo"}`)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send text status = %d, body %s", rec.Code, rec.Body)
	}
	sent := decodeJSON[struct {
		MessageID string `json:"message_id"`
	}](t, rec)
	rec = f.get(t, "/api/v1/sessions/"+f.session.ID+"/messages/"+sent.MessageID)
	if rec.Code != http.StatusOK {
		t.Fatalf("get text status = %d", rec.Code)
	}
	if msg := decodeJSON[MessageView](t, rec); msg.Text != "halo" {
		t.Fatalf("message = %#v", msg)
	}

	// Webhooks: create, list, get, delete.
	rec = httptest.NewRecorder()
	f.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/webhooks",
		strings.NewReader(`{"url":"https://example.com/hook","events":["message.received"]}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create webhook status = %d, body %s", rec.Code, rec.Body)
	}
	webhook := decodeJSON[WebhookView](t, rec)
	rec = f.get(t, "/api/v1/webhooks/"+webhook.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("get webhook status = %d", rec.Code)
	}
	if got := decodeJSON[WebhookView](t, rec); got.URL != "https://example.com/hook" {
		t.Fatalf("webhook = %#v", got)
	}
	rec = f.get(t, "/api/v1/webhooks")
	if rec.Code != http.StatusOK {
		t.Fatalf("list webhooks status = %d", rec.Code)
	}
}

// TestMediaAttachmentJSONOmitsKey pins the wire shape: MediaKey is tagged
// json:"-" so no encoder path can serialise it.
func TestMediaAttachmentJSONOmitsKey(t *testing.T) {
	raw, err := json.Marshal(MediaAttachment{
		ID: "m1", SessionID: "s1", MessageID: "x1", Kind: MediaKindImage,
		FileName: "a.png", MimeType: "image/png", Size: 3, SHA256: "ab",
		MediaKey: "c2VjcmV0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "c2VjcmV0") || strings.Contains(string(raw), "media_key") {
		t.Fatalf("marshalled attachment leaks the key: %s", raw)
	}
	for _, field := range []string{`"id"`, `"session_id"`, `"message_id"`, `"kind"`, `"file_name"`, `"mime_type"`, `"size"`, `"sha256"`, `"created_at"`} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("marshalled attachment is missing %s: %s", field, raw)
		}
	}
}

// mediaDelivererStub records what the route handed to the send boundary.
type mediaDelivererStub struct {
	id  string
	err error
	got struct {
		sessionID, to, fileName, mimeType, caption string
		payload                                    []byte
	}
	calls int
}

func (d *mediaDelivererStub) DeliverMedia(_ context.Context, sessionID, to, fileName, mimeType, caption string, data []byte) (string, error) {
	d.calls++
	d.got.sessionID, d.got.to, d.got.fileName, d.got.mimeType, d.got.caption = sessionID, to, fileName, mimeType, caption
	d.got.payload = append([]byte(nil), data...)
	return d.id, d.err
}

// TestSendImageDeliversWhenConfigured pins the delivery boundary: with a
// deliverer installed the upload is sent, the route reports the wire id, and
// the stored record is keyed by it so receipts correlate.
func TestSendImageDeliversWhenConfigured(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)
	deliverer := &mediaDelivererStub{id: "WIRE1"}
	f.handler.SetMediaDeliverer(deliverer)

	payload := append(append([]byte(nil), tinyPNG...), []byte(" body")...)
	rec := f.upload(t, MediaKindImage, "photo.png", "image/png", payload)
	queued := mustQueuedMedia(t, rec)

	if queued.Status != "sent" || queued.WireID != "WIRE1" || queued.MessageID != "WIRE1" {
		t.Fatalf("queued = %#v", queued)
	}
	if deliverer.calls != 1 {
		t.Fatalf("deliver calls = %d, want 1", deliverer.calls)
	}
	if deliverer.got.to != "6281234567890@s.whatsapp.net" ||
		deliverer.got.fileName != "photo.png" ||
		deliverer.got.mimeType != "image/png" ||
		deliverer.got.sessionID != f.session.ID {
		t.Fatalf("deliver args = %#v", deliverer.got)
	}
	if !bytes.Equal(deliverer.got.payload, payload) {
		t.Fatal("deliverer did not receive the plaintext")
	}

	// The record exists under the wire id and still holds ciphertext.
	attachment, blob, err := f.media.Get(t.Context(), f.session.ID, queued.MediaID)
	if err != nil {
		t.Fatal(err)
	}
	if attachment.MessageID != "WIRE1" {
		t.Fatalf("stored message id = %q", attachment.MessageID)
	}
	if bytes.Contains(blob, payload) {
		t.Fatal("stored blob contains the plaintext")
	}
}

// TestSendImageDeliveryFailureIsBadGateway keeps a failed send from storing a
// record that claims the message went out.
func TestSendImageDeliveryFailureIsBadGateway(t *testing.T) {
	f := newMediaFixture(t)
	f.connect(t)
	f.handler.SetMediaDeliverer(&mediaDelivererStub{err: errors.New("cdn refused")})

	rec := f.upload(t, MediaKindImage, "photo.png", "image/png", tinyPNG)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if list := f.get(t, "/api/v1/sessions/"+f.session.ID+"/media"); !strings.Contains(list.Body.String(), `"data":[]`) {
		t.Fatalf("failed delivery stored a record: %s", list.Body)
	}
}
