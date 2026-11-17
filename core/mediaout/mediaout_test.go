package mediaout

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	stanza "github.com/angga0x3/whatscore/protocol/messaging"
)

// TestBuildEncryptsUploadsAndFillsTheMessage pins the whole pipeline against
// a real HTTP server: the body is an encrypted blob (not the plaintext), the
// request names the image class, and the message carries the upload location
// with the envelope's digests and key.
func TestBuildEncryptsUploadsAndFillsTheMessage(t *testing.T) {
	plaintext := []byte("not-a-real-png-but-bytes")
	sum := sha256.Sum256(plaintext)

	var gotBody []byte
	var gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"url":"https://mmg.whatsapp.net/x","direct_path":"/v/t62/x"}`))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	connect := func(context.Context) (*Connection, error) {
		return &Connection{Auth: "AUTH", Host: host}, nil
	}
	result, err := Build(context.Background(), srv.Client(), connect, File{
		Name: "photo.png", MimeType: "image/png", Caption: "pantai", Data: plaintext,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if result.Kind != stanza.PayloadImage {
		t.Fatalf("kind = %q", result.Kind)
	}
	if result.Size != len(plaintext) {
		t.Fatalf("size = %d", result.Size)
	}
	if strings.HasPrefix(gotPath, "/mms/image/") == false {
		t.Fatalf("path = %q", gotPath)
	}
	// The uploaded bytes are the ciphertext: same length or padded, and never
	// the plaintext itself.
	if string(gotBody) == string(plaintext) {
		t.Fatal("plaintext was uploaded")
	}
	blobSum := sha256.Sum256(gotBody)
	if !strings.HasPrefix(gotPath, "/mms/image/"+base64.URLEncoding.EncodeToString(blobSum[:])) {
		t.Fatalf("token is not the uploaded blob's hash: %q", gotPath)
	}

	img := result.Message.GetImageMessage()
	if img == nil {
		t.Fatal("imageMessage missing")
	}
	if img.GetUrl() != "https://mmg.whatsapp.net/x" || img.GetDirectPath() != "/v/t62/x" {
		t.Fatalf("location = %q %q", img.GetUrl(), img.GetDirectPath())
	}
	if img.GetCaption() != "pantai" || img.GetMimetype() != "image/png" {
		t.Fatalf("caption/mime = %q %q", img.GetCaption(), img.GetMimetype())
	}
	if img.GetFileLength() != uint64(len(plaintext)) {
		t.Fatalf("length = %d", img.GetFileLength())
	}
	// The digest the message carries is the plaintext's, and the key is 32
	// bytes: those are what the recipient decrypts with.
	if string(img.GetFileSHA256()) != string(sum[:]) {
		t.Fatal("fileSHA256 is not the plaintext digest")
	}
	if len(img.GetMediaKey()) != 32 {
		t.Fatalf("media key is %d bytes", len(img.GetMediaKey()))
	}
}

// TestBuildDocument pins the second kind the project sends.
func TestBuildDocument(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"url":"https://mmg.whatsapp.net/d","direct_path":"/v/t62/d"}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	connect := func(context.Context) (*Connection, error) {
		return &Connection{Auth: "A", Host: host}, nil
	}
	result, err := Build(context.Background(), srv.Client(), connect, File{
		Name: "laporan.pdf", MimeType: "application/pdf", Data: []byte("%PDF-1.4"),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if result.Message.GetDocumentMessage().GetFileName() != "laporan.pdf" {
		t.Fatalf("document = %#v", result.Message.GetDocumentMessage())
	}
}

// TestBuildFailsClosed covers the inputs a send must refuse rather than
// upload something broken.
func TestBuildFailsClosed(t *testing.T) {
	client := &http.Client{}
	ok := func(context.Context) (*Connection, error) { return &Connection{Auth: "a", Host: "h"}, nil }
	cases := map[string]struct {
		client  *http.Client
		connect ConnFunc
		file    File
	}{
		"nil client":  {nil, ok, File{Name: "a", MimeType: "image/png", Data: []byte{1}}},
		"nil connect": {client, nil, File{Name: "a", MimeType: "image/png", Data: []byte{1}}},
		"empty file":  {client, ok, File{Name: "a", MimeType: "image/png"}},
		"bad mime":    {client, ok, File{Name: "a", MimeType: "video/mp4", Data: []byte{1}}},
		"empty conn":  {client, func(context.Context) (*Connection, error) { return &Connection{}, nil }, File{Name: "a", MimeType: "image/png", Data: []byte{1}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(context.Background(), tc.client, tc.connect, tc.file); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestKindFor pins the MIME table both callers share.
func TestKindFor(t *testing.T) {
	cases := map[string]stanza.PayloadKind{
		"image/jpeg":               stanza.PayloadImage,
		"image/webp":               stanza.PayloadImage,
		"application/pdf":          stanza.PayloadDocument,
		"text/plain":               stanza.PayloadDocument,
		"application/octet-stream": stanza.PayloadDocument,
	}
	for mimeType, want := range cases {
		kind, _, err := KindFor(mimeType)
		if err != nil || kind != want {
			t.Fatalf("KindFor(%q) = %q, %v", mimeType, kind, err)
		}
	}
	if _, _, err := KindFor("video/mp4"); err == nil {
		t.Fatal("video accepted")
	}
}

// TestMimeForPrefersTheCallerThenTheExtension keeps a file without a declared
// type from failing on a send.
func TestMimeForPrefersTheCallerThenTheExtension(t *testing.T) {
	if got := MimeFor("x.png", "image/jpeg"); got != "image/jpeg" {
		t.Fatalf("declared type ignored: %q", got)
	}
	if got := MimeFor("x.png", ""); got != "image/png" {
		t.Fatalf("extension not used: %q", got)
	}
	if got := MimeFor("x.unknownext", ""); got != "application/octet-stream" {
		t.Fatalf("fallback = %q", got)
	}
}
