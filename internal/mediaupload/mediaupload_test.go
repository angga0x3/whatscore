package mediaupload

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// TestUploadPostsTheReferenceShape pins path, query, headers and body against
// a real HTTP server: the CDN route is /mms/{type}/{token}, the token is the
// URL-safe base64 of the encrypted blob's SHA-256, and auth travels in the
// query.
func TestUploadPostsTheReferenceShape(t *testing.T) {
	blob := []byte("ciphertext-and-mac")
	sum := sha256.Sum256(blob)
	wantToken := base64.URLEncoding.EncodeToString(sum[:])

	var gotPath, gotAuth, gotToken, gotOrigin, gotReferer, gotBody string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.URL.Query().Get("auth")
		gotToken = r.URL.Query().Get("token")
		gotOrigin = r.Header.Get("Origin")
		gotReferer = r.Header.Get("Referer")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		_, _ = w.Write([]byte(`{"url":"https://mmg.whatsapp.net/x","direct_path":"/v/t62/x","handle":"h","object_id":"o"}`))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	resp, err := Upload(context.Background(), server.Client(), host, "AUTH123", "image", blob, sum)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if want := "/mms/image/" + wantToken; gotPath != want {
		t.Fatalf("path = %q, want %q", gotPath, want)
	}
	if gotAuth != "AUTH123" || gotToken != wantToken {
		t.Fatalf("query auth=%q token=%q", gotAuth, gotToken)
	}
	if gotOrigin != Origin || gotReferer != Origin+"/" {
		t.Fatalf("origin=%q referer=%q", gotOrigin, gotReferer)
	}
	if gotBody != string(blob) {
		t.Fatalf("body = %q", gotBody)
	}
	if resp.URL != "https://mmg.whatsapp.net/x" || resp.DirectPath != "/v/t62/x" {
		t.Fatalf("response = %#v", resp)
	}
}

// TestUploadReportsHTTPFailures keeps a rejected upload loud: a 4xx/5xx is
// not an upload.
func TestUploadReportsHTTPFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	if _, err := Upload(context.Background(), server.Client(), host, "a", "image", []byte{1}, sha256.Sum256([]byte{1})); err == nil {
		t.Fatal("403 accepted as success")
	}
}

// TestUploadRejectsEmptyReply keeps a reply without a destination loud.
func TestUploadRejectsEmptyReply(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"url":""}`))
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	if _, err := Upload(context.Background(), server.Client(), host, "a", "image", []byte{1}, sha256.Sum256([]byte{1})); err == nil {
		t.Fatal("empty reply accepted")
	}
}

// TestParseConnReadsTheMediaConnChild pins the query answer: auth, ttl, and
// the host list.
func TestParseConnReadsTheMediaConnChild(t *testing.T) {
	node := &binary.Node{
		Tag:   "media_conn",
		Attrs: binary.Attrs{"auth": "AUTH", "ttl": "3600"},
		Children: []binary.Node{
			{Tag: "host", Attrs: binary.Attrs{"hostname": "mmg.whatsapp.net"}},
			{Tag: "host", Attrs: binary.Attrs{"hostname": "media.fbsbx.com"}},
		},
	}
	conn, err := ParseConn(node)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if conn.Auth != "AUTH" || conn.TTL != 3600 {
		t.Fatalf("conn = %#v", conn)
	}
	host, err := conn.Host()
	if err != nil || host != "mmg.whatsapp.net" {
		t.Fatalf("host = %q, %v", host, err)
	}
}

// TestParseConnRejectsIncompleteAnswers fails closed on an answer a client
// cannot upload with.
func TestParseConnRejectsIncompleteAnswers(t *testing.T) {
	cases := map[string]*binary.Node{
		"nil":       nil,
		"wrong tag": {Tag: "iq"},
		"no auth":   {Tag: "media_conn", Children: []binary.Node{{Tag: "host", Attrs: binary.Attrs{"hostname": "x"}}}},
		"no host":   {Tag: "media_conn", Attrs: binary.Attrs{"auth": "a"}},
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConn(node); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestMMSTypeTable keeps the path class honest for the kinds this project
// sends.
func TestMMSTypeTable(t *testing.T) {
	for kind, want := range map[string]string{
		"image": "image", "video": "video", "audio": "audio", "document": "document",
	} {
		got, err := MMSType(kind)
		if err != nil || got != want {
			t.Fatalf("MMSType(%q) = %q, %v", kind, got, err)
		}
	}
	if _, err := MMSType("sticker"); err == nil {
		t.Fatal("sticker accepted")
	}
}
