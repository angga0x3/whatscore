// Package mediaupload posts one encrypted media blob to the CDN host the
// WhatsApp server names, and parses the reply that goes into the message
// protobuf.
//
// The upload is one HTTP POST: the body is the encrypted blob (ciphertext ‖
// MAC, exactly what core/media produced), the path names the object type and
// a token derived from the blob's SHA-256, and the query carries the short
// lived auth value from the media connection. The reply names where the blob
// landed — the URL and direct path the recipient downloads from.
//
// Shapes are taken from reference study of whatsmeow `upload.go` and
// `mediaconn.go` (PF-092). They are not yet proven against the live service.
package mediaupload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// Origin is the web client origin the CDN expects on uploads. The reference
// sends it on every upload request; a request without it is refused.
const Origin = "https://web.whatsapp.com"

// Conn is one answer to the media connection query: the hosts that accept
// uploads and the auth value they require.
type Conn struct {
	Auth  string
	TTL   int
	Hosts []string
}

// Host returns the first host, or an error when the server named none.
func (c *Conn) Host() (string, error) {
	if c == nil || len(c.Hosts) == 0 {
		return "", fmt.Errorf("mediaupload: no upload host")
	}
	return c.Hosts[0], nil
}

// ParseConn reads the <media_conn> child of the query reply.
func ParseConn(node *binary.Node) (*Conn, error) {
	if node == nil || node.Tag != "media_conn" {
		return nil, fmt.Errorf("mediaupload: expected media_conn, got %v", tagOf(node))
	}
	conn := &Conn{
		Auth: node.Attrs["auth"],
	}
	if conn.Auth == "" {
		return nil, fmt.Errorf("mediaupload: media_conn has no auth")
	}
	if ttl := node.Attrs["ttl"]; ttl != "" {
		if _, err := fmt.Sscanf(ttl, "%d", &conn.TTL); err != nil {
			return nil, fmt.Errorf("mediaupload: media_conn ttl %q: %w", ttl, err)
		}
	}
	for _, child := range node.Children {
		if child.Tag != "host" {
			continue
		}
		if host := child.Attrs["hostname"]; host != "" {
			conn.Hosts = append(conn.Hosts, host)
		}
	}
	if len(conn.Hosts) == 0 {
		return nil, fmt.Errorf("mediaupload: media_conn names no host")
	}
	return conn, nil
}

// Response is the CDN's answer to one upload.
type Response struct {
	URL        string `json:"url"`
	DirectPath string `json:"direct_path"`
	Handle     string `json:"handle"`
	ObjectID   string `json:"object_id"`
}

// Upload posts ciphertext to host and returns where it landed. mmsType is the
// object class in the path ("image", "document", …); token is derived from
// the encrypted blob's SHA-256, the same value the message carries as
// fileEncSHA256.
func Upload(ctx context.Context, client *http.Client, host, auth, mmsType string, ciphertext []byte, encSHA256 [32]byte) (*Response, error) {
	if client == nil {
		return nil, fmt.Errorf("mediaupload: nil http client")
	}
	if host == "" || auth == "" {
		return nil, fmt.Errorf("mediaupload: empty host or auth")
	}
	if mmsType == "" {
		return nil, fmt.Errorf("mediaupload: empty media type")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("mediaupload: empty ciphertext")
	}

	token := base64.URLEncoding.EncodeToString(encSHA256[:])
	query := url.Values{"auth": {auth}, "token": {token}}
	endpoint := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     fmt.Sprintf("/mms/%s/%s", mmsType, token),
		RawQuery: query.Encode(),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("mediaupload: request: %w", err)
	}
	req.ContentLength = int64(len(ciphertext))
	req.Header.Set("Origin", Origin)
	req.Header.Set("Referer", Origin+"/")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mediaupload: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("mediaupload: status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	var out Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("mediaupload: decode reply: %w", err)
	}
	if out.URL == "" || out.DirectPath == "" {
		return nil, fmt.Errorf("mediaupload: reply names no url or direct path")
	}
	return &out, nil
}

// MMSType maps a payload kind to the object class in the upload path. The
// reference table is mediaTypeToMMSType (whatsmeow download.go); only the
// classes this project sends are declared.
func MMSType(kind string) (string, error) {
	switch kind {
	case "image":
		return "image", nil
	case "video":
		return "video", nil
	case "audio":
		return "audio", nil
	case "document":
		return "document", nil
	default:
		return "", fmt.Errorf("mediaupload: no mms type for %q", kind)
	}
}

func tagOf(node *binary.Node) string {
	if node == nil {
		return "nil"
	}
	return node.Tag
}
