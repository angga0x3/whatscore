package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	mediapkg "github.com/angga0x3/whatscore/protocol/media"
)

// mediaOrigin is the header pair whatsmeow sends on every media request
// (socket.Origin); the CDN answers without it.
const mediaOrigin = "https://web.whatsapp.com"

// mediaHTTPClient is the client media downloads share. Timeout is generous
// because the blob is the whole file.
var mediaHTTPClient = &http.Client{Timeout: 2 * time.Minute}

// mediaURLScheme pins the CDN scheme; the tests point it at a plain-HTTP
// local server.
var mediaURLScheme = "https"

// refreshMediaHosts asks the server which hosts serve media this session
// (whatsmeow queryMediaConn: iq set xmlns w:m <media_conn/>).
func refreshMediaHosts(ctx context.Context, d *dispatcher) ([]string, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	reply, err := d.request(ctx, &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to": serverJID, "type": "set", "xmlns": "w:m", "id": id,
		},
		Children: []wabinary.Node{{Tag: "media_conn"}},
	}, 20*time.Second)
	if err != nil {
		return nil, err
	}
	conn := child(reply, "media_conn")
	if conn == nil {
		return nil, fmt.Errorf("reply has no <media_conn>: %s", attrSummary(reply))
	}
	var hosts []string
	for i := range conn.Children {
		if conn.Children[i].Tag == "host" {
			if h := conn.Children[i].Attrs["hostname"]; h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("media_conn lists no hosts: %s", attrSummary(conn))
	}
	return hosts, nil
}

// mmsTypeFor maps a media kind to the mms-type query value the CDN expects
// (whatsmeow mediaTypeToMMSType); stickers download under the image type.
func mmsTypeFor(kind string) string {
	switch kind {
	case "image", "sticker":
		return "image"
	case "video":
		return "video"
	case "audio":
		return "audio"
	case "document":
		return "document"
	default:
		return ""
	}
}

// extensionFor picks the file extension from the mimetype, with a generic
// fallback so an unknown type still lands on disk.
func extensionFor(mimetype string) string {
	if base, ok := strings.CutPrefix(mimetype, "image/"); ok {
		if base == "jpeg" {
			return ".jpg"
		}
		return "." + base
	}
	if base, ok := strings.CutPrefix(mimetype, "video/"); ok {
		return "." + base
	}
	if base, ok := strings.CutPrefix(mimetype, "audio/"); ok {
		if base == "ogg; codecs=opus" {
			return ".ogg"
		}
		return "." + base
	}
	if base, ok := strings.CutPrefix(mimetype, "application/"); ok {
		if base == "pdf" {
			return ".pdf"
		}
	}
	return ".bin"
}

// DownloadMedia fetches one media attachment over the CDN, decrypts and
// verifies it, and writes it into destDir. It follows whatsmeow's
// DownloadMediaWithPath: the URL is host ‖ directPath ‖ &hash=encSHA256
// ‖ &mms-type=..., the blob is ciphertext ‖ 10-byte MAC, the media key
// expands under the attachment's HKDF info string, and the plaintext must
// hash to fileSHA256.
func DownloadMedia(ctx context.Context, d *dispatcher, info *events.MediaAttachment, destDir string) (string, error) {
	if len(info.DirectPath) == 0 || !strings.HasPrefix(info.DirectPath, "/") {
		return "", fmt.Errorf("media has no usable direct path: %q", info.DirectPath)
	}
	if len(info.MediaKey) != mediapkg.MediaKeySize {
		return "", fmt.Errorf("media key is %d bytes, want %d", len(info.MediaKey), mediapkg.MediaKeySize)
	}
	if len(info.FileEncSHA256) != sha256.Size {
		return "", fmt.Errorf("enc digest is %d bytes, want %d", len(info.FileEncSHA256), sha256.Size)
	}
	if len(info.FileSHA256) != sha256.Size {
		return "", fmt.Errorf("file digest is %d bytes, want %d", len(info.FileSHA256), sha256.Size)
	}
	var mediaKey [mediapkg.MediaKeySize]byte
	copy(mediaKey[:], info.MediaKey)
	keys, err := mediapkg.DeriveKeys(mediaKey, info.KeysType, 0)
	if err != nil {
		return "", fmt.Errorf("derive media keys: %w", err)
	}

	hosts, err := refreshMediaHosts(ctx, d)
	if err != nil {
		return "", fmt.Errorf("media hosts: %w", err)
	}
	hash := base64.URLEncoding.EncodeToString(info.FileEncSHA256)
	mmsType := mmsTypeFor(info.Kind)
	var lastErr error
	for _, host := range hosts {
		url := fmt.Sprintf("%s://%s%s&hash=%s&mms-type=%s&__wa-mms=", mediaURLScheme, host, info.DirectPath, hash, mmsType)
		blob, err := fetchMedia(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}
		plaintext, err := mediapkg.Decrypt(blob, keys)
		if err != nil {
			return "", fmt.Errorf("decrypt %d-byte blob: %w", len(blob), err)
		}
		var wantSHA [32]byte
		copy(wantSHA[:], info.FileSHA256)
		if sum := sha256.Sum256(plaintext); sum != wantSHA {
			return "", fmt.Errorf("plaintext hash does not match fileSHA256")
		}
		if err := os.MkdirAll(destDir, 0o700); err != nil {
			return "", err
		}
		// Deterministic name: the same attachment re-served by a retry lands
		// on the same path instead of accumulating copies. The direct path's
		// tail is not a safe filename (it carries a query string).
		sum := sha256.Sum256(plaintext)
		name := fmt.Sprintf("%s-%x%s", info.Kind, sum[:8], extensionFor(info.MimeType))
		path := filepath.Join(destDir, name)
		if err := os.WriteFile(path, plaintext, 0o600); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("all %d media hosts failed: %w", len(hosts), lastErr)
}

// fetchMedia issues the CDN GET with the headers whatsmeow sends.
func fetchMedia(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", mediaOrigin)
	req.Header.Set("Referer", mediaOrigin+"/")
	resp, err := mediaHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("media download: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
