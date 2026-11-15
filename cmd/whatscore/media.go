package main

// Inbound media pipeline: a decrypted media attachment is fetched from the
// WhatsApp CDN (whatsmeow's DownloadMediaWithPath shape — mediaConn hosts,
// host ‖ directPath ‖ hash=encSHA256 ‖ mms-type, Origin header), decrypted
// under the message's media key, verified against fileSHA256, and stored
// re-encrypted at rest the way the upload routes store theirs (core/media
// Encrypt with a fresh media key), so GET /media/{id} metadata and any future
// blob read see the same shape whichever direction the bytes came from.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/binary"
	protocolmedia "github.com/angga0x3/whatscore/protocol/media"
)

// mediaOrigin is the header pair whatsmeow sends on every media request
// (socket.Origin); the CDN answers without it.
const mediaOrigin = "https://web.whatsapp.com"

// mediaHTTPClient is the client media downloads share. The timeout is
// generous because the blob is the whole file.
var mediaHTTPClient = &http.Client{Timeout: 2 * time.Minute}

// mediaSaver stores one decrypted inbound attachment.
type mediaSaver interface {
	SaveInboundMedia(ctx context.Context, sessionID, kind, fileName, mimetype string, plaintext []byte) (string, error)
}

// refreshMediaHosts asks the server which hosts serve media for this session
// (whatsmeow queryMediaConn: iq set xmlns w:m <media_conn/>).
func (r *sessionRuntime) refreshMediaHosts(ctx context.Context) ([]string, error) {
	reply, err := r.request(ctx, &binary.Node{
		Tag: "iq",
		Attrs: binary.Attrs{
			"to": serverJID, "type": "set", "xmlns": "w:m", "id": r.newRequestID(),
		},
		Children: []binary.Node{{Tag: "media_conn"}},
	}, 20*time.Second)
	if err != nil {
		return nil, err
	}
	conn := child(reply, "media_conn")
	if conn == nil {
		return nil, fmt.Errorf("reply has no <media_conn>")
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
		return nil, fmt.Errorf("media_conn lists no hosts")
	}
	return hosts, nil
}

// mmsTypeFor maps a media kind to the mms-type query value the CDN expects;
// stickers download under the image type (whatsmeow mediaTypeToMMSType).
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

// keysTypeFor maps a media kind to the HKDF info string its CDN blob expands
// under (whatsmeow classToMediaType): stickers ride the image keys.
func keysTypeFor(kind string) string {
	switch kind {
	case "video":
		return protocolmedia.TypeVideo
	case "audio":
		return protocolmedia.TypeAudio
	case "document":
		return protocolmedia.TypeDocument
	default:
		return protocolmedia.TypeImage
	}
}

// downloadMedia fetches, decrypts and verifies one CDN blob. Every failure is
// a hard error: a blob that does not hash to fileSHA256 must not be stored.
func (r *sessionRuntime) downloadMedia(ctx context.Context, m *events.MediaAttachment) ([]byte, error) {
	if !strings.HasPrefix(m.DirectPath, "/") {
		return nil, fmt.Errorf("media has no usable direct path: %q", m.DirectPath)
	}
	if len(m.MediaKey) != protocolmedia.MediaKeySize {
		return nil, fmt.Errorf("media key is %d bytes, want %d", len(m.MediaKey), protocolmedia.MediaKeySize)
	}
	if len(m.FileEncSHA256) != sha256.Size {
		return nil, fmt.Errorf("enc digest is %d bytes, want %d", len(m.FileEncSHA256), sha256.Size)
	}
	if len(m.FileSHA256) != sha256.Size {
		return nil, fmt.Errorf("file digest is %d bytes, want %d", len(m.FileSHA256), sha256.Size)
	}
	var mediaKey [protocolmedia.MediaKeySize]byte
	copy(mediaKey[:], m.MediaKey)
	keys, err := protocolmedia.DeriveKeys(mediaKey, m.KeysType, 0)
	if err != nil {
		return nil, fmt.Errorf("derive media keys: %w", err)
	}

	hosts, err := r.refreshMediaHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("media hosts: %w", err)
	}
	hash := base64.URLEncoding.EncodeToString(m.FileEncSHA256)
	mmsType := mmsTypeFor(m.Kind)
	var lastErr error
	for _, host := range hosts {
		url := fmt.Sprintf("https://%s%s&hash=%s&mms-type=%s&__wa-mms=", host, m.DirectPath, hash, mmsType)
		blob, err := fetchCDN(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}
		plaintext, err := protocolmedia.Decrypt(blob, keys)
		if err != nil {
			return nil, fmt.Errorf("decrypt %d-byte blob: %w", len(blob), err)
		}
		var want [32]byte
		copy(want[:], m.FileSHA256)
		if sum := sha256.Sum256(plaintext); sum != want {
			return nil, errors.New("plaintext hash does not match fileSHA256")
		}
		return plaintext, nil
	}
	return nil, fmt.Errorf("all %d media hosts failed: %w", len(hosts), lastErr)
}

// fetchCDN issues the CDN GET with the headers whatsmeow sends.
func fetchCDN(ctx context.Context, url string) ([]byte, error) {
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

// handleMediaEvent downloads and stores one inbound attachment. It runs in
// its own goroutine per event: the download must never block the read loop,
// and a failure is logged, not fatal — the message itself still happened.
func (r *sessionRuntime) handleMediaEvent(messageID string, m *events.MediaAttachment) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	plaintext, err := r.downloadMedia(ctx, m)
	if err != nil {
		r.logger.Warn("inbound media download failed", "session", r.id, "message", messageID, "kind", m.Kind, "error", err)
		return
	}
	fileName := m.FileName
	if fileName == "" {
		fileName = "inbound-" + m.Kind
	}
	if r.mediaSaver == nil {
		r.logger.Info("inbound media downloaded but no store is configured", "session", r.id, "message", messageID, "bytes", len(plaintext))
		return
	}
	mediaID, err := r.mediaSaver.SaveInboundMedia(ctx, r.id, m.Kind, fileName, m.MimeType, plaintext)
	if err != nil {
		r.logger.Warn("inbound media store failed", "session", r.id, "message", messageID, "error", err)
		return
	}
	r.logger.Info("inbound media stored", "session", r.id, "message", messageID, "media", mediaID, "kind", m.Kind, "bytes", len(plaintext))
}
