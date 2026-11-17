package main

// Outbound media: one file encrypted with core/media, uploaded to the CDN host
// the server names, and turned into the message protobuf a client renders.
//
// The shapes come from reference study of whatsmeow `upload.go`/`mediaconn.go`
// (PF-092) and are not yet proven against the live service. What can be proven
// offline is proven: the upload request shape, the media connection parse, and
// the protobuf fields are pinned by tests; the CDN's acceptance is not.

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/angga0x3/whatscore/core/media"
	"github.com/angga0x3/whatscore/internal/mediaupload"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	protocolmedia "github.com/angga0x3/whatscore/protocol/media"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"google.golang.org/protobuf/proto"
)

// mediaHTTP is the client used for uploads. The CDN is a different service
// from the websocket, so it gets its own timeout rather than the probe's
// socket deadline.
var mediaHTTP = &http.Client{Timeout: 90 * time.Second}

// mediaConnTTL bounds how long one media connection answer is reused. The
// server reports its own ttl; this is only the fallback.
const mediaConnTTL = 5 * time.Minute

// mediaConnection is the parsed <media_conn> answer, cached for one run.
type mediaConnection struct {
	conn      *mediaupload.Conn
	fetchedAt time.Time
}

// queryMediaConn asks the server where uploads should go. It rides the same
// dispatcher as every other iq, so an inbound message arriving mid-query is
// not discarded.
func queryMediaConn(ctx context.Context, d *dispatcher) (*mediaupload.Conn, error) {
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
		return nil, fmt.Errorf("media connection query: %w", err)
	}
	for i := range reply.Children {
		if reply.Children[i].Tag == "media_conn" {
			return mediaupload.ParseConn(&reply.Children[i])
		}
	}
	return nil, fmt.Errorf("media connection query: reply has no media_conn (%d children)", len(reply.Children))
}

// mediaKindFor picks the message kind from the MIME type. The probe sends the
// two kinds the REST surface already carries: images and documents. Video,
// audio and stickers have protobuf builders but no probe flag yet.
func mediaKindFor(mimeType string) (stanza.PayloadKind, string, error) {
	switch {
	case strings.HasPrefix(mimeType, "image/"):
		return stanza.PayloadImage, protocolmedia.TypeImage, nil
	case mimeType == "application/pdf",
		strings.HasPrefix(mimeType, "text/"),
		strings.HasPrefix(mimeType, "application/"),
		mimeType == "application/octet-stream":
		return stanza.PayloadDocument, protocolmedia.TypeDocument, nil
	default:
		return "", "", fmt.Errorf("unsupported media type %q", mimeType)
	}
}

// buildMediaPayload reads one file, encrypts it, uploads the ciphertext, and
// returns the protobuf Message the recipient receives. The same message is
// what the own-device copy wraps.
func buildMediaPayload(ctx context.Context, d *dispatcher, cfg sendConfig) (*protobuf.Message, error) {
	if cfg.FilePath == "" {
		return nil, fmt.Errorf("media send needs a file")
	}
	plaintext, err := os.ReadFile(cfg.FilePath)
	if err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%s is empty", cfg.FilePath)
	}
	mimeType := cfg.MimeType
	if mimeType == "" {
		mimeType = mime.TypeByExtension(filepath.Ext(cfg.FilePath))
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	kind, mediaType, err := mediaKindFor(mimeType)
	if err != nil {
		return nil, err
	}

	descriptor, ciphertext, err := media.Encrypt(plaintext, mediaType, filepath.Base(cfg.FilePath))
	if err != nil {
		return nil, fmt.Errorf("encrypt %s: %w", cfg.FilePath, err)
	}
	conn, err := queryMediaConn(ctx, d)
	if err != nil {
		return nil, err
	}
	host, err := conn.Host()
	if err != nil {
		return nil, err
	}
	mmsType, err := mediaupload.MMSType(string(kind))
	if err != nil {
		return nil, err
	}
	upload, err := mediaupload.Upload(ctx, mediaHTTP, host, conn.Auth, mmsType, ciphertext, descriptor.EncSHA256)
	if err != nil {
		return nil, fmt.Errorf("upload %s: %w", cfg.FilePath, err)
	}
	payload, err := stanza.EncodeMediaMessage(stanza.MediaMessage{
		Kind:          kind,
		URL:           upload.URL,
		DirectPath:    upload.DirectPath,
		MimeType:      mimeType,
		Caption:       cfg.Caption,
		FileName:      filepath.Base(cfg.FilePath),
		Title:         strings.TrimSuffix(filepath.Base(cfg.FilePath), filepath.Ext(cfg.FilePath)),
		FileSHA256:    descriptor.SHA256[:],
		FileEncSHA256: descriptor.EncSHA256[:],
		MediaKey:      descriptor.MediaKey[:],
		FileLength:    uint64(descriptor.Size),
	})
	if err != nil {
		return nil, err
	}
	var message protobuf.Message
	if err := proto.Unmarshal(payload, &message); err != nil {
		return nil, fmt.Errorf("re-read media payload: %w", err)
	}
	fmt.Printf("media: %s (%s, %d bytes) uploaded to %s\n", cfg.FilePath, mimeType, descriptor.Size, upload.DirectPath)
	return &message, nil
}
