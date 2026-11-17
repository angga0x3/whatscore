// Package mediaout turns a file into the message protobuf that sends it:
// encrypt with core/media, upload the ciphertext to the CDN host the server
// names, and fill the protobuf fields a recipient needs to download and
// decrypt.
//
// The transport is injected — the media connection comes from a caller
// function, because the probe and the server reach the server over different
// code — and the HTTP client is the caller's, so each side owns its timeouts.
//
// Shapes are reference study (PF-092); the request and payload halves are
// proven by tests, the CDN's acceptance by one live upload on 2026-11-17.
package mediaout

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/angga0x3/whatscore/core/media"
	"github.com/angga0x3/whatscore/internal/mediaupload"
	protocolmedia "github.com/angga0x3/whatscore/protocol/media"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"google.golang.org/protobuf/proto"
)

// Connection is where uploads go and what they must authenticate with.
type Connection struct {
	Auth string
	Host string
}

// ConnFunc fetches one media connection. It is a function, not a type, so a
// caller can hand over a closure bound to its own iq path.
type ConnFunc func(ctx context.Context) (*Connection, error)

// File is one outbound attachment.
type File struct {
	Name     string
	MimeType string
	Caption  string
	Data     []byte
}

// Result is the built message and the class it travels under.
type Result struct {
	// Message is the protobuf Message to send (and to wrap for the account's
	// own devices).
	Message *protobuf.Message
	// Payload is Message marshalled, ready for a Signal send.
	Payload []byte
	// Kind is the payload kind; the stanza class it implies is "media".
	Kind stanza.PayloadKind
	// Size is the plaintext length.
	Size int
}

// KindFor picks the message kind from the MIME type. Images and documents are
// the kinds this project sends; video, audio and stickers have protobuf
// builders but no caller yet.
func KindFor(mimeType string) (stanza.PayloadKind, string, error) {
	switch {
	case strings.HasPrefix(mimeType, "image/"):
		return stanza.PayloadImage, protocolmedia.TypeImage, nil
	case mimeType == "application/pdf",
		strings.HasPrefix(mimeType, "text/"),
		strings.HasPrefix(mimeType, "application/"),
		mimeType == "application/octet-stream":
		return stanza.PayloadDocument, protocolmedia.TypeDocument, nil
	default:
		return "", "", fmt.Errorf("mediaout: unsupported media type %q", mimeType)
	}
}

// MimeFor returns the file's MIME type, falling back to the extension and
// then to an opaque binary.
func MimeFor(name, declared string) string {
	if declared != "" {
		return declared
	}
	if byExt := mime.TypeByExtension(filepath.Ext(name)); byExt != "" {
		return byExt
	}
	return "application/octet-stream"
}

// Build encrypts, uploads and marshals one file.
func Build(ctx context.Context, client *http.Client, connect ConnFunc, file File) (*Result, error) {
	if client == nil {
		return nil, fmt.Errorf("mediaout: nil http client")
	}
	if connect == nil {
		return nil, fmt.Errorf("mediaout: nil media connection source")
	}
	if len(file.Data) == 0 {
		return nil, fmt.Errorf("mediaout: empty file")
	}
	mimeType := MimeFor(file.Name, file.MimeType)
	kind, mediaType, err := KindFor(mimeType)
	if err != nil {
		return nil, err
	}
	descriptor, ciphertext, err := media.Encrypt(file.Data, mediaType, file.Name)
	if err != nil {
		return nil, fmt.Errorf("mediaout: encrypt: %w", err)
	}
	conn, err := connect(ctx)
	if err != nil {
		return nil, err
	}
	if conn == nil || conn.Host == "" || conn.Auth == "" {
		return nil, fmt.Errorf("mediaout: no usable media connection")
	}
	mmsType, err := mediaupload.MMSType(string(kind))
	if err != nil {
		return nil, err
	}
	upload, err := mediaupload.Upload(ctx, client, conn.Host, conn.Auth, mmsType, ciphertext, descriptor.EncSHA256)
	if err != nil {
		return nil, fmt.Errorf("mediaout: upload: %w", err)
	}
	payload, err := stanza.EncodeMediaMessage(stanza.MediaMessage{
		Kind:          kind,
		URL:           upload.URL,
		DirectPath:    upload.DirectPath,
		MimeType:      mimeType,
		Caption:       file.Caption,
		FileName:      file.Name,
		Title:         strings.TrimSuffix(file.Name, filepath.Ext(file.Name)),
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
		return nil, fmt.Errorf("mediaout: re-read payload: %w", err)
	}
	return &Result{
		Message: &message,
		Payload: payload,
		Kind:    kind,
		Size:    descriptor.Size,
	}, nil
}
