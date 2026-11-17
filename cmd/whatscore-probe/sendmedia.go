package main

// Outbound media for the probe: the shared pipeline lives in core/mediaout;
// this file supplies the one thing that differs per caller — how the media
// connection is fetched over this client's own iq path.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/angga0x3/whatscore/core/mediaout"
	"github.com/angga0x3/whatscore/internal/mediaupload"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// mediaHTTP is the client used for uploads. The CDN is a different service
// from the websocket, so it gets its own timeout rather than the probe's
// socket deadline.
var mediaHTTP = &http.Client{Timeout: 90 * time.Second}

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

// buildMediaPayload encrypts, uploads and marshals one file. The dispatcher
// supplies the media connection; everything else is core/mediaout's.
func buildMediaPayload(ctx context.Context, d *dispatcher, cfg sendConfig) (*protobuf.Message, error) {
	if cfg.FilePath == "" {
		return nil, fmt.Errorf("media send needs a file")
	}
	data, err := os.ReadFile(cfg.FilePath)
	if err != nil {
		return nil, err
	}
	result, err := mediaout.Build(ctx, mediaHTTP, func(ctx context.Context) (*mediaout.Connection, error) {
		conn, err := queryMediaConn(ctx, d)
		if err != nil {
			return nil, err
		}
		host, err := conn.Host()
		if err != nil {
			return nil, err
		}
		return &mediaout.Connection{Auth: conn.Auth, Host: host}, nil
	}, mediaout.File{
		Name:     filepath.Base(cfg.FilePath),
		MimeType: cfg.MimeType,
		Caption:  cfg.Caption,
		Data:     data,
	})
	if err != nil {
		return nil, err
	}
	fmt.Printf("media: %s (%s, %d bytes) uploaded\n", cfg.FilePath, result.Kind, result.Size)
	return result.Message, nil
}
