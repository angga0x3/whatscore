package messaging

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
)

// Receiver turns inbound frames into normalized message events. Malformed
// frames are logged and dropped; they do not tear the connection down.
type Receiver struct {
	bus       *events.Bus
	sessionID string
	codec     binary.Codec
	logger    *slog.Logger
}

// ReceiverOption configures a Receiver.
type ReceiverOption func(*Receiver) error

// WithReceiverCodec overrides the binary codec.
func WithReceiverCodec(codec binary.Codec) ReceiverOption {
	return func(r *Receiver) error {
		if codec == nil {
			return fmt.Errorf("core/messaging: nil receiver codec")
		}
		r.codec = codec
		return nil
	}
}

// WithReceiverLogger sets the logger used for dropped frames.
func WithReceiverLogger(logger *slog.Logger) ReceiverOption {
	return func(r *Receiver) error {
		if logger == nil {
			return fmt.Errorf("core/messaging: nil receiver logger")
		}
		r.logger = logger
		return nil
	}
}

// NewReceiver wires a bus and session id.
func NewReceiver(bus *events.Bus, sessionID string, opts ...ReceiverOption) (*Receiver, error) {
	if bus == nil {
		return nil, fmt.Errorf("core/messaging: nil bus")
	}
	if sessionID == "" {
		return nil, fmt.Errorf("core/messaging: empty session id")
	}
	r := &Receiver{
		bus:       bus,
		sessionID: sessionID,
		codec:     binary.NewCodec(nil),
		logger:    slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// HandleFrame decodes one frame and publishes a message event when it is a
// text message. Non-message frames and malformed payloads are ignored.
func (r *Receiver) HandleFrame(ctx context.Context, frame []byte) error {
	node, err := r.codec.Decode(bytes.NewReader(frame))
	if err != nil {
		r.logger.WarnContext(ctx, "dropping undecodable frame", "error", err)
		return nil
	}
	if node.Tag != "message" {
		return nil
	}
	incoming, err := stanza.ParseIncomingText(node)
	if err != nil {
		r.logger.WarnContext(ctx, "dropping malformed message", "error", err)
		return nil
	}

	chat := incoming.From
	sender := incoming.From
	if !incoming.Participant.IsEmpty() {
		sender = incoming.Participant
	}
	timestamp := incoming.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	r.bus.Publish(events.Event{
		Type:      events.TypeMessage,
		SessionID: r.sessionID,
		Timestamp: timestamp,
		Message: &events.Message{
			ID:        incoming.ID,
			Chat:      chat.String(),
			Sender:    sender.String(),
			Timestamp: timestamp,
			Direction: events.DirectionIncoming,
			Text:      incoming.Text,
			IsGroup:   chat.Server == stanza.GroupServer,
		},
	})
	return nil
}
