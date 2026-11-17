// Package messaging orchestrates text stanzas over a frame connection: it
// builds a protocol/messaging node, encodes it with protocol/binary, and
// writes one frame. Encryption and Signal are not part of this layer yet.
package messaging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// ErrInvalidMessage is returned for unusable send requests.
var ErrInvalidMessage = errors.New("core/messaging: invalid message")

// FrameWriter writes one encoded frame.
type FrameWriter interface {
	WriteFrame(ctx context.Context, frame []byte) error
}

// Sender builds and writes text stanzas.
type Sender struct {
	write    FrameWriter
	codec    binary.Codec
	newID    func() (string, error)
	identity [32]byte
	idPair   signal.KeyPair
	peers    map[string]*PeerSession
	bundles  PreKeyBundleSource
}

// Option configures a Sender.
type Option func(*Sender) error

// WithCodec overrides the binary codec (default: an empty-dictionary codec).
func WithCodec(codec binary.Codec) Option {
	return func(s *Sender) error {
		if codec == nil {
			return fmt.Errorf("core/messaging: nil codec")
		}
		s.codec = codec
		return nil
	}
}

// WithIDGenerator overrides message-id generation.
func WithIDGenerator(generate func() (string, error)) Option {
	return func(s *Sender) error {
		if generate == nil {
			return fmt.Errorf("core/messaging: nil id generator")
		}
		s.newID = generate
		return nil
	}
}

// NewSender wires a writer and defaults.
func NewSender(write FrameWriter, opts ...Option) (*Sender, error) {
	if write == nil {
		return nil, fmt.Errorf("core/messaging: nil writer")
	}
	s := &Sender{
		write: write,
		codec: binary.NewCodec(nil),
		newID: randomID,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// SendText builds and writes one text message, returning its id.
func (s *Sender) SendText(ctx context.Context, to, text string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	jid, err := stanza.ParseJID(strings.TrimSpace(to))
	if err != nil {
		return "", fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if jid.User == "" {
		return "", fmt.Errorf("%w: to %q has no user", ErrInvalidMessage, to)
	}
	id, err := s.newID()
	if err != nil {
		return "", fmt.Errorf("%w: generate id: %w", ErrInvalidMessage, err)
	}
	if id == "" {
		return "", fmt.Errorf("%w: empty id", ErrInvalidMessage)
	}

	node, err := stanza.BuildTextMessage(stanza.TextMessage{ID: id, To: jid, Text: text})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	frame, err := s.codec.Encode(node)
	if err != nil {
		return "", fmt.Errorf("core/messaging: encode: %w", err)
	}
	if err := s.write.WriteFrame(ctx, frame); err != nil {
		return "", fmt.Errorf("core/messaging: write: %w", err)
	}
	return id, nil
}

// SendReceipt writes one receipt for a message id. The receipt type is the
// protocol value (empty for delivery, "read", "played", ...).
func (s *Sender) SendReceipt(ctx context.Context, to, id, receiptType string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	jid, err := stanza.ParseJID(strings.TrimSpace(to))
	if err != nil {
		return fmt.Errorf("%w: to: %w", ErrInvalidMessage, err)
	}
	if jid.User == "" {
		return fmt.Errorf("%w: to %q has no user", ErrInvalidMessage, to)
	}
	node, err := stanza.BuildReceipt(stanza.Receipt{ID: id, To: jid, Type: receiptType})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	frame, err := s.codec.Encode(node)
	if err != nil {
		return fmt.Errorf("core/messaging: encode receipt: %w", err)
	}
	if err := s.write.WriteFrame(ctx, frame); err != nil {
		return fmt.Errorf("core/messaging: write receipt: %w", err)
	}
	return nil
}

func randomID() (string, error) {
	var raw [10]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(raw[:])), nil
}

// SendReadReceipt tells a chat that the given messages were read: the first
// id rides the receipt attrs, the rest under a <list> (whatsmeow MarkRead).
// The blue ticks.
func (s *Sender) SendReadReceipt(ctx context.Context, chat string, ids []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return fmt.Errorf("%w: read receipt without ids", stanza.ErrInvalidReceipt)
	}
	jid, err := stanza.ParseJID(strings.TrimSpace(chat))
	if err != nil {
		return fmt.Errorf("%w: to: %w", stanza.ErrInvalidReceipt, err)
	}
	node, err := stanza.BuildReceipt(stanza.Receipt{
		ID: ids[0], To: jid, Type: "read", ExtraIDs: ids[1:],
		Timestamp: time.Now(),
	})
	if err != nil {
		return fmt.Errorf("%w: %w", stanza.ErrInvalidReceipt, err)
	}
	frame, err := s.codec.Encode(node)
	if err != nil {
		return fmt.Errorf("core/messaging: encode: %w", err)
	}
	if err := s.write.WriteFrame(ctx, frame); err != nil {
		return fmt.Errorf("core/messaging: write: %w", err)
	}
	return nil
}

// SendTyping sends the typing indicator for a chat: composing while the user
// types, paused when they stop. Clients send composing periodically while the
// indicator should stay up; a single paused clears it.
func (s *Sender) SendTyping(ctx context.Context, chat string, composing bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	jid, err := stanza.ParseJID(strings.TrimSpace(chat))
	if err != nil {
		return fmt.Errorf("%w: to: %w", stanza.ErrInvalidChatState, err)
	}
	node, err := stanza.BuildChatState(jid, composing)
	if err != nil {
		return fmt.Errorf("%w: %w", stanza.ErrInvalidChatState, err)
	}
	frame, err := s.codec.Encode(node)
	if err != nil {
		return fmt.Errorf("core/messaging: encode: %w", err)
	}
	if err := s.write.WriteFrame(ctx, frame); err != nil {
		return fmt.Errorf("core/messaging: write: %w", err)
	}
	return nil
}
