// Package client is the public SDK facade over a single session. It composes
// the session actor, the event bus, and the credential manager behind a small
// API; protocol types never leak through it.
//
// Sending currently writes a plaintext text stanza (no Signal encryption).
// Isolated tests and fake-server runs can use it; production use waits for
// protocol/signal.
package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/angga0x3/whatscore/core/contacts"
	corecredentials "github.com/angga0x3/whatscore/core/credentials"
	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/core/groups"
	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/core/session"
	"github.com/angga0x3/whatscore/protocol/signal"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// ErrInvalidConfig is returned by New when the configuration is unusable.
var ErrInvalidConfig = errors.New("client: invalid config")

// Message is a text message to send.
type Message struct {
	To   string
	Text string
}

// Client is one WhatsApp session plus its SDK surface. It is safe for
// concurrent use.
type Client struct {
	id             string
	session        *session.Session
	sender         *coremessaging.Sender
	receiver       *coremessaging.Receiver
	bus            *events.Bus
	ownBus         bool
	creds          *corecredentials.Manager
	sessions       SessionStore
	registrationID uint32
	directoryOnce  sync.Once
	directory      directoryCaches
}

// directoryCaches holds the lazily created contact and group caches.
type directoryCaches struct {
	contacts *contacts.Cache
	groups   *groups.Cache
}

type options struct {
	dialer         transport.Dialer
	endpoint       transport.Endpoint
	reconnect      transport.ReconnectPolicy
	connector      session.Connector
	handler        session.FrameHandler
	bus            *events.Bus
	logger         *slog.Logger
	creds          *corecredentials.Manager
	sessions       SessionStore
	registrationID uint32
}

// Option configures New.
type Option func(*options) error

// WithDialer overrides the default WebSocket dialer.
func WithDialer(d transport.Dialer) Option {
	return func(o *options) error {
		if d == nil {
			return fmt.Errorf("%w: nil dialer", ErrInvalidConfig)
		}
		o.dialer = d
		return nil
	}
}

// WithEndpoint overrides the default WhatsApp Web endpoint.
func WithEndpoint(endpoint transport.Endpoint) Option {
	return func(o *options) error {
		if endpoint.URL == "" {
			return fmt.Errorf("%w: empty endpoint URL", ErrInvalidConfig)
		}
		o.endpoint = endpoint
		return nil
	}
}

// WithReconnectPolicy enables reconnection with the given policy.
func WithReconnectPolicy(policy transport.ReconnectPolicy) Option {
	return func(o *options) error {
		if policy == nil {
			return fmt.Errorf("%w: nil reconnect policy", ErrInvalidConfig)
		}
		o.reconnect = policy
		return nil
	}
}

// WithConnector wraps each dialed connection, for example with Noise.
func WithConnector(connector session.Connector) Option {
	return func(o *options) error {
		if connector == nil {
			return fmt.Errorf("%w: nil connector", ErrInvalidConfig)
		}
		o.connector = connector
		return nil
	}
}

// WithFrameHandler receives inbound frames after the connector.
func WithFrameHandler(handler session.FrameHandler) Option {
	return func(o *options) error {
		if handler == nil {
			return fmt.Errorf("%w: nil frame handler", ErrInvalidConfig)
		}
		o.handler = handler
		return nil
	}
}

// WithBus shares an existing event bus. The client will not close it.
func WithBus(bus *events.Bus) Option {
	return func(o *options) error {
		if bus == nil {
			return fmt.Errorf("%w: nil bus", ErrInvalidConfig)
		}
		o.bus = bus
		return nil
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) error {
		if logger == nil {
			return fmt.Errorf("%w: nil logger", ErrInvalidConfig)
		}
		o.logger = logger
		return nil
	}
}

// WithCredentials attaches the encrypted credential manager.
func WithCredentials(manager *corecredentials.Manager) Option {
	return func(o *options) error {
		if manager == nil {
			return fmt.Errorf("%w: nil credential manager", ErrInvalidConfig)
		}
		o.creds = manager
		return nil
	}
}

// New builds a client for one session id. Without options it uses the
// WhatsApp Web endpoint and the WebSocket dialer; the client owns its event
// bus unless WithBus supplies one.
func New(id string, opts ...Option) (*Client, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: empty session id", ErrInvalidConfig)
	}
	cfg := options{
		dialer:   &transport.WebSocketDialer{},
		endpoint: transport.DefaultEndpoint(),
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	ownBus := false
	if cfg.bus == nil {
		cfg.bus = events.NewBus()
		ownBus = true
	}

	receiverOpts := []coremessaging.ReceiverOption{}
	if cfg.logger != nil {
		receiverOpts = append(receiverOpts, coremessaging.WithReceiverLogger(cfg.logger))
	}
	receiver, err := coremessaging.NewReceiver(cfg.bus, id, receiverOpts...)
	if err != nil {
		if ownBus {
			cfg.bus.Close()
		}
		return nil, err
	}
	handler := session.FrameHandler(receiver)
	if cfg.handler != nil {
		handler = frameHandlers{receiver, cfg.handler}
	}

	sess, err := session.New(session.Config{
		ID:           id,
		Endpoint:     cfg.endpoint,
		Dialer:       cfg.dialer,
		Reconnect:    cfg.reconnect,
		Connector:    cfg.connector,
		FrameHandler: handler,
		Bus:          cfg.bus,
		Logger:       cfg.logger,
	})
	if err != nil {
		if ownBus {
			cfg.bus.Close()
		}
		return nil, err
	}
	sender, err := coremessaging.NewSender(sess)
	if err != nil {
		_ = sess.Stop(context.Background())
		if ownBus {
			cfg.bus.Close()
		}
		return nil, err
	}
	return &Client{
		id:             id,
		session:        sess,
		sender:         sender,
		receiver:       receiver,
		bus:            cfg.bus,
		ownBus:         ownBus,
		creds:          cfg.creds,
		sessions:       cfg.sessions,
		registrationID: cfg.registrationID,
	}, nil
}

// frameHandlers runs each handler in order until one fails.
type frameHandlers []session.FrameHandler

func (h frameHandlers) HandleFrame(ctx context.Context, frame []byte) error {
	for _, handler := range h {
		if err := handler.HandleFrame(ctx, frame); err != nil {
			return err
		}
	}
	return nil
}

// ID returns the session id.
func (c *Client) ID() string { return c.id }

// Connect establishes the session connection.
func (c *Client) Connect(ctx context.Context) error {
	return c.session.Connect(ctx)
}

// Disconnect closes the current connection without stopping the session.
func (c *Client) Disconnect(ctx context.Context) error {
	return c.session.Disconnect(ctx)
}

// State returns the current session state.
func (c *Client) State(ctx context.Context) (session.State, error) {
	return c.session.State(ctx)
}

// Subscribe returns an event subscription. The caller must Close it.
func (c *Client) Subscribe() *events.Subscription {
	return c.bus.Subscribe()
}

// Credentials returns the attached credential manager, or nil.
func (c *Client) Credentials() *corecredentials.Manager {
	return c.creds
}

// SendMessage builds and writes a plaintext text stanza. End-to-end
// encryption (Signal) is not wired yet; the frame is only protected by the
// transport encryption when a Noise connector is installed.
func (c *Client) SendMessage(ctx context.Context, msg Message) (string, error) {
	return c.sender.SendText(ctx, msg.To, msg.Text)
}

// SetSignalIdentity sets this client's Signal identity public key, which is
// mixed into every message MAC.
func (c *Client) SetSignalIdentity(identity [32]byte) { c.sender.SetIdentity(identity) }

// SetSignalPeer installs an established peer session. The caller owns
// persistence through core/signalsession.
func (c *Client) SetSignalPeer(peer string, session *coremessaging.PeerSession) error {
	return c.sender.SetPeer(peer, session)
}

// SendEncryptedMessage encrypts and sends text using the peer session.
func (c *Client) SendEncryptedMessage(ctx context.Context, to, text string) (string, *coremessaging.PeerSession, error) {
	return c.sender.SendEncryptedText(ctx, to, text)
}

// SetReceiveSignalPeer installs the peer session used for inbound decryption.
func (c *Client) SetReceiveSignalPeer(peer string, session *coremessaging.PeerSession) error {
	return c.receiver.SetReceiverPeer(peer, session)
}

// SetReceiveSignalIdentity sets the identity used to authenticate inbound
// Signal messages.
func (c *Client) SetReceiveSignalIdentity(identity [32]byte) {
	c.receiver.SetReceiverIdentity(identity)
}

// SetSignalIdentityPair sets the identity key pair, required to start a new
// session from a peer bundle.
func (c *Client) SetSignalIdentityPair(pair signal.KeyPair) {
	c.sender.SetIdentityPair(pair)
}

// SetPreKeyBundleSource installs the peer bundle provider used by
// SendPreKeyMessage.
func (c *Client) SetPreKeyBundleSource(source coremessaging.PreKeyBundleSource) {
	c.sender.SetPreKeyBundleSource(source)
}

// SendPreKeyMessage starts a session from the peer bundle and sends the first
// message as a pkmsg carrier.
func (c *Client) SendPreKeyMessage(ctx context.Context, to, text string, registrationID uint32) (string, *coremessaging.PeerSession, error) {
	return c.sender.SendPreKeyText(ctx, to, text, registrationID)
}

// SetPreKeySource installs the prekey provider used to bootstrap inbound
// prekey messages.
func (c *Client) SetPreKeySource(source coremessaging.PreKeySource) {
	c.receiver.SetPreKeySource(source)
}

// SendReceipt writes a delivery/read/played receipt for a message id.
func (c *Client) SendReceipt(ctx context.Context, to, id, receiptType string) error {
	return c.sender.SendReceipt(ctx, to, id, receiptType)
}

// Close stops the session and, when the client owns it, closes the event bus.
// It is idempotent.
func (c *Client) Close(ctx context.Context) error {
	err := c.session.Stop(ctx)
	if c.ownBus {
		c.bus.Close()
	}
	return err
}
