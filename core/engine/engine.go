// Package engine is the orchestration layer that turns the protocol modules
// into a real connection sequence. It owns no wire format and no crypto of
// its own: it dials through an injected transport.Dialer, runs the Noise
// client handshake (PF-004..PF-009), builds the post-handshake ClientPayload
// with protocol/auth (PF-020..PF-027), exchanges binary nodes through
// protocol/binary, and drives the pairing exchange of protocol/pairing
// (PF-015..PF-017).
//
// A Conn is the result of Connect: an encrypted frame connection plus a
// node codec and an optional frame pump. The pump consumes frames through a
// FrameHandler, the same shape core/session uses, so callers can plug in
// core/messaging's Receiver without core/engine importing it (and without
// risking an import cycle as core/messaging grows). Pairing reads frames
// directly instead; the two readers are mutually exclusive by construction.
//
// What is deliberately not wired:
//
//   - Device-identity signing after pair-success (PF-017). StartPairing
//     verifies the server's container and then refuses to complete without
//     an injected signal.Signer, returning ErrSignerRequired. Generating the
//     device signature needs an XEdDSA device signer that protocol/signal
//     does not expose yet; see docs/architecture/engine.md.
//   - Reconnect/backoff. That is core/session's job; this package is one
//     dial, one handshake, one connection.
//   - Signal session establishment and messaging. Those operate on the
//     returned Conn through their own packages.
//
// Import direction: core/engine imports protocol/*, core/events, and
// core/session. The core/session import exists only for the Connector adapter
// (session.go); core/session itself never imports core/engine, so the
// dependency stays one-way and the composition root injects the adapter.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/auth"
	"github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/pairing"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// Sentinel errors. Callers match with errors.Is; every returned error wraps
// one of these with %w plus context (technical specification §8.1).
var (
	// ErrNotConnected is returned by Conn methods after Close, or when an
	// operation needs a live connection and none exists.
	ErrNotConnected = errors.New("engine: not connected")

	// ErrAuthFailed is returned when the ClientPayload cannot be built or
	// the Noise handshake fails: from the caller's perspective the server
	// did not accept the client as this device.
	ErrAuthFailed = errors.New("engine: authentication failed")

	// ErrStreamError is returned by WaitAuth when the server answers the
	// ClientPayload with a <stream:error> stanza (PF-029).
	ErrStreamError = errors.New("engine: stream error")

	// ErrUnexpectedStanza is returned by WaitAuth when the server sends
	// something other than a <success>, <failure>, <stream:error>, or the
	// documented benign <ack> before the auth outcome. See WaitAuth for why
	// this fails closed instead of skipping the stanza.
	ErrUnexpectedStanza = errors.New("engine: unexpected stanza before the auth outcome")

	// ErrSignerRequired is returned by the pairing flow when device-identity
	// signing would be needed but no signal.Signer was injected. The server
	// container has already been verified when this error is returned.
	ErrSignerRequired = errors.New("engine: signer required")

	// ErrPairingFailed is returned for a malformed pairing exchange: an
	// undecodable pair-device/pair-success stanza, a failed identity
	// verification, or a closed connection while pairing is in flight.
	ErrPairingFailed = errors.New("engine: pairing failed")

	// ErrReaderBusy is returned when a second reader (pump or pairing) is
	// started on one Conn. A transport connection supports exactly one
	// reader (transport.FrameConn contract).
	ErrReaderBusy = errors.New("engine: another reader is active")

	// ErrInvalidConfig is returned by New for unusable configuration.
	ErrInvalidConfig = errors.New("engine: invalid config")
)

// Defaults for the registration ClientPayload. The values mirror the
// reference base payload recorded in docs/protocol/auth.md (PF-021, PF-022,
// PF-024) and act as placeholders until the version registry (§7) owns them.
var (
	// DefaultVersion is the WhatsApp Web version used for the user agent's
	// app version and the MD5 build hash (PF-021, PF-023).
	DefaultVersion = auth.Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849}

	// DefaultUserAgent is the reference registration user agent (PF-021).
	DefaultUserAgent = auth.UserAgent{
		Platform:       protobuf.ClientPayload_UserAgent_WEB,
		ReleaseChannel: protobuf.ClientPayload_UserAgent_RELEASE,
		MCC:            "000",
		MNC:            "000",
		OSVersion:      "0.1",
		Manufacturer:   "",
		Device:         "Desktop",
		OSBuildNumber:  "0.1",
		LocaleLanguage: "en",
		LocaleCountry:  "US",
	}

	// DefaultDeviceProps is the companion DeviceProps subset WhatsCore emits
	// (PF-024). It matches the gaps documented there: os="whatscore",
	// version 0.1.0, platform UNKNOWN, no historySyncConfig.
	DefaultDeviceProps = auth.DeviceProps{
		OS:              "whatscore",
		Version:         auth.Version{Primary: 0, Secondary: 1, Tertiary: 0},
		PlatformType:    protobuf.DeviceProps_UNKNOWN,
		RequireFullSync: false,
	}
)

// Credentials selects the paired-device login form (PF-026, PF-027). When
// Config.Credentials is nil, Connect sends the registration form built by
// auth.BuildClientPayload instead.
type Credentials struct {
	// Username is the user part of the paired account JID (field 1).
	Username uint64
	// Device is the companion device ID (field 18), at most 0xFFFF.
	Device uint32
}

// PreKeyProvider supplies the public registration key material for the
// registration ClientPayload (PF-023). *core/prekeys.Manager satisfies it
// with its Bundle method; the boolean selects whether a one-time prekey is
// included (registration does not need one).
type PreKeyProvider interface {
	Bundle(includeOneTime bool) signal.PreKeyBundle
}

// FrameHandler consumes inbound frames. Calls are serialized; a returned
// error stops the pump and is surfaced by Conn.Pump. It is structurally
// identical to core/session.FrameHandler, so a core/messaging.Receiver can
// be passed directly.
type FrameHandler interface {
	HandleFrame(ctx context.Context, frame []byte) error
}

// FrameHandlerFunc adapts a function to FrameHandler.
type FrameHandlerFunc func(ctx context.Context, frame []byte) error

// HandleFrame implements FrameHandler.
func (f FrameHandlerFunc) HandleFrame(ctx context.Context, frame []byte) error {
	return f(ctx, frame)
}

// Config describes one engine connection. SessionID, Dialer, NoiseKey,
// RootPub, and Identity are required; everything else has a documented
// default or an optional behaviour.
//
// Treat Config as immutable after New.
type Config struct {
	// SessionID identifies the session in logs and on pairing events.
	SessionID string

	// Endpoint is passed verbatim to the dialer (URL and dial options).
	Endpoint transport.Endpoint

	// Dialer opens the transport connection. Tests inject in-memory pairs;
	// production injects transport.WebSocketDialer.
	Dialer transport.Dialer

	// NoiseKey is the long-lived Curve25519 Noise static key pair
	// (PF-004..PF-007). Its public half goes into msg3.static and into the
	// pairing QR payload.
	NoiseKey noise.KeyPair

	// RootPub is the pinned 32-byte server root public key used to verify
	// the server certificate chain (PF-009).
	RootPub []byte

	// Identity is this device's Signal identity key pair. Its public half is
	// carried in the registration payload (PF-023) and the pairing QR code
	// (PF-015).
	Identity signal.KeyPair

	// RegistrationID is the Signal registration ID (PF-023). It is ignored
	// for the login form.
	RegistrationID uint32

	// PreKeys supplies the signed prekey and its signature for the
	// registration payload. It is required when Credentials is nil.
	PreKeys PreKeyProvider

	// Signer signs the device identity during pairing (PF-017). Nil makes
	// StartPairing fail with ErrSignerRequired after the server container has
	// been verified, so no unsigned credential is ever returned.
	Signer DeviceSigner

	// Credentials, when non-nil, selects the login form (PF-026) instead of
	// the registration form.
	Credentials *Credentials

	// AdvSecret is the 32-byte companion advertising secret (PF-015,
	// PF-017). It is part of every pairing QR payload and authenticates the
	// pair-success device identity; pairing requires a non-zero value.
	AdvSecret [32]byte

	// ClientType is the opaque client-type field of the QR payload
	// (PF-015). Empty is allowed.
	ClientType string

	// Bus, when non-nil, receives events.TypePairingCode events as QR
	// payloads become valid. The engine never closes the bus.
	Bus *events.Bus

	// Logger receives diagnostic logs. Nil discards them.
	Logger *slog.Logger

	// AuthTimeout bounds AuthConnector's wait for the server verdict. Zero uses
	// DefaultAuthTimeout; negative disables the internal deadline and relies on
	// the caller's context alone.
	AuthTimeout time.Duration
	// Codec encodes and decodes binary nodes. Nil uses binary.NewCodec(nil):
	// an empty dictionary, so every tag and attribute encodes raw. Inject a
	// dictionary-backed codec to use wire tokens (PF-010..PF-014).
	Codec binary.Codec

	// FrameHandler, when non-nil, is invoked by Conn.Pump for every inbound
	// frame. Nil discards frames (reading still detects connection drops).
	FrameHandler FrameHandler

	// Version overrides DefaultVersion for the ClientPayload.
	Version auth.Version

	// UserAgent overrides DefaultUserAgent for the ClientPayload.
	UserAgent auth.UserAgent

	// DeviceProps overrides DefaultDeviceProps for the registration payload.
	DeviceProps auth.DeviceProps

	// ConnectType and ConnectReason default to WIFI_UNKNOWN and
	// USER_ACTIVATED (PF-022).
	ConnectType   protobuf.ClientPayload_ConnectType
	ConnectReason protobuf.ClientPayload_ConnectReason
}

// Engine is the validated, immutable configuration plus a logger. It is safe
// for concurrent use: Connect may be called multiple times, each call
// producing an independent Conn.
type Engine struct {
	cfg    Config
	logger *slog.Logger
}

// New validates cfg, applies documented defaults, and returns an Engine.
func New(cfg Config) (*Engine, error) {
	if cfg.SessionID == "" {
		return nil, fmt.Errorf("%w: empty session id", ErrInvalidConfig)
	}
	if cfg.Dialer == nil {
		return nil, fmt.Errorf("%w: nil dialer", ErrInvalidConfig)
	}
	if len(cfg.RootPub) != 32 {
		return nil, fmt.Errorf("%w: root public key must be 32 bytes, got %d", ErrInvalidConfig, len(cfg.RootPub))
	}
	if cfg.NoiseKey.Pub == ([32]byte{}) || cfg.NoiseKey.Priv == ([32]byte{}) {
		return nil, fmt.Errorf("%w: noise key pair is unset", ErrInvalidConfig)
	}
	if cfg.Identity.Public == ([32]byte{}) || cfg.Identity.Private == ([32]byte{}) {
		return nil, fmt.Errorf("%w: signal identity key pair is unset", ErrInvalidConfig)
	}
	if cfg.Credentials == nil && cfg.PreKeys == nil {
		return nil, fmt.Errorf("%w: registration needs a PreKeyProvider", ErrInvalidConfig)
	}
	if cfg.Version == (auth.Version{}) {
		cfg.Version = DefaultVersion
	}
	if cfg.UserAgent == (auth.UserAgent{}) {
		cfg.UserAgent = DefaultUserAgent
	}
	if cfg.DeviceProps == (auth.DeviceProps{}) {
		cfg.DeviceProps = DefaultDeviceProps
	}
	if cfg.ConnectType == protobuf.ClientPayload_CELLULAR_UNKNOWN {
		cfg.ConnectType = protobuf.ClientPayload_WIFI_UNKNOWN
	}
	if cfg.ConnectReason == protobuf.ClientPayload_PUSH {
		cfg.ConnectReason = protobuf.ClientPayload_USER_ACTIVATED
	}
	if cfg.Codec == nil {
		cfg.Codec = binary.NewCodec(nil)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	// Copy the slice so later mutation by the caller cannot change a
	// connection that is already handshaking.
	cfg.RootPub = append([]byte(nil), cfg.RootPub...)
	return &Engine{cfg: cfg, logger: cfg.Logger}, nil
}

// Config returns a copy of the effective configuration (defaults applied).
func (e *Engine) Config() Config {
	cfg := e.cfg
	cfg.RootPub = append([]byte(nil), cfg.RootPub...)
	return cfg
}

// Connect runs the full client sequence once:
//
//	dial (transport.Dialer) → build ClientPayload (protocol/auth) →
//	Noise handshake (noise.DoClientHandshake) → *Conn
//
// The returned Conn owns the encrypted connection. On any failure the
// underlying transport is closed by the failing stage.
func (e *Engine) Connect(ctx context.Context) (*Conn, error) {
	payload, err := e.clientPayload()
	if err != nil {
		return nil, fmt.Errorf("%w: building client payload: %w", ErrAuthFailed, err)
	}

	fr, err := e.cfg.Dialer.Dial(ctx, e.cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("engine: dial %q: %w", e.cfg.Endpoint.URL, err)
	}

	sc, err := e.handshakeOver(ctx, fr, payload)
	if err != nil {
		return nil, err
	}

	e.logger.Debug("engine connected",
		"session", e.cfg.SessionID,
		"cipher_suite", sc.CipherSuiteName(),
		"form", e.payloadForm(),
	)
	return &Conn{
		engine:   e,
		sc:       sc,
		codec:    e.cfg.Codec,
		handler:  e.cfg.FrameHandler,
		logger:   e.logger,
		closedCh: make(chan struct{}),
	}, nil
}

// payloadForm reports which ClientPayload form Connect uses, for logs.
func (e *Engine) payloadForm() string {
	if e.cfg.Credentials != nil {
		return "login"
	}
	return "registration"
}

// clientPayload selects and builds the ClientPayload form (PF-025, PF-027):
// login when credentials are supplied, registration otherwise.
func (e *Engine) clientPayload() ([]byte, error) {
	if e.cfg.Credentials != nil {
		return auth.BuildLoginPayload(auth.LoginInput{
			Version:       e.cfg.Version,
			UserAgent:     e.cfg.UserAgent,
			WebInfo:       auth.WebInfo{SubPlatform: protobuf.ClientPayload_WebInfo_WEB_BROWSER},
			ConnectType:   e.cfg.ConnectType,
			ConnectReason: e.cfg.ConnectReason,
			Username:      e.cfg.Credentials.Username,
			Device:        e.cfg.Credentials.Device,
		})
	}
	if e.cfg.PreKeys == nil {
		return nil, fmt.Errorf("%w: no prekey provider", ErrInvalidConfig)
	}
	bundle := e.cfg.PreKeys.Bundle(false)
	// PF-023: eIdent is this device's identity and eSkeySig is the identity's
	// signature over the signed prekey. A provider that signs with a different
	// identity would produce a payload the server cannot use, so fail closed.
	if bundle.IdentityKey != ([32]byte{}) && bundle.IdentityKey != e.cfg.Identity.Public {
		return nil, fmt.Errorf("%w: prekey provider identity does not match the configured identity", ErrInvalidConfig)
	}
	return auth.BuildClientPayload(auth.Input{
		Version:       e.cfg.Version,
		UserAgent:     e.cfg.UserAgent,
		WebInfo:       auth.WebInfo{SubPlatform: protobuf.ClientPayload_WebInfo_WEB_BROWSER},
		ConnectType:   e.cfg.ConnectType,
		ConnectReason: e.cfg.ConnectReason,
		Registration: auth.Registration{
			RegistrationID:        e.cfg.RegistrationID,
			IdentityKey:           e.cfg.Identity.Public[:],
			SignedPreKeyID:        bundle.SignedPreKeyID,
			SignedPreKey:          bundle.SignedPreKey[:],
			SignedPreKeySignature: bundle.SignedPreKeySignature,
		},
		DeviceProps: e.cfg.DeviceProps,
	})
}

// Conn is one established, Noise-encrypted connection. It supports one
// concurrent reader and one concurrent writer, matching the transport
// contract: WriteNode may run while Pump or pairing reads.
type Conn struct {
	engine  *Engine
	sc      noise.SecureConn
	codec   binary.Codec
	handler FrameHandler
	logger  *slog.Logger

	mu     sync.Mutex
	closed bool
	reader string // non-empty while a reader owns the connection
	// closedCh is closed by Close so blocked helpers (a pairing code send)
	// unblock even when their context has no deadline.
	closedCh chan struct{}

	pairing *pairingFlow
}

// SecureConn exposes the encrypted frame connection for callers that need
// raw frames (for example a media pipeline). The Conn remains the owner of
// Close.
func (c *Conn) SecureConn() noise.SecureConn { return c.sc }

// CipherSuite returns the negotiated Noise suite (PF-004).
func (c *Conn) CipherSuite() string { return c.sc.CipherSuiteName() }

// WriteNode encodes node and writes it as one encrypted frame. Encoding is
// deterministic (PF-011: attributes are emitted in lexicographic key order).
func (c *Conn) WriteNode(ctx context.Context, node *binary.Node) error {
	if node == nil {
		return fmt.Errorf("engine: cannot write a nil node")
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return ErrNotConnected
	}
	frame, err := c.codec.Encode(node)
	if err != nil {
		return fmt.Errorf("engine: encoding node %q: %w", node.Tag, err)
	}
	if err := c.sc.WriteFrame(ctx, frame); err != nil {
		return fmt.Errorf("engine: writing node %q: %w", node.Tag, err)
	}
	return nil
}

// ReadNode reads one encrypted frame and decodes exactly one node from it.
func (c *Conn) ReadNode(ctx context.Context) (*binary.Node, error) {
	if err := c.beginRead("read"); err != nil {
		return nil, err
	}
	defer c.endRead()
	frame, err := c.sc.ReadFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("engine: reading frame: %w", err)
	}
	node, err := c.codec.Decode(bytes.NewReader(frame))
	if err != nil {
		return nil, fmt.Errorf("engine: decoding frame: %w", err)
	}
	return node, nil
}

// Pump reads frames until the connection fails, ctx is done, or the
// configured FrameHandler returns an error, and returns that error. With no
// FrameHandler it drains frames so connection drops are still detected.
//
// Pump is the only reader while it runs; ReadNode and StartPairing return
// ErrReaderBusy concurrently.
func (c *Conn) Pump(ctx context.Context) error {
	if err := c.beginRead("pump"); err != nil {
		return err
	}
	defer c.endRead()
	return c.pumpLoop(ctx)
}

// StartPump runs the pump in a background goroutine and returns its result
// channel (buffered, exactly one value). The goroutine ends when the
// connection closes, ctx is done, or the frame handler fails.
func (c *Conn) StartPump(ctx context.Context) (<-chan error, error) {
	if err := c.beginRead("pump"); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() {
		defer c.endRead()
		defer close(done)
		done <- c.pumpLoop(ctx)
	}()
	return done, nil
}

// pumpLoop is the shared body of Pump and StartPump.
func (c *Conn) pumpLoop(ctx context.Context) error {
	for {
		frame, err := c.sc.ReadFrame(ctx)
		if err != nil {
			return err
		}
		if c.handler == nil {
			continue
		}
		if err := c.handler.HandleFrame(ctx, frame); err != nil {
			return fmt.Errorf("engine: frame handler: %w", err)
		}
	}
}

// Close closes the encrypted connection and marks the Conn unusable. It is
// idempotent; repeated calls return nil. In-flight reads unblock with the
// transport's close error.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.closedCh)
	c.mu.Unlock()
	return c.sc.Close()
}

// beginRead claims the single reader slot. op names the operation for the
// contention error.
func (c *Conn) beginRead(op string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrNotConnected
	}
	if c.reader != "" {
		return fmt.Errorf("%w: %s is reading, cannot start %s", ErrReaderBusy, c.reader, op)
	}
	c.reader = op
	return nil
}

func (c *Conn) endRead() {
	c.mu.Lock()
	c.reader = ""
	c.mu.Unlock()
}

// DeviceSigner signs the device-identity message described in PF-017.
// signal.XEdDSASigner implements it; the interface exists so tests can inject a
// deterministic signer and so the engine does not depend on one construction.
type DeviceSigner interface {
	SignDeviceIdentity(details, identityPub, accountSignatureKey []byte) ([]byte, error)
}

// CredentialResult is the verified outcome of a pairing run (PF-016,
// PF-017). It carries the server's device identity plus the local key
// material a caller persists as core/credentials.Record.
type CredentialResult struct {
	// JID and LID identify the newly paired device.
	JID string
	LID string
	// BusinessName and Platform echo the pair-success metadata.
	BusinessName string
	Platform     string
	// ClientProps is the opaque client-props blob from pair-success.
	ClientProps []byte
	// Device is the authenticated server identity (PF-017).
	Device *pairing.DeviceIdentity

	// Local credentials to persist.
	NoiseKey       noise.KeyPair
	Identity       signal.KeyPair
	AdvSecret      [32]byte
	RegistrationID uint32

	// DeviceSignature is the companion signature over the device identity
	// (PF-017 deviceSignature). It is always empty: generating it is the
	// signing step that is not wired yet (see StartPairing).
	DeviceSignature []byte
}

// pairingFlow carries one StartPairing run: QR batches, completion, result.
type pairingFlow struct {
	codes chan []pairing.QRPayload
	done  chan struct{}

	mu     sync.Mutex
	result *CredentialResult
	err    error
}

func (f *pairingFlow) finish(result *CredentialResult, err error) {
	f.mu.Lock()
	f.result = result
	f.err = err
	f.mu.Unlock()
	close(f.done)
}

func (f *pairingFlow) outcome() (*CredentialResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.result, f.err
}

// StartPairing starts the pairing exchange on the connection. It claims the
// reader slot, answers each server <pair-device> stanza with a PairDeviceAck
// (PF-016), and emits the QR payloads derived from its refs (PF-015). On
// <pair-success> it parses the stanza and verifies the device identity
// against the configured adv secret and identity public key (PF-017).
//
// The returned channel yields one batch per <pair-device> stanza and is
// closed when the flow ends. WaitPairing returns the final outcome:
//
//   - a *CredentialResult on success;
//   - ErrSignerRequired when verification succeeded but no Signer is
//     configured. Device-identity signing (PF-017 deviceSignature) is not
//     implemented; the gate makes that gap explicit instead of returning an
//     unsigned credential as if pairing had completed.
//   - ErrPairingFailed on a malformed stanza, failed verification, or a
//     dropped connection.
//
// Pairing and Pump cannot run at the same time; only one reader is allowed.
// A Conn supports one pairing run: a second StartPairing after the first
// finished returns ErrPairingFailed ("already started") rather than waiting
// for a pair-success that will never come.
func (c *Conn) StartPairing(ctx context.Context) (<-chan []pairing.QRPayload, error) {
	if c.engine.cfg.AdvSecret == ([32]byte{}) {
		return nil, fmt.Errorf("%w: pairing needs a non-zero adv secret", ErrInvalidConfig)
	}

	flow := &pairingFlow{
		codes: make(chan []pairing.QRPayload, 4),
		done:  make(chan struct{}),
	}
	// Claim the reader slot and the pairing flow in one critical section so
	// two callers cannot both start a flow.
	c.mu.Lock()
	switch {
	case c.closed:
		c.mu.Unlock()
		return nil, ErrNotConnected
	case c.pairing != nil:
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: pairing already started", ErrPairingFailed)
	case c.reader != "":
		reader := c.reader
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %s is reading, cannot start pairing", ErrReaderBusy, reader)
	}
	c.reader = "pairing"
	c.pairing = flow
	c.mu.Unlock()

	go func() {
		defer c.endRead()
		defer close(flow.codes)
		flow.finish(c.runPairing(ctx, flow))
	}()
	return flow.codes, nil
}

// WaitPairing blocks until the pairing flow started by StartPairing ends,
// ctx is done, or the Conn is closed, and returns its outcome.
func (c *Conn) WaitPairing(ctx context.Context) (*CredentialResult, error) {
	c.mu.Lock()
	flow := c.pairing
	c.mu.Unlock()
	if flow == nil {
		return nil, fmt.Errorf("%w: pairing not started", ErrPairingFailed)
	}
	select {
	case <-flow.done:
		return flow.outcome()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// runPairing is the pairing reader loop. It returns the outcome that
// flow.finish publishes.
func (c *Conn) runPairing(ctx context.Context, flow *pairingFlow) (*CredentialResult, error) {
	for {
		frame, err := c.sc.ReadFrame(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: reading frame: %w", ErrPairingFailed, err)
		}
		node, err := c.codec.Decode(bytes.NewReader(frame))
		if err != nil {
			// Frames outside the pairing exchange are not ours to judge;
			// log and keep reading, like core/messaging's receiver.
			c.logger.WarnContext(ctx, "pairing: dropping undecodable frame", "error", err)
			continue
		}
		if node.Tag != "iq" {
			continue
		}

		switch {
		case childOf(node, "pair-device") != nil:
			if err := c.handlePairDevice(ctx, flow, node); err != nil {
				return nil, err
			}
		case childOf(node, "pair-success") != nil:
			return c.handlePairSuccess(ctx, node)
		}
	}
}

// handlePairDevice acknowledges the stanza and publishes the QR payloads.
func (c *Conn) handlePairDevice(ctx context.Context, flow *pairingFlow, node *binary.Node) error {
	refs, err := pairing.ParsePairDevice(node)
	if err != nil {
		return fmt.Errorf("%w: pair-device: %w", ErrPairingFailed, err)
	}
	ack, err := pairing.PairDeviceAck(node)
	if err != nil {
		return fmt.Errorf("%w: pair-device ack: %w", ErrPairingFailed, err)
	}
	if err := c.WriteNode(ctx, ack); err != nil {
		return fmt.Errorf("%w: writing pair-device ack: %w", ErrPairingFailed, err)
	}

	cfg := c.engine.cfg
	payloads := make([]pairing.QRPayload, 0, len(refs))
	for _, ref := range refs {
		payload := pairing.QRPayload{
			Ref:               ref,
			NoisePublicKey:    cfg.NoiseKey.Pub,
			IdentityPublicKey: cfg.Identity.Public,
			AdvSecret:         cfg.AdvSecret,
			ClientType:        cfg.ClientType,
		}
		// Encode validates the payload and produces the string a caller
		// renders as a QR code (rendering itself is out of scope).
		code, err := payload.Encode()
		if err != nil {
			return fmt.Errorf("%w: encoding QR payload: %w", ErrPairingFailed, err)
		}
		if cfg.Bus != nil {
			cfg.Bus.Publish(events.Event{
				Type:      events.TypePairingCode,
				SessionID: cfg.SessionID,
				PairingCode: &events.PairingCode{
					Code: code,
				},
			})
		}
		payloads = append(payloads, payload)
	}

	select {
	case flow.codes <- payloads:
		return nil
	case <-c.closedCh:
		return fmt.Errorf("%w: connection closed before the QR payloads were consumed", ErrPairingFailed)
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrPairingFailed, ctx.Err())
	}
}

// handlePairSuccess parses and verifies the completion stanza. The signing
// step that would produce our device signature is the documented gap.
func (c *Conn) handlePairSuccess(ctx context.Context, node *binary.Node) (*CredentialResult, error) {
	cfg := c.engine.cfg
	success, err := pairing.ParsePairSuccess(node)
	if err != nil {
		return nil, fmt.Errorf("%w: pair-success: %w", ErrPairingFailed, err)
	}
	device, err := pairing.VerifyDeviceIdentity(success.DeviceIdentity, cfg.AdvSecret[:], cfg.Identity.Public[:])
	if err != nil {
		return nil, fmt.Errorf("%w: verifying device identity: %w", ErrPairingFailed, err)
	}

	if cfg.Signer == nil {
		return nil, fmt.Errorf("%w: pair-success verified for %s but no device signer is configured",
			ErrSignerRequired, success.ID)
	}

	// PF-017: sign 0x06,0x01 ‖ details ‖ identityPub ‖ accountSignatureKey.
	// The account signature key comes from the verified server container, so
	// the signature binds this device to the identity the server just issued.
	deviceSignature, err := cfg.Signer.SignDeviceIdentity(
		device.Details, cfg.Identity.Public[:], device.AccountKey)
	if err != nil {
		return nil, fmt.Errorf("%w: signing device identity: %w", ErrPairingFailed, err)
	}

	c.logger.InfoContext(ctx, "pairing verified", "session", cfg.SessionID, "jid", success.ID)
	return &CredentialResult{
		JID:             success.ID,
		LID:             success.LID,
		BusinessName:    success.BusinessName,
		Platform:        success.Platform,
		ClientProps:     success.ClientProps,
		Device:          device,
		NoiseKey:        cfg.NoiseKey,
		Identity:        cfg.Identity,
		AdvSecret:       cfg.AdvSecret,
		RegistrationID:  cfg.RegistrationID,
		DeviceSignature: deviceSignature,
	}, nil
}

// childOf returns the first child of node with tag, or nil.
func childOf(node *binary.Node, tag string) *binary.Node {
	for i := range node.Children {
		if node.Children[i].Tag == tag {
			return &node.Children[i]
		}
	}
	return nil
}
