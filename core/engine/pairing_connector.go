package engine

import (
	"context"
	"fmt"

	"github.com/angga0x3/whatscore/protocol/transport"
)

// pairingConnector pairs an unpaired device over one Connect call, so the
// session actor sees a normal Connect: dial → handshake → registration
// payload → StartPairing (the QR codes stream onto the bus as
// TypePairingCode events) → the phone scans → pair-success verified and
// signed → onPaired persists the credentials → the pairing connection is
// retired and a fresh connection logs in with the new credentials.
//
// The two-connection shape is what the live pairing flow requires (PF-073,
// PF-077): the pairing connection ends after pair-device-sign, and the
// server only answers <success> to a login payload carried by a fresh
// handshake.
type pairingConnector struct {
	engine   *Engine
	onPaired func(CredentialResult) error
}

// PairingConnector returns a session.Connector that pairs an unpaired device
// and then logs in with the fresh credentials. onPaired runs between the two
// connections: a composition root that drops the credentials there loses the
// pairing, because the login connection presents exactly the identity the
// server just issued.
func (e *Engine) PairingConnector(onPaired func(CredentialResult) error) interface {
	Connect(context.Context, transport.FrameConn) (transport.FrameConn, error)
} {
	return &pairingConnector{engine: e, onPaired: onPaired}
}

// Connect runs pairing to completion and then logs in, returning the login
// connection to the session. raw must be freshly dialed and untouched; the
// pairing connection is closed inside this call and a second connection is
// dialed from the engine's own dialer.
func (c *pairingConnector) Connect(ctx context.Context, raw transport.FrameConn) (transport.FrameConn, error) {
	if raw == nil {
		return nil, fmt.Errorf("%w: nil frame connection", ErrInvalidConfig)
	}
	if c.engine.cfg.Credentials != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: pairing connector given an already-paired engine", ErrInvalidConfig)
	}
	if c.engine.cfg.Dialer == nil {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: pairing connector needs a dialer for the login connection", ErrInvalidConfig)
	}

	payload, err := c.engine.clientPayload()
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: building registration payload: %w", ErrAuthFailed, err)
	}
	secure, err := c.engine.handshakeOver(ctx, raw, payload)
	if err != nil {
		return nil, err
	}
	conn := c.engine.newConn(secure)

	if _, err := conn.StartPairing(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: starting pairing: %w", ErrPairingFailed, err)
	}
	result, err := conn.WaitPairing(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if c.onPaired != nil {
		if err := c.onPaired(*result); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: persisting paired credentials: %w", ErrPairingFailed, err)
		}
	}
	// The pairing stream has served its purpose; the login connection starts
	// from a fresh dial.
	_ = conn.Close()

	loginEngine, err := c.engine.withCredentials(*result)
	if err != nil {
		return nil, fmt.Errorf("%w: building login engine: %w", ErrAuthFailed, err)
	}
	loginPayload, err := loginEngine.loginPayload()
	if err != nil {
		return nil, fmt.Errorf("%w: building login payload: %w", ErrAuthFailed, err)
	}
	raw2, err := c.engine.cfg.Dialer.Dial(ctx, c.engine.cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: dialing the login connection: %w", ErrAuthFailed, err)
	}
	secure2, err := loginEngine.handshakeOver(ctx, raw2, loginPayload)
	if err != nil {
		return nil, err
	}
	if err := loginEngine.awaitVerdict(ctx, secure2); err != nil {
		_ = secure2.Close()
		return nil, err
	}
	return secure2, nil
}
