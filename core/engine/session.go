package engine

import (
	"context"
	"fmt"

	"github.com/angga0x3/whatscore/core/session"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// Connector adapts an Engine to core/session.Connector: it performs the Noise
// handshake over a connection the session already dialed. The session owns
// dialing, retry, and lifecycle; the engine owns the handshake and the
// ClientPayload. There is therefore exactly one dial path per process, and
// core/session never imports core/engine — the composition root passes this
// adapter in:
//
//	connector := eng.Connector()
//	sess, err := session.New(session.Config{
//		ID:        "primary",
//		Endpoint:  endpoint,
//		Dialer:    dialer,
//		Connector: connector,
//		...
//	})
//
// A connector may be shared by several sessions and reconnect attempts: it
// holds no per-connection state, builds a fresh ClientPayload per attempt (so
// rotated prekeys are picked up), and returns an independent SecureConn each
// time.
func (e *Engine) Connector() session.Connector {
	return &connector{engine: e}
}

// connector is the adapter returned by Engine.Connector.
type connector struct {
	engine *Engine
}

var _ session.Connector = (*connector)(nil)

// Connect runs the client Noise handshake (PF-007) over raw and returns the
// encrypted connection. raw must be freshly dialed and untouched: the
// handshake consumes the first three frames. On success the returned
// SecureConn owns raw and closes it when closed. On failure raw is closed
// before the error is returned (noise.DoClientHandshake enforces that for
// handshake failures; a payload-build failure closes it here), so the caller
// never leaks a half-open connection.
//
// Every error wraps ErrAuthFailed: the server did not accept this device.
func (c *connector) Connect(ctx context.Context, raw transport.FrameConn) (transport.FrameConn, error) {
	if raw == nil {
		return nil, fmt.Errorf("%w: nil frame connection", ErrInvalidConfig)
	}
	payload, err := c.engine.clientPayload()
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: building client payload: %w", ErrAuthFailed, err)
	}
	return c.engine.handshakeOver(ctx, raw, payload)
}

// handshakeOver runs the Noise client handshake with an already-built payload
// and wraps every failure as ErrAuthFailed. Connect and Connector both go
// through it, so the handshake and its error shape exist once. The payload is
// a parameter rather than built here because Connect builds it before dialing
// (a configuration error then fails without opening a socket).
func (e *Engine) handshakeOver(ctx context.Context, fr transport.FrameConn, payload []byte) (noise.SecureConn, error) {
	sc, err := noise.DoClientHandshake(ctx, fr, e.cfg.NoiseKey, e.cfg.RootPub, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: noise handshake: %w", ErrAuthFailed, err)
	}
	return sc, nil
}
