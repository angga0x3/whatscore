package engine

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/angga0x3/whatscore/protocol/transport"
)

// DefaultAuthTimeout bounds how long the connector waits for the server's
// post-handshake verdict when the caller's context carries no deadline.
const DefaultAuthTimeout = 20 * time.Second

// authConnector wraps Connector with the auth-outcome step, so a session only
// reaches CONNECTED after the server actually accepted the payload.
//
// Connector alone stops at handshake completion, which would report CONNECTED
// while the server was still deciding or had already rejected the device. This
// wrapper is what the composition root should use when the session state is
// user-visible.
type authConnector struct {
	engine  *Engine
	timeout time.Duration
}

// AuthConnector returns a session.Connector that performs the Noise handshake
// and then waits for <success>/<failure>. A rejection surfaces as ErrAuthFailed
// instead of a healthy connection.
func (e *Engine) AuthConnector() interface {
	Connect(context.Context, transport.FrameConn) (transport.FrameConn, error)
} {
	return &authConnector{engine: e, timeout: e.cfg.AuthTimeout}
}

// Connect handshakes, then reads the auth outcome over the encrypted channel.
// The verdict is read before the connection is handed to the session, so the
// session's own reader loop cannot race it.
func (c *authConnector) Connect(ctx context.Context, raw transport.FrameConn) (transport.FrameConn, error) {
	encrypted, err := c.engine.Connector().Connect(ctx, raw)
	if err != nil {
		return nil, err
	}
	secure, ok := encrypted.(interface {
		ReadFrame(context.Context) ([]byte, error)
		Close() error
	})
	if !ok {
		_ = encrypted.Close()
		return nil, fmt.Errorf("%w: connector returned an unusable connection", ErrAuthFailed)
	}

	if c.timeout > 0 {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, c.timeout)
			defer cancel()
		}
	}

	if err := c.awaitVerdict(ctx, secure); err != nil {
		_ = encrypted.Close()
		return nil, err
	}
	return encrypted, nil
}

// awaitVerdict decodes frames until the auth outcome arrives. It uses the
// engine's codec so the interpretation matches WaitAuth's, and it fails closed:
// an undecodable frame or an unexpected stanza means the stream cannot be
// trusted before the session takes ownership of it.
func (c *authConnector) awaitVerdict(ctx context.Context, conn interface {
	ReadFrame(context.Context) ([]byte, error)
}) error {
	for {
		frame, err := conn.ReadFrame(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("%w: waiting for auth outcome: %w", ErrAuthFailed, ctxErr)
			}
			return fmt.Errorf("%w: waiting for auth outcome: %w", ErrAuthFailed, err)
		}
		node, err := c.engine.cfg.Codec.Decode(bytes.NewReader(frame))
		if err != nil {
			return fmt.Errorf("%w: undecodable frame before the auth outcome: %w", ErrUnexpectedStanza, err)
		}
		switch node.Tag {
		case tagSuccess:
			return nil
		case tagAck:
			continue
		case tagFailure:
			failure := parseFailure(node)
			return fmt.Errorf("%w: %s (reason %d)", ErrAuthFailed, failure.Message, failure.Reason)
		case tagStreamError:
			streamErr := parseStreamError(node)
			if streamErr.ConflictType != "" {
				return fmt.Errorf("%w: %s (%s)", ErrStreamError, streamErr.Code, streamErr.ConflictType)
			}
			return fmt.Errorf("%w: %s", ErrStreamError, streamErr.Code)
		default:
			return fmt.Errorf("%w: %s", ErrUnexpectedStanza, sanitizeServerText(node.Tag))
		}
	}
}
