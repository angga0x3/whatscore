package noise

import (
	"context"
	"fmt"

	"github.com/angga0x3/whatscore/protocol/transport"
)

// ClientConnector adapts a ClientHandshaker to the connection-wrapping shape
// used by the session runtime: it performs the handshake and returns the
// encrypted connection.
type ClientConnector struct {
	Handshaker *ClientHandshaker
}

// Connect runs the handshake over fr and returns the SecureConn.
func (c *ClientConnector) Connect(ctx context.Context, fr transport.FrameConn) (transport.FrameConn, error) {
	if c == nil || c.Handshaker == nil {
		return nil, fmt.Errorf("%w: nil handshaker", ErrHandshakeFailed)
	}
	return c.Handshaker.Handshake(ctx, fr)
}
