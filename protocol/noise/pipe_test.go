package noise

import (
	"context"
	"fmt"
	"sync"

	"github.com/angga0x3/whatscore/protocol/transport"
)

// pipeConn is an in-memory transport.FrameConn for tests: frames written
// to one end become readable at the other end. It implements the same
// concurrency contract as the real transport (one reader, one writer,
// safe Close), and reports transport.ErrClosed after Close so tests can
// assert error wrapping.
type pipeConn struct {
	name       string
	in         chan []byte
	peerIn     chan []byte
	peerClosed chan struct{}
	closeOnce  sync.Once
	closed     chan struct{}
}

// newPipePair returns two connected FrameConns: writes on a are readable
// on b and vice versa.
func newPipePair() (*pipeConn, *pipeConn) {
	aclosed := make(chan struct{})
	bclosed := make(chan struct{})
	ach := make(chan []byte, 64)
	bch := make(chan []byte, 64)
	a := &pipeConn{name: "a", in: ach, peerIn: bch, closed: aclosed, peerClosed: bclosed}
	b := &pipeConn{name: "b", in: bch, peerIn: ach, closed: bclosed, peerClosed: aclosed}
	return a, b
}

// ReadFrame implements transport.FrameConn.
func (p *pipeConn) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case <-p.closed:
		return nil, fmt.Errorf("pipe %s read: %w", p.name, transport.ErrClosed)
	default:
	}
	select {
	case f, ok := <-p.in:
		if !ok {
			return nil, fmt.Errorf("pipe %s read: %w", p.name, transport.ErrClosed)
		}
		return f, nil
	case <-p.closed:
		return nil, fmt.Errorf("pipe %s read: %w", p.name, transport.ErrClosed)
	case <-ctx.Done():
		return nil, fmt.Errorf("pipe %s read: %w", p.name, ctx.Err())
	}
}

// WriteFrame implements transport.FrameConn.
func (p *pipeConn) WriteFrame(ctx context.Context, frame []byte) error {
	select {
	case <-p.closed:
		return fmt.Errorf("pipe %s write: %w", p.name, transport.ErrClosed)
	case <-p.peerClosed:
		return fmt.Errorf("pipe %s write: peer closed: %w", p.name, transport.ErrClosed)
	default:
	}
	select {
	case p.peerIn <- append([]byte(nil), frame...):
		return nil
	case <-p.closed:
		return fmt.Errorf("pipe %s write: %w", p.name, transport.ErrClosed)
	case <-p.peerClosed:
		return fmt.Errorf("pipe %s write: peer closed: %w", p.name, transport.ErrClosed)
	case <-ctx.Done():
		return fmt.Errorf("pipe %s write: %w", p.name, ctx.Err())
	}
}

// Close implements transport.FrameConn; idempotent.
func (p *pipeConn) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

// inject pushes a raw frame as if the peer had written it, for
// corruption tests.
func (p *pipeConn) inject(frame []byte) {
	p.in <- append([]byte(nil), frame...)
}

// recorderConn is a FrameConn that records everything written to it; used
// to capture ciphertexts for byte-exact vector comparisons.
type recorderConn struct {
	mu     sync.Mutex
	frames [][]byte
}

// ReadFrame implements transport.FrameConn by replaying recorded frames.
func (r *recorderConn) ReadFrame(context.Context) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.frames) == 0 {
		return nil, fmt.Errorf("recorder: no recorded frames")
	}
	f := r.frames[0]
	r.frames = r.frames[1:]
	return f, nil
}

// WriteFrame implements transport.FrameConn by recording the frame.
func (r *recorderConn) WriteFrame(_ context.Context, frame []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, append([]byte(nil), frame...))
	return nil
}

// Close implements transport.FrameConn.
func (r *recorderConn) Close() error { return nil }
