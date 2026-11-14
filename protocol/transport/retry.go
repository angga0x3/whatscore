package transport

import (
	"context"
	"fmt"
	"time"
)

// ConnectWithRetry dials endpoint through dialer, retrying with backoff until
// the connection succeeds, the policy gives up, or ctx is done. It returns
// the established FrameConn ready for frame I/O (PF-003 framing when dialer
// is a WebSocketDialer; PF-002 endpoint values when endpoint is
// DefaultEndpoint).
//
// Loop semantics:
//
//   - Each iteration attempts one Dial. On success, policy.Reset is called
//     and the connection is returned.
//   - On failure, policy.Next(attempt) decides the next move (attempt is
//     1-based on the failed dial). If it reports false, ConnectWithRetry
//     returns the last dial error wrapped with the attempt count; the
//     underlying error stays accessible via errors.Is/errors.As.
//   - Otherwise onRetry (when non-nil) is invoked with the attempt number,
//     the delay, and the error, and the goroutine sleeps the delay
//     ctx-aware: cancellation during the sleep returns an error wrapping
//     ctx.Err() instead of a connection.
//   - A context that is already cancelled before a dial is not dialled at
//     all; the returned error wraps ctx.Err().
func ConnectWithRetry(
	ctx context.Context,
	dialer Dialer,
	endpoint Endpoint,
	policy ReconnectPolicy,
	onRetry func(attempt int, delay time.Duration, err error),
) (FrameConn, error) {
	var lastErr error
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("transport: connect cancelled: %w", err)
		}

		fc, err := dialer.Dial(ctx, endpoint)
		if err == nil {
			policy.Reset()
			return fc, nil
		}
		lastErr = err

		delay, ok := policy.Next(attempt)
		if !ok {
			return nil, fmt.Errorf(
				"transport: connect failed after %d attempt(s): %w", attempt, lastErr)
		}

		if onRetry != nil {
			onRetry(attempt, delay, err)
		}

		if !sleepContext(ctx, delay) {
			return nil, fmt.Errorf(
				"transport: connect cancelled while waiting to retry: %w", ctx.Err())
		}
	}
}

// sleepContext waits for d or ctx.Done, whichever comes first. It reports
// whether the full delay elapsed (true) or the context ended first (false).
func sleepContext(ctx context.Context, d time.Duration) bool {
	if err := ctx.Err(); err != nil {
		return false
	}
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
