package transport

import (
	"math/rand/v2"
	"time"
)

// jitterFraction is the relative half-width of the jitter applied to backoff
// delays: each delay is multiplied by a factor drawn from [1-f, 1+f] where
// f is this value (±20%).
const jitterFraction = 0.20

// exponentialBackoff is the ReconnectPolicy returned by NewExponentialBackoff.
// It is stateless: the attempt number passed to Next carries all state, so
// the policy is safe for concurrent use.
type exponentialBackoff struct {
	base        time.Duration
	maxDelay    time.Duration
	maxAttempts int
}

var _ ReconnectPolicy = (*exponentialBackoff)(nil)

// NewExponentialBackoff returns a ReconnectPolicy with exponential delays:
// the delay after attempt N (1-based) is base shifted left by N-1, capped at
// maxDelay, with deterministic-range jitter of ±20% applied on top. Once
// attempt reaches maxAttempts, Next reports false and the caller gives up —
// that is, maxAttempts is the total number of connection attempts allowed.
//
// Jitter uses math/rand/v2. It exists to spread reconnect storms, not to
// defend against anything adversarial, so no cryptographic source is needed.
//
// The policy is stateless (state comes from the attempt parameter) and safe
// for concurrent use.
func NewExponentialBackoff(base, maxDelay time.Duration, maxAttempts int) ReconnectPolicy {
	return &exponentialBackoff{base: base, maxDelay: maxDelay, maxAttempts: maxAttempts}
}

// Next returns the delay before connection attempt attempt+1. attempt is
// 1-based (the first failure is attempt 1, yielding a delay of base ± 20%).
// It returns false once attempt reaches maxAttempts. Shift amounts beyond 62
// (and any shift that would overflow the duration) resolve to maxDelay
// instead of wrapping.
func (b *exponentialBackoff) Next(attempt int) (time.Duration, bool) {
	if attempt >= b.maxAttempts {
		return 0, false
	}

	shift := attempt - 1
	if shift < 0 {
		shift = 0
	}

	delay := b.base
	if shift > 0 {
		if shift > 62 {
			delay = b.maxDelay // shifting further would overflow int64
		} else if shifted := b.base << uint(shift); shifted > 0 {
			delay = shifted
		} else {
			delay = b.maxDelay // overflow wrapped the duration negative
		}
	}
	if delay > b.maxDelay {
		delay = b.maxDelay
	}
	return jitter(delay), true
}

// Reset does nothing. The policy is stateless — the attempt number passed to
// Next carries all backoff state — so there is nothing to reset; the method
// exists to satisfy the ReconnectPolicy interface.
func (b *exponentialBackoff) Reset() {}

// jitter multiplies d by a factor uniformly drawn from [1-±20%, 1+20%] using
// math/rand/v2 (global generator). Jitter of reconnect delays is not
// security-sensitive; see NewExponentialBackoff.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	factor := 1 - jitterFraction + 2*jitterFraction*rand.Float64() // [0.8, 1.2)
	return time.Duration(float64(d) * factor)
}
