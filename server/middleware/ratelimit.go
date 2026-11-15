package middleware

// Implementation notes:
//   - Token bucket per identity, refilled lazily from the injected clock; no
//     background goroutine, so nothing to stop or leak on shutdown.
//   - Idle buckets are swept at most once per IdleTTL/4 (amortised, on access)
//     and the map is hard-capped, so a hostile key space cannot grow memory
//     without bound. When the cap is reached the least recently used bucket is
//     dropped, which can hand an attacker a little extra slack but never
//     unbounded memory.
//   - Identities are hashed before they become map keys, so raw API keys are
//     never retained in the limiter's memory and never appear in responses.

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/angga0x3/whatscore/server/http/handlers"
)

// Defaults for NewRateLimiter. They are intentionally conservative for an API
// that drives a WhatsApp session: short bursts are fine, sustained hammering
// is not.
const (
	// DefaultRate is the sustained refill rate in tokens per second.
	DefaultRate = 10.0
	// DefaultBurst is the bucket depth: the largest instantaneous burst.
	DefaultBurst = 30
	// DefaultIdleTTL is how long an untouched bucket is kept before eviction.
	DefaultIdleTTL = 5 * time.Minute
	// DefaultMaxBuckets bounds the number of identities tracked at once.
	DefaultMaxBuckets = 4096
)

// Standard rate-limit header names (RFC 6585 Retry-After plus the de-facto
// X-RateLimit-* family).
//
// X-RateLimit-Reset is emitted as delta-seconds until the next token — the same
// value as Retry-After — rather than an absolute epoch timestamp. Delta seconds
// need no clock agreement between server and client and cannot leak the
// process's wall clock.
const (
	HeaderRateLimitLimit     = "X-RateLimit-Limit"
	HeaderRateLimitRemaining = "X-RateLimit-Remaining"
	HeaderRateLimitReset     = "X-RateLimit-Reset"
	HeaderRetryAfter         = "Retry-After"
)

// CodeRateLimited is the error code used in the standard error envelope when a
// request is throttled.
const CodeRateLimited = "rate_limited"

// KeyFunc derives the rate-limit identity of a request. It must be cheap and
// stable for the same caller within a burst of requests.
type KeyFunc func(*http.Request) string

// Option customises a RateLimiter at construction time.
type Option func(*RateLimiterConfig)

// WithKeyFunc overrides the identity function, taking precedence over
// RateLimiterConfig.KeyFunc. A nil func is ignored.
func WithKeyFunc(kf KeyFunc) Option {
	return func(cfg *RateLimiterConfig) {
		if kf != nil {
			cfg.KeyFunc = kf
		}
	}
}

// RateLimiterConfig configures a RateLimiter. Zero values fall back to the
// Default* constants, so an empty config yields a usable limiter.
type RateLimiterConfig struct {
	// Rate is the sustained refill rate in tokens per second.
	Rate float64
	// Burst is the bucket depth (maximum instantaneous requests).
	Burst int
	// IdleTTL is how long an untouched identity is remembered.
	IdleTTL time.Duration
	// Now is the clock. Nil means time.Now; tests inject a fake.
	Now func() time.Time
	// KeyFunc derives the identity. Nil means DefaultKeyFunc.
	KeyFunc KeyFunc
	// MaxBuckets hard-caps tracked identities. Zero means DefaultMaxBuckets.
	MaxBuckets int
}

// Decision is the outcome of one rate-limit check.
type Decision struct {
	// Allowed is true when a token was consumed.
	Allowed bool
	// Limit is the configured burst, reported as X-RateLimit-Limit.
	Limit int
	// Remaining is the number of whole tokens left after this check.
	Remaining int
	// RetryAfter is the exact wait until the next token, only meaningful on
	// denial (it is zero when Allowed).
	RetryAfter time.Duration
}

// DeniedError is the typed denial returned by Allow. It carries the wait until
// the next token is available and knows how to render Retry-After.
type DeniedError struct {
	// RetryAfter is the exact (sub-second precision) wait until the next
	// token becomes available.
	RetryAfter time.Duration
}

// Error implements error. The message is constant apart from the delay; it
// never contains the rate-limit identity.
func (e *DeniedError) Error() string {
	return fmt.Sprintf("rate limit exceeded: retry after %s", e.RetryAfter.Round(time.Millisecond))
}

// RetryAfterSeconds renders the Retry-After header value: the wait rounded up
// to whole seconds, never below 1 (Retry-After: 0 invites hot-loop retries).
func (e *DeniedError) RetryAfterSeconds() int {
	return retryAfterSeconds(e.RetryAfter)
}

func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		return 1
	}
	return secs
}

// bucket is one identity's token bucket. last is the last refill instant and
// key is the map key, kept here so eviction can delete from the map too.
type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// RateLimiter is a concurrency-safe, bounded, per-process token-bucket limiter.
//
// It is deliberately process-local: WhatsCore ships as a single self-hosted
// binary, and adding Redis (or any shared store) to enforce a cross-instance
// budget would bring a new dependency, a new failure mode on the request path,
// and a data store holding rate-limit identities. The limiter therefore
// protects one process from a single noisy or hostile client, which is the
// threat this control targets. The documented limitation: with N instances
// behind a load balancer the effective limit is N × Burst, so deployments that
// need a global budget must route /api/v1 to one instance or front the API
// with a proxy enforcing its own quota (see technical-specification.md §9).
//
// A RateLimiter is safe for concurrent use and must be shared by all requests
// of a process; do not construct one per handler.
type RateLimiter struct {
	rate       float64
	burst      int
	idleTTL    time.Duration
	maxBuckets int
	sweepEvery time.Duration
	now        func() time.Time
	keyFunc    KeyFunc

	mu        sync.Mutex
	buckets   map[string]*list.Element
	lru       *list.List // front = most recently used
	nextSweep time.Time
}

// NewRateLimiter builds a limiter from cfg, filling zero fields with defaults.
// Options, if any, are applied last.
func NewRateLimiter(cfg RateLimiterConfig, opts ...Option) *RateLimiter {
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.Rate <= 0 || math.IsNaN(cfg.Rate) || math.IsInf(cfg.Rate, 0) {
		cfg.Rate = DefaultRate
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = DefaultIdleTTL
	}
	if cfg.MaxBuckets <= 0 {
		cfg.MaxBuckets = DefaultMaxBuckets
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = DefaultKeyFunc
	}

	sweepEvery := cfg.IdleTTL / 4
	if sweepEvery <= 0 {
		sweepEvery = cfg.IdleTTL
	}

	rl := &RateLimiter{
		rate:       cfg.Rate,
		burst:      cfg.Burst,
		idleTTL:    cfg.IdleTTL,
		maxBuckets: cfg.MaxBuckets,
		sweepEvery: sweepEvery,
		now:        cfg.Now,
		keyFunc:    cfg.KeyFunc,
		buckets:    make(map[string]*list.Element, 16),
		lru:        list.New(),
	}
	rl.nextSweep = rl.now().Add(sweepEvery)
	return rl
}

// DefaultKeyFunc identifies a caller by API key when one is presented, and by
// the connection's remote IP otherwise.
//
// X-Forwarded-For is deliberately ignored: it is attacker-controlled unless a
// trusted proxy rewrote it, and the router omits chi's RealIP for the same
// reason. Deployments behind a proxy that must attribute by client IP should
// supply their own KeyFunc after validating the forwarded chain.
//
// The API key is hashed into the identity, so the plaintext secret is not
// retained as a map key.
//
// Trade-off worth knowing: a caller that rotates the Authorization value
// obtains a fresh bucket, so this identity does not throttle per connection.
// That is fine once API-key authentication is wired ahead of the limiter
// (only valid keys reach it, and a valid key is the real identity). Until then
// treat the limiter as a courtesy limit for well-behaved clients, and pass
// WithKeyFunc with an IP-based identity if an unauthenticated deployment needs
// a hard per-connection cap.
func DefaultKeyFunc(r *http.Request) string {
	if key := apiKeyFromHeader(r); key != "" {
		sum := sha256.Sum256([]byte(key))
		return "key:" + hex.EncodeToString(sum[:])
	}
	return "ip:" + clientIP(r)
}

// apiKeyFromHeader extracts a bearer token from Authorization, accepting both
// "Bearer <token>" and a bare token value.
func apiKeyFromHeader(r *http.Request) string {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return ""
	}
	if len(raw) >= 7 && strings.EqualFold(raw[:7], "bearer ") {
		return strings.TrimSpace(raw[7:])
	}
	return raw
}

// clientIP returns the host part of RemoteAddr. It never consults proxy
// headers. If RemoteAddr has no port the value is used verbatim.
func clientIP(r *http.Request) string {
	addr := strings.TrimSpace(r.RemoteAddr)
	if addr == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// Key returns the identity the limiter would use for r.
func (rl *RateLimiter) Key(r *http.Request) string {
	if rl == nil {
		return ""
	}
	key := rl.keyFunc(r)
	if key == "" {
		key = DefaultKeyFunc(r)
	}
	return key
}

// Allow consumes one token for key. On denial the returned Decision is not
// allowed and the error carries the wait until the next token.
func (rl *RateLimiter) Allow(key string) (Decision, *DeniedError) {
	if rl == nil {
		return Decision{Allowed: true}, nil
	}
	if key == "" {
		key = "unknown"
	}
	return rl.allowAt(key, rl.now())
}

func (rl *RateLimiter) allowAt(key string, now time.Time) (Decision, *DeniedError) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.sweepIfDueLocked(now)

	el, ok := rl.buckets[key]
	if !ok {
		rl.makeRoomLocked()
		el = rl.lru.PushFront(&bucket{key: key, tokens: float64(rl.burst), last: now})
		rl.buckets[key] = el
	}

	b := el.Value.(*bucket)
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = math.Min(float64(rl.burst), b.tokens+elapsed.Seconds()*rl.rate)
		b.last = now
	} else if elapsed < 0 {
		// Clock went backwards (fake clock in tests, or an NTP step): keep the
		// accumulated tokens and restart the refill window from "now".
		b.last = now
	}
	rl.lru.MoveToFront(el)

	dec := Decision{Limit: rl.burst}
	if b.tokens >= 1 {
		b.tokens--
		dec.Allowed = true
		dec.Remaining = int(math.Floor(b.tokens))
		if dec.Remaining < 0 {
			dec.Remaining = 0
		}
		return dec, nil
	}

	wait := (1 - b.tokens) / rl.rate * float64(time.Second)
	if wait < 0 {
		wait = 0
	}
	dec.RetryAfter = time.Duration(math.Ceil(wait))
	return dec, &DeniedError{RetryAfter: dec.RetryAfter}
}

// sweepIfDueLocked evicts buckets idle for longer than idleTTL, at most once
// per sweepEvery so the cost stays amortised. Callers hold rl.mu.
func (rl *RateLimiter) sweepIfDueLocked(now time.Time) {
	if now.Before(rl.nextSweep) {
		return
	}
	for el := rl.lru.Back(); el != nil; {
		prev := el.Prev()
		if now.Sub(el.Value.(*bucket).last) >= rl.idleTTL {
			rl.removeLocked(el)
		}
		el = prev
	}
	rl.nextSweep = now.Add(rl.sweepEvery)
}

// makeRoomLocked drops least-recently-used buckets until a new identity fits.
// Callers hold rl.mu.
func (rl *RateLimiter) makeRoomLocked() {
	for len(rl.buckets) >= rl.maxBuckets {
		back := rl.lru.Back()
		if back == nil {
			return
		}
		rl.removeLocked(back)
	}
}

func (rl *RateLimiter) removeLocked(el *list.Element) {
	if b, ok := el.Value.(*bucket); ok {
		delete(rl.buckets, b.key)
	}
	rl.lru.Remove(el)
}

// Middleware returns the chi-compatible middleware. On allow it sets
// X-RateLimit-Limit and X-RateLimit-Remaining and continues; on deny it
// responds 429 with Retry-After, X-RateLimit-Reset and the standard error
// envelope (code "rate_limited"). The identity never appears in the response.
//
// A nil *RateLimiter yields a pass-through middleware; the router treats a nil
// Deps.RateLimit as "disabled" before calling here.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if rl == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dec, denied := rl.Allow(rl.Key(r))

			h := w.Header()
			h.Set(HeaderRateLimitLimit, strconv.Itoa(dec.Limit))
			if denied != nil {
				secs := denied.RetryAfterSeconds()
				h.Set(HeaderRateLimitRemaining, "0")
				h.Set(HeaderRetryAfter, strconv.Itoa(secs))
				h.Set(HeaderRateLimitReset, strconv.Itoa(secs))
				handlers.WriteError(w, http.StatusTooManyRequests, CodeRateLimited,
					"request rate limit exceeded; retry after "+strconv.Itoa(secs)+" seconds")
				return
			}

			h.Set(HeaderRateLimitRemaining, strconv.Itoa(dec.Remaining))
			next.ServeHTTP(w, r)
		})
	}
}
