package middleware

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock for deterministic refill tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestLimiter builds a limiter with a fake clock and the given config.
// Config zero fields are filled by NewRateLimiter, which is what we want.
func newTestLimiter(cfg RateLimiterConfig) (*RateLimiter, *fakeClock) {
	clock := newFakeClock()
	cfg.Now = clock.Now
	return NewRateLimiter(cfg), clock
}

func requestWith(remoteAddr, apiKey, forwardedFor string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	r.RemoteAddr = remoteAddr
	if apiKey != "" {
		r.Header.Set("Authorization", apiKey)
	}
	if forwardedFor != "" {
		r.Header.Set("X-Forwarded-For", forwardedFor)
	}
	return r
}

// size reports how many identities are currently tracked.
func (rl *RateLimiter) size() int {
	if rl == nil {
		return 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// hasBucket reports whether key is currently tracked.
func (rl *RateLimiter) hasBucket(key string) bool {
	if rl == nil {
		return false
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	_, ok := rl.buckets[key]
	return ok
}

func TestAllowDenyTable(t *testing.T) {
	limiter, clock := newTestLimiter(RateLimiterConfig{Rate: 1, Burst: 3, IdleTTL: time.Minute})

	tests := []struct {
		name          string
		advance       time.Duration
		wantAllowed   bool
		wantRemaining int
		wantRetrySecs int
	}{
		{name: "first token", wantAllowed: true, wantRemaining: 2},
		{name: "second token", wantAllowed: true, wantRemaining: 1},
		{name: "third token", wantAllowed: true, wantRemaining: 0},
		{name: "exhausted", wantAllowed: false, wantRetrySecs: 1},
		{name: "half a token is not enough", advance: 500 * time.Millisecond, wantAllowed: false, wantRetrySecs: 1},
		{name: "one token refilled", advance: 500 * time.Millisecond, wantAllowed: true, wantRemaining: 0},
		{name: "exhausted again", wantAllowed: false, wantRetrySecs: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clock.Advance(tc.advance)
			dec, denied := limiter.Allow("client")
			if dec.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, want %v (decision %+v)", dec.Allowed, tc.wantAllowed, dec)
			}
			if dec.Allowed == (denied != nil) {
				t.Fatalf("decision/error disagree: allowed=%v err=%v", dec.Allowed, denied)
			}
			if dec.Allowed {
				if dec.Remaining != tc.wantRemaining {
					t.Errorf("Remaining = %d, want %d", dec.Remaining, tc.wantRemaining)
				}
				if dec.Limit != 3 {
					t.Errorf("Limit = %d, want 3", dec.Limit)
				}
				return
			}
			if got := denied.RetryAfterSeconds(); got != tc.wantRetrySecs {
				t.Errorf("RetryAfterSeconds() = %d, want %d", got, tc.wantRetrySecs)
			}
		})
	}
}

func TestBurstExhaustionThenRefill(t *testing.T) {
	limiter, clock := newTestLimiter(RateLimiterConfig{Rate: 4, Burst: 5, IdleTTL: time.Minute})

	for i := 0; i < 5; i++ {
		if dec, denied := limiter.Allow("k"); !dec.Allowed || denied != nil {
			t.Fatalf("request %d: denied before burst exhausted: %+v", i, dec)
		}
	}
	if dec, denied := limiter.Allow("k"); dec.Allowed || denied == nil {
		t.Fatal("sixth request allowed after burst exhausted")
	}

	// Rate 4/s: 250ms is exactly one token.
	clock.Advance(250 * time.Millisecond)
	dec, denied := limiter.Allow("k")
	if !dec.Allowed || denied != nil {
		t.Fatalf("request after one refill interval denied: %+v", dec)
	}
	if dec.Remaining != 0 {
		t.Errorf("Remaining = %d, want 0", dec.Remaining)
	}

	// A full idle period restores the whole burst, never more.
	clock.Advance(time.Minute)
	dec, _ = limiter.Allow("k")
	if !dec.Allowed || dec.Remaining != 4 {
		t.Errorf("after long idle: Allowed=%v Remaining=%d, want true/4", dec.Allowed, dec.Remaining)
	}
}

func TestRetryAfterCeilsAndHasMinimumOne(t *testing.T) {
	// Rate 1/s, burst 1: a denial right after consumption waits a full second.
	limiter, clock := newTestLimiter(RateLimiterConfig{Rate: 1, Burst: 1, IdleTTL: time.Minute})
	_, _ = limiter.Allow("k")

	_, denied := limiter.Allow("k")
	if denied == nil {
		t.Fatal("expected denial")
	}
	if got := denied.RetryAfterSeconds(); got != 1 {
		t.Errorf("RetryAfterSeconds() = %d, want 1", got)
	}

	// Rate 0.5/s means a 2s wait: ceil must round up, not down.
	slow, _ := newTestLimiter(RateLimiterConfig{Rate: 0.5, Burst: 1, IdleTTL: time.Minute})
	_, _ = slow.Allow("k")
	_, denied = slow.Allow("k")
	if got := denied.RetryAfterSeconds(); got != 2 {
		t.Errorf("RetryAfterSeconds() = %d, want 2", got)
	}

	// Partially refilled buckets round up fractional seconds.
	clock.Advance(900 * time.Millisecond)
	_, denied = limiter.Allow("k")
	if got := denied.RetryAfterSeconds(); got != 1 {
		t.Errorf("RetryAfterSeconds() after 900ms = %d, want 1 (ceil)", got)
	}

	if got := retryAfterSeconds(0); got != 1 {
		t.Errorf("retryAfterSeconds(0) = %d, want 1", got)
	}
	if got := retryAfterSeconds(-time.Second); got != 1 {
		t.Errorf("retryAfterSeconds(-1s) = %d, want 1", got)
	}
	if got := retryAfterSeconds(1500 * time.Millisecond); got != 2 {
		t.Errorf("retryAfterSeconds(1.5s) = %d, want 2", got)
	}
	if got := retryAfterSeconds(time.Second); got != 1 {
		t.Errorf("retryAfterSeconds(1s) = %d, want 1", got)
	}
}

func TestPerKeyIsolation(t *testing.T) {
	limiter, _ := newTestLimiter(RateLimiterConfig{Rate: 1, Burst: 2, IdleTTL: time.Minute})

	for i := 0; i < 2; i++ {
		if dec, _ := limiter.Allow("alpha"); !dec.Allowed {
			t.Fatalf("alpha request %d denied", i)
		}
	}
	if dec, _ := limiter.Allow("alpha"); dec.Allowed {
		t.Fatal("alpha allowed beyond burst")
	}
	// A different identity starts with a full bucket.
	if dec, denied := limiter.Allow("beta"); !dec.Allowed || denied != nil {
		t.Fatalf("beta denied: %+v", dec)
	}
	// And consuming beta did not replenish alpha.
	if dec, _ := limiter.Allow("alpha"); dec.Allowed {
		t.Fatal("alpha replenished by unrelated key activity")
	}
	if got := limiter.size(); got != 2 {
		t.Errorf("tracked buckets = %d, want 2", got)
	}
}

func TestDefaultKeyFunc(t *testing.T) {
	tests := []struct {
		name        string
		apiKey      string
		remoteAddr  string
		forwardedTo string
		wantPrefix  string
		wantKey     string // exact value when no hashing is involved
	}{
		{
			name:        "api key preferred over ip",
			apiKey:      "Bearer wc_live_abc",
			remoteAddr:  "203.0.113.7:5555",
			forwardedTo: "10.0.0.1",
			wantPrefix:  "key:",
		},
		{
			name:       "bare api key accepted",
			apiKey:     "wc_live_abc",
			remoteAddr: "203.0.113.7:5555",
			wantPrefix: "key:",
		},
		{
			name:        "ip fallback strips port",
			remoteAddr:  "203.0.113.7:5555",
			forwardedTo: "10.0.0.1",
			wantKey:     "ip:203.0.113.7",
		},
		{
			name:        "x-forwarded-for ignored",
			remoteAddr:  "203.0.113.7:5555",
			forwardedTo: "198.51.100.200, 10.0.0.1",
			wantKey:     "ip:203.0.113.7",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "198.51.100.9",
			wantKey:    "ip:198.51.100.9",
		},
		{
			name:       "empty remote addr",
			remoteAddr: "",
			wantKey:    "ip:unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := requestWith(tc.remoteAddr, tc.apiKey, tc.forwardedTo)
			got := DefaultKeyFunc(r)
			if tc.wantKey != "" && got != tc.wantKey {
				t.Fatalf("DefaultKeyFunc() = %q, want %q", got, tc.wantKey)
			}
			if tc.wantPrefix != "" && !strings.HasPrefix(got, tc.wantPrefix) {
				t.Fatalf("DefaultKeyFunc() = %q, want prefix %q", got, tc.wantPrefix)
			}
			if tc.apiKey != "" && got == "ip:"+clientIP(r) {
				t.Error("API key was not preferred over the client IP")
			}
			if tc.forwardedTo != "" && strings.Contains(got, "198.51.100.200") {
				t.Error("X-Forwarded-For influenced the identity")
			}
		})
	}
}

func TestDefaultKeyFuncNeverLeaksRawAPIKey(t *testing.T) {
	r := requestWith("203.0.113.7:5555", "Bearer wc_live_supersecret", "")
	key := DefaultKeyFunc(r)
	if key == "wc_live_supersecret" {
		t.Fatal("key is the raw API key")
	}
	if got := len(key); got != len("key:")+64 {
		t.Errorf("key length = %d, want %d (sha-256 hex)", got, len("key:")+64)
	}
	if want := DefaultKeyFunc(requestWith("203.0.113.7:5555", "Bearer wc_live_supersecret", "")); key != want {
		t.Error("same API key produced different identities")
	}
	if same := DefaultKeyFunc(requestWith("198.51.100.1:1", "Bearer wc_live_supersecret", "")); same != key {
		t.Error("identity depends on RemoteAddr even though an API key was present")
	}
}

func TestWithKeyFuncOption(t *testing.T) {
	clock := newFakeClock()
	limiter := NewRateLimiter(RateLimiterConfig{
		Rate: 1, Burst: 1, IdleTTL: time.Minute, Now: clock.Now,
		KeyFunc: DefaultKeyFunc,
	}, WithKeyFunc(func(*http.Request) string { return "tenant-42" }))

	if got := limiter.Key(requestWith("203.0.113.7:5555", "Bearer wc_live_x", "")); got != "tenant-42" {
		t.Fatalf("Key() = %q, want tenant-42 (option did not override config)", got)
	}

	// Nil options and nil funcs must not panic or clobber the default.
	limiter = NewRateLimiter(RateLimiterConfig{Rate: 1, Burst: 1, Now: clock.Now}, nil)
	if got := limiter.Key(requestWith("203.0.113.7:5555", "", "")); got != "ip:203.0.113.7" {
		t.Fatalf("Key() = %q, want default IP identity", got)
	}
	limiter = NewRateLimiter(RateLimiterConfig{Rate: 1, Burst: 1, Now: clock.Now}, WithKeyFunc(nil))
	if got := limiter.Key(requestWith("203.0.113.7:5555", "", "")); got != "ip:203.0.113.7" {
		t.Fatalf("Key() = %q after WithKeyFunc(nil), want default IP identity", got)
	}
}

func TestIdleEviction(t *testing.T) {
	limiter, clock := newTestLimiter(RateLimiterConfig{
		Rate: 1, Burst: 5, IdleTTL: 10 * time.Second,
	})

	_, _ = limiter.Allow("stale")
	if !limiter.hasBucket("stale") {
		t.Fatal("bucket missing right after first use")
	}

	// Sweeps run at most every IdleTTL/4, so advance past both the TTL and the
	// next sweep deadline, touching a live key to trigger the sweep.
	clock.Advance(10 * time.Second)
	_, _ = limiter.Allow("fresh")
	clock.Advance(3 * time.Second) // > IdleTTL/4 since last sweep, still < TTL for "fresh"
	_, _ = limiter.Allow("fresh")

	if limiter.hasBucket("stale") {
		t.Error("idle bucket was not evicted")
	}
	if !limiter.hasBucket("fresh") {
		t.Error("active bucket was evicted")
	}
	if got := limiter.size(); got != 1 {
		t.Errorf("tracked buckets = %d, want 1", got)
	}

	// An evicted identity must come back with a full bucket, not its old state.
	dec, denied := limiter.Allow("stale")
	if !dec.Allowed || denied != nil || dec.Remaining != 4 {
		t.Errorf("revived bucket: %+v, want full burst", dec)
	}
}

func TestBoundedMapUnderManyKeys(t *testing.T) {
	const maxBuckets = 128
	limiter, _ := newTestLimiter(RateLimiterConfig{
		Rate: 1, Burst: 1, IdleTTL: time.Hour, MaxBuckets: maxBuckets,
	})

	for i := 0; i < 10_000; i++ {
		_, _ = limiter.Allow(fmt.Sprintf("hostile-key-%d", i))
		size := limiter.size()
		if size > maxBuckets {
			t.Fatalf("bucket map grew to %d, cap is %d", size, maxBuckets)
		}
		if n := limiter.lru.Len(); n != size {
			t.Fatalf("list/map desync: list=%d map=%d", n, size)
		}
	}
	if got := limiter.size(); got == 0 {
		t.Fatal("limiter forgot every key; cap logic dropped too much")
	}
}

func TestMiddlewareHeadersOnAllowAndDeny(t *testing.T) {
	limiter, clock := newTestLimiter(RateLimiterConfig{Rate: 1, Burst: 2, IdleTTL: time.Minute})
	handler := limiter.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	call := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, requestWith("203.0.113.7:5555", "Bearer wc_live_test", ""))
		return rec
	}

	first := call()
	if first.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", first.Code)
	}
	if got := first.Header().Get(HeaderRateLimitLimit); got != "2" {
		t.Errorf("%s = %q, want 2", HeaderRateLimitLimit, got)
	}
	if got := first.Header().Get(HeaderRateLimitRemaining); got != "1" {
		t.Errorf("%s = %q, want 1", HeaderRateLimitRemaining, got)
	}
	if got := first.Header().Get(HeaderRetryAfter); got != "" {
		t.Errorf("%s = %q on an allowed request, want empty", HeaderRetryAfter, got)
	}
	if got := first.Header().Get(HeaderRateLimitReset); got != "" {
		t.Errorf("%s = %q on an allowed request, want empty", HeaderRateLimitReset, got)
	}

	second := call()
	if second.Code != http.StatusOK || second.Header().Get(HeaderRateLimitRemaining) != "0" {
		t.Fatalf("second request: status=%d remaining=%q", second.Code, second.Header().Get(HeaderRateLimitRemaining))
	}

	denied := call()
	if denied.Code != http.StatusTooManyRequests {
		t.Fatalf("third request status = %d, want 429", denied.Code)
	}
	if got := denied.Header().Get(HeaderRetryAfter); got != "1" {
		t.Errorf("%s = %q, want 1", HeaderRetryAfter, got)
	}
	if got := denied.Header().Get(HeaderRateLimitReset); got != "1" {
		t.Errorf("%s = %q, want 1", HeaderRateLimitReset, got)
	}
	if got := denied.Header().Get(HeaderRateLimitRemaining); got != "0" {
		t.Errorf("%s = %q, want 0", HeaderRateLimitRemaining, got)
	}
	if got := denied.Header().Get(HeaderRateLimitLimit); got != "2" {
		t.Errorf("%s = %q, want 2", HeaderRateLimitLimit, got)
	}

	// The identity (or the API key inside it) must never be echoed back.
	for _, h := range []string{HeaderRateLimitLimit, HeaderRateLimitRemaining, HeaderRateLimitReset, HeaderRetryAfter} {
		if v := denied.Header().Get(h); len(v) > 3 {
			t.Errorf("header %s = %q looks like a leaked identity", h, v)
		}
	}
	if body := denied.Body.String(); strings.Contains(body, "203.0.113.7") ||
		strings.Contains(body, "wc_live_test") || strings.Contains(body, "Bearer") {
		t.Errorf("response body leaks the identity: %s", body)
	}

	// After one refill interval the same client is served again.
	clock.Advance(time.Second)
	if rec := call(); rec.Code != http.StatusOK {
		t.Fatalf("request after refill status = %d, want 200", rec.Code)
	}
}

func TestMiddlewareErrorEnvelopeMatchesAPI(t *testing.T) {
	limiter, _ := newTestLimiter(RateLimiterConfig{Rate: 0.1, Burst: 1, IdleTTL: time.Minute})
	handler := limiter.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), requestWith("203.0.113.7:5555", "", ""))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWith("203.0.113.7:5555", "", ""))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if body.Error.Code != CodeRateLimited {
		t.Errorf("error.code = %q, want %q", body.Error.Code, CodeRateLimited)
	}
	if body.Error.Message == "" {
		t.Error("error.message is empty")
	}
	// Only the two documented envelope keys, no extra fields.
	var raw map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body is not a JSON object: %v", err)
	}
	if len(raw) != 1 {
		t.Errorf("envelope has %d top-level keys, want 1", len(raw))
	}
	if got := len(raw["error"]); got != 2 {
		t.Errorf("error object has %d keys, want 2 (code, message)", got)
	}
	// Retry-After for rate 0.1/s is 10s.
	if got := rec.Header().Get(HeaderRetryAfter); got != "10" {
		t.Errorf("%s = %q, want 10", HeaderRetryAfter, got)
	}
}

func TestMiddlewareNilLimiterIsPassThrough(t *testing.T) {
	var limiter *RateLimiter
	called := false
	handler := limiter.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWith("203.0.113.7:5555", "", ""))
	if !called || rec.Code != http.StatusTeapot {
		t.Fatalf("nil limiter blocked the request: called=%v status=%d", called, rec.Code)
	}
	if rec.Header().Get(HeaderRateLimitLimit) != "" {
		t.Error("nil limiter wrote rate-limit headers")
	}
}

func TestDeniedErrorShape(t *testing.T) {
	limiter, _ := newTestLimiter(RateLimiterConfig{Rate: 1, Burst: 1, IdleTTL: time.Minute})
	_, _ = limiter.Allow("k")
	_, denied := limiter.Allow("k")
	if denied == nil {
		t.Fatal("expected denial")
	}
	msg := denied.Error()
	if !strings.Contains(msg, "rate limit exceeded") {
		t.Errorf("Error() = %q, want it to mention the rate limit", msg)
	}
	if strings.Contains(msg, "identity") {
		t.Errorf("Error() = %q leaks the identity", msg)
	}

	// Allow on a nil limiter is a pass-through, never a panic.
	var nilLimiter *RateLimiter
	if dec, err := nilLimiter.Allow("anything"); !dec.Allowed || err != nil {
		t.Errorf("nil limiter: %+v, %v", dec, err)
	}
	if key := nilLimiter.Key(requestWith("203.0.113.7:5555", "", "")); key != "" {
		t.Errorf("nil limiter Key() = %q, want empty", key)
	}

	// A backwards clock must not add tokens.
	clocked, clock := newTestLimiter(RateLimiterConfig{Rate: 1, Burst: 2, IdleTTL: time.Minute})
	_, _ = clocked.Allow("k")
	clock.Advance(-time.Hour)
	dec, _ := clocked.Allow("k")
	if dec.Remaining != 0 {
		t.Errorf("backwards clock granted tokens: Remaining = %d, want 0", dec.Remaining)
	}
	if dec.Allowed == false {
		t.Error("backwards clock wrongly denied a request that had one token")
	}

	// An empty identity is coerced to a stable placeholder rather than a
	// unique bucket per request.
	empty, _ := newTestLimiter(RateLimiterConfig{Rate: 1, Burst: 1, IdleTTL: time.Minute})
	_, _ = empty.Allow("")
	if _, denied := empty.Allow(""); denied == nil {
		t.Error("empty identities were not bucketed together")
	}
}

func TestDefaultConfigFillsZeroValues(t *testing.T) {
	limiter := NewRateLimiter(RateLimiterConfig{})
	if limiter.rate != DefaultRate || limiter.burst != DefaultBurst ||
		limiter.idleTTL != DefaultIdleTTL || limiter.maxBuckets != DefaultMaxBuckets {
		t.Fatalf("defaults not applied: rate=%v burst=%d ttl=%v max=%d",
			limiter.rate, limiter.burst, limiter.idleTTL, limiter.maxBuckets)
	}
	if limiter.now == nil || limiter.keyFunc == nil {
		t.Fatal("nil clock or key func")
	}
	if limiter.sweepEvery <= 0 || limiter.sweepEvery >= limiter.idleTTL {
		t.Errorf("sweepEvery = %v, want in (0, IdleTTL)", limiter.sweepEvery)
	}

	// Nonsense rates fall back instead of producing an unusable limiter.
	for _, cfg := range []RateLimiterConfig{
		{Rate: -1},
		{Rate: math.NaN()},
		{Rate: math.Inf(1)},
		{Rate: 1, Burst: -5},
	} {
		l := NewRateLimiter(cfg)
		if l.rate <= 0 || l.burst <= 0 || l.idleTTL <= 0 || l.maxBuckets <= 0 {
			t.Errorf("cfg %+v not normalised: rate=%v burst=%d ttl=%v max=%d",
				cfg, l.rate, l.burst, l.idleTTL, l.maxBuckets)
		}
		if cfg.Rate > 0 && !math.IsInf(cfg.Rate, 0) && l.rate != cfg.Rate {
			t.Errorf("cfg %+v: rate = %v, want the explicit positive rate kept", cfg, l.rate)
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	const burst = 50
	limiter, _ := newTestLimiter(RateLimiterConfig{Rate: 1, Burst: burst, IdleTTL: time.Minute})

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		allowed  int
		denied   int
		remained = map[int]bool{}
	)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dec, err := limiter.Allow("shared")
			mu.Lock()
			if dec.Allowed {
				allowed++
				remained[dec.Remaining] = true
			} else {
				denied++
			}
			mu.Unlock()
			if dec.Allowed == (err != nil) {
				t.Errorf("decision/error disagree under concurrency: %+v %v", dec, err)
			}
		}()
	}
	wg.Wait()

	if allowed != burst {
		t.Errorf("allowed = %d concurrent requests, want exactly %d (burst)", allowed, burst)
	}
	if denied != 200-burst {
		t.Errorf("denied = %d, want %d", denied, 200-burst)
	}
	if len(remained) != burst {
		t.Errorf("distinct remaining values = %d, want %d (one per allowed token)", len(remained), burst)
	}
	if !remained[0] {
		t.Error("no request observed Remaining == 0")
	}
}

func BenchmarkRateLimiterAllow(b *testing.B) {
	limiter := NewRateLimiter(RateLimiterConfig{Rate: 1e9, Burst: 1 << 30})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := limiter.Allow("628123@s.whatsapp.net"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRateLimiterManyKeys(b *testing.B) {
	limiter := NewRateLimiter(RateLimiterConfig{Rate: 1e9, Burst: 1 << 30, MaxBuckets: 4096})
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := limiter.Allow(keys[i%len(keys)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRateLimiterDenied(b *testing.B) {
	limiter := NewRateLimiter(RateLimiterConfig{Rate: 0.0001, Burst: 1})
	_, _ = limiter.Allow("k")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := limiter.Allow("k"); err == nil {
			b.Fatal("expected denial")
		}
	}
}
