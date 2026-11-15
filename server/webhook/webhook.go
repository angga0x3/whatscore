// Package webhook implements outbound webhook delivery for the REST adapter:
// HMAC-signed JSON envelopes, bounded exponential retries, and per-attempt
// delivery records. It is a transport concern only — it performs no
// persistence and owns no protocol logic.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Headers carried by every delivery. Receivers must verify HeaderSignature
// over the exact request body before trusting the payload.
const (
	HeaderSignature = "X-Whatscore-Signature"
	HeaderEvent     = "X-Whatscore-Event"
	HeaderDelivery  = "X-Whatscore-Delivery"
)

// Delivery defaults, matching the published contract: a 10 s timeout per
// attempt, at most 10 attempts, a 1 s → 1 min backoff, 256 KiB request bodies
// and 64 KiB of response body read.
const (
	DefaultTimeout          = 10 * time.Second
	DefaultMaxAttempts      = 10
	DefaultMaxBodyBytes     = 256 << 10
	DefaultMaxResponseBytes = 64 << 10
	DefaultBackoffBase      = time.Second
	DefaultBackoffMax       = time.Minute
)

// Sentinel errors. Callers match with errors.Is.
var (
	// ErrInvalidEndpoint is returned when the target is not an absolute
	// http(s) URL with a non-empty host.
	ErrInvalidEndpoint = errors.New("webhook: invalid endpoint URL")
	// ErrInvalidEvent is returned when an envelope field is missing or its
	// data is not a JSON object.
	ErrInvalidEvent = errors.New("webhook: invalid event")
	// ErrTooLarge is returned when the encoded envelope exceeds the body
	// limit. No request is sent in that case.
	ErrTooLarge = errors.New("webhook: payload too large")
	// ErrRejected is returned when the final attempt was answered with a
	// non-2xx status. Per-attempt detail lives in the delivery records.
	ErrRejected = errors.New("webhook: endpoint rejected delivery")
)

// Event is the webhook envelope defined by the API contract (Event schema):
// id, event, timestamp, session_id, data.
type Event struct {
	ID        string          `json:"id"`
	Event     string          `json:"event"`
	Timestamp time.Time       `json:"timestamp"`
	SessionID string          `json:"session_id"`
	Data      json.RawMessage `json:"data"`
}

// Delivery is one delivery attempt. The REST layer maps these records onto the
// WebhookDelivery schema (status, attempts, response_code, last_error), so the
// field names here are internal and carry no JSON contract. All attempts of a
// single Deliver call share ID (also sent as HeaderDelivery) and EndpointID.
type Delivery struct {
	ID          string
	EndpointID  string
	EventID     string
	Attempt     int
	StatusCode  int
	Error       string
	DeliveredAt time.Time
	Duration    time.Duration
}

// Sign returns the lowercase hex HMAC-SHA256 of body under secret. This is the
// value of HeaderSignature, with no prefix.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether signature is a valid Sign(secret, body). The
// comparison is constant time; malformed signatures never panic.
func Verify(secret, body []byte, signature string) bool {
	want := Sign(secret, body)
	return subtle.ConstantTimeCompare([]byte(want), []byte(signature)) == 1
}

// ExponentialBackoff returns a delay function for retry attempt n (1-based):
// base << (n-1), capped at maxDelay. Attempts below 1 use base. The result is
// deterministic; callers that need jitter must add it themselves.
func ExponentialBackoff(base, maxDelay time.Duration) func(attempt int) time.Duration {
	if base < 0 {
		base = 0
	}
	if maxDelay < base {
		maxDelay = base
	}
	return func(attempt int) time.Duration {
		if attempt < 1 {
			attempt = 1
		}
		shift := attempt - 1
		// The comparison avoids the overflow that a bare left shift of a
		// large base would produce.
		if shift > 62 || base > maxDelay>>uint(shift) {
			return maxDelay
		}
		return base << uint(shift)
	}
}

// Config configures a Sender. Zero values select the defaults above.
type Config struct {
	// Client is the HTTP client used for deliveries. It is shallow-copied, so
	// the caller's value is never mutated; the copy drops the cookie jar and
	// forces the no-redirect policy described by the security spec.
	Client *http.Client
	// Timeout bounds each attempt, not the whole retry sequence.
	Timeout time.Duration
	// MaxAttempts is the total number of attempts, including the first.
	MaxAttempts int
	// MaxBodyBytes caps the encoded envelope; larger events fail with
	// ErrTooLarge before any request is sent.
	MaxBodyBytes int
	// MaxResponseBytes caps how much of a response body is read. Excess is
	// discarded rather than treated as an error.
	MaxResponseBytes int
	// Backoff returns the pause before the given attempt. nil selects
	// ExponentialBackoff(DefaultBackoffBase, DefaultBackoffMax).
	Backoff func(attempt int) time.Duration
	// EndpointID, when set, is stamped on every delivery record so a worker can
	// persist them against the endpoint.
	EndpointID string
}

// Sender delivers events to HTTP endpoints. It is immutable after New and safe
// for concurrent use.
type Sender struct {
	client           *http.Client
	timeout          time.Duration
	maxAttempts      int
	maxBodyBytes     int
	maxResponseBytes int
	backoff          func(attempt int) time.Duration
	endpointID       string
}

// New returns a Sender with cfg applied over the defaults. It takes ownership
// of redirect policy: a webhook target can never bounce the request to
// another host (technical specification §9), even when cfg.Client follows
// redirects by default.
func New(cfg Config) *Sender {
	s := &Sender{
		timeout:          cfg.Timeout,
		maxAttempts:      cfg.MaxAttempts,
		maxBodyBytes:     cfg.MaxBodyBytes,
		maxResponseBytes: cfg.MaxResponseBytes,
		backoff:          cfg.Backoff,
		endpointID:       cfg.EndpointID,
	}
	if s.timeout <= 0 {
		s.timeout = DefaultTimeout
	}
	if s.maxAttempts <= 0 {
		s.maxAttempts = DefaultMaxAttempts
	}
	if s.maxBodyBytes <= 0 {
		s.maxBodyBytes = DefaultMaxBodyBytes
	}
	if s.maxResponseBytes <= 0 {
		s.maxResponseBytes = DefaultMaxResponseBytes
	}
	if s.backoff == nil {
		s.backoff = ExponentialBackoff(DefaultBackoffBase, DefaultBackoffMax)
	}

	client := cfg.Client
	if client == nil {
		client = &http.Client{}
	} else {
		clone := *client
		client = &clone
	}
	// Cookies make no sense for webhooks and would otherwise leak between
	// endpoints sharing a client.
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	s.client = client
	return s
}

// Deliver POSTs event to endpointURL, signing the body with secret, and
// retries non-2xx and transport failures according to Config. It returns one
// record per attempt, in order; records are nil when validation fails before
// the first attempt.
//
// A nil error means some attempt reached a 2xx response. Otherwise the error
// wraps ErrRejected (the final attempt got a non-2xx status), the last
// transport failure, or the context error that stopped the sequence —
// errors.Is matches the corresponding sentinel, context.Canceled, or
// context.DeadlineExceeded.
func (s *Sender) Deliver(ctx context.Context, endpointURL string, event Event, secret []byte) ([]Delivery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := parseEndpoint(endpointURL)
	if err != nil {
		return nil, err
	}
	if err := event.validate(); err != nil {
		return nil, err
	}

	body, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidEvent, err)
	}
	if len(body) > s.maxBodyBytes {
		return nil, fmt.Errorf("%w: body is %d bytes, limit is %d", ErrTooLarge, len(body), s.maxBodyBytes)
	}

	signature := Sign(secret, body)
	deliveryID, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("webhook: delivery id: %w", err)
	}

	records := make([]Delivery, 0, s.maxAttempts)
	var lastErr error
	for attempt := 1; attempt <= s.maxAttempts; attempt++ {
		if attempt > 1 {
			if err := wait(ctx, s.backoff(attempt-1)); err != nil {
				return records, err
			}
		}

		record, attemptErr := s.attempt(ctx, target, body, signature, event.Event, deliveryID)
		record.ID = deliveryID
		record.EndpointID = s.endpointID
		record.EventID = event.ID
		record.Attempt = attempt
		records = append(records, record)

		if attemptErr != nil {
			lastErr = attemptErr
			if ctxErr := ctx.Err(); ctxErr != nil {
				return records, ctxErr
			}
			continue
		}
		if isSuccess(record.StatusCode) {
			return records, nil
		}
		lastErr = nil
	}

	last := records[len(records)-1]
	if last.StatusCode != 0 {
		return records, fmt.Errorf("%w: status %d after %d attempt(s)", ErrRejected, last.StatusCode, len(records))
	}
	// maxAttempts >= 1 always runs at least one attempt, so a zero status here
	// means every attempt failed below HTTP (dial, TLS, timeout).
	return records, fmt.Errorf("webhook: delivery failed after %d attempt(s): %w", len(records), lastErr)
}

// attempt performs one POST and always returns a record.
func (s *Sender) attempt(parent context.Context, target *url.URL, body []byte, signature, eventName, deliveryID string) (Delivery, error) {
	timeout := s.timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		// Only unreachable for URLs that already passed parseEndpoint.
		return Delivery{Error: err.Error()}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderSignature, signature)
	req.Header.Set(HeaderEvent, eventName)
	req.Header.Set(HeaderDelivery, deliveryID)

	start := time.Now()
	resp, err := s.client.Do(req)
	if err != nil {
		cause := causeOf(err)
		return Delivery{Error: cause.Error(), Duration: time.Since(start)}, cause
	}
	defer func() { _ = resp.Body.Close() }()

	// The status is the outcome; the body is drained only up to the cap so an
	// endless or oversized response cannot exhaust memory or stall the retry
	// sequence.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, int64(s.maxResponseBytes)+1))

	record := Delivery{StatusCode: resp.StatusCode, Duration: time.Since(start)}
	if isSuccess(resp.StatusCode) {
		record.DeliveredAt = time.Now().UTC()
	} else {
		record.Error = fmt.Sprintf("unexpected status %d", resp.StatusCode)
	}
	return record, nil
}

// parseEndpoint accepts only absolute http(s) URLs with a host. Range policy
// (loopback, link-local, cloud metadata) belongs to endpoint registration,
// not to the delivery primitive.
func parseEndpoint(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: empty URL", ErrInvalidEndpoint)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEndpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q is not http or https", ErrInvalidEndpoint, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrInvalidEndpoint)
	}
	return u, nil
}

// validate reports the first contract violation in the envelope.
func (e Event) validate() error {
	switch {
	case e.ID == "":
		return fmt.Errorf("%w: empty id", ErrInvalidEvent)
	case e.Event == "":
		return fmt.Errorf("%w: empty event", ErrInvalidEvent)
	case e.Timestamp.IsZero():
		return fmt.Errorf("%w: zero timestamp", ErrInvalidEvent)
	case e.SessionID == "":
		return fmt.Errorf("%w: empty session_id", ErrInvalidEvent)
	case len(e.Data) == 0:
		return fmt.Errorf("%w: empty data", ErrInvalidEvent)
	case !json.Valid(e.Data):
		return fmt.Errorf("%w: data is not valid JSON", ErrInvalidEvent)
	}
	// The contract types data as an object; arrays and scalars are rejected
	// instead of shipping a payload receivers cannot index.
	if trimmed := bytes.TrimLeft(e.Data, " \t\r\n"); len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("%w: data is not a JSON object", ErrInvalidEvent)
	}
	return nil
}

// causeOf strips the *url.Error wrapper so recorded and returned errors carry
// the failure reason without the target URL or its query string.
func causeOf(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err
	}
	return err
}

// wait sleeps for d unless ctx ends first.
func wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isSuccess(status int) bool { return status >= 200 && status < 300 }

// newUUID returns a random RFC 4122 version 4 UUID, matching the uuid columns
// that persist deliveries.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
