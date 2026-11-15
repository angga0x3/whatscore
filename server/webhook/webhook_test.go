package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// noBackoff disables waits so retry tests stay fast.
func noBackoff(int) time.Duration { return 0 }

// testSender returns a Sender with zero waits and a fixed endpoint id.
func testSender(cfg Config) *Sender {
	if cfg.Backoff == nil {
		cfg.Backoff = noBackoff
	}
	cfg.EndpointID = "ep_test"
	return New(cfg)
}

func testEvent() Event {
	return Event{
		ID:        "evt_01JTEST",
		Event:     "message.received",
		Timestamp: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
		SessionID: "e8b8c2c0-0f6b-4a88-a4b1-1f1a12345678",
		Data:      json.RawMessage(`{"text":"Halo WhatsCore!"}`),
	}
}

func TestSignKnownAnswer(t *testing.T) {
	// HMAC-SHA256("secret", `{"hello":"world"}`) — fixed vector so a change in
	// encoding or hash is caught.
	got := Sign([]byte("secret"), []byte(`{"hello":"world"}`))
	want := "2677ad3e7c090b2fa2c0fb13020d66d5420879b8316eb356a2d60fb9073bc778"
	if got != want {
		t.Fatalf("Sign = %q, want %q", got, want)
	}
}

func TestVerify(t *testing.T) {
	secret := []byte("s3cr3t")
	body := []byte(`{"id":"evt_1"}`)
	good := Sign(secret, body)

	tests := []struct {
		name      string
		secret    []byte
		body      []byte
		signature string
		want      bool
	}{
		{name: "valid", secret: secret, body: body, signature: good, want: true},
		{name: "tampered body", secret: secret, body: []byte(`{"id":"evt_2"}`), signature: good, want: false},
		{name: "wrong secret", secret: []byte("other"), body: body, signature: good, want: false},
		{name: "truncated signature", secret: secret, body: body, signature: good[:len(good)-2], want: false},
		{name: "extended signature", secret: secret, body: body, signature: good + "00", want: false},
		{name: "uppercase hex", secret: secret, body: body, signature: strings.ToUpper(good), want: false},
		{name: "empty signature", secret: secret, body: body, signature: "", want: false},
		{name: "garbage signature", secret: secret, body: body, signature: "not-hex", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Verify(tc.secret, tc.body, tc.signature); got != tc.want {
				t.Errorf("Verify = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestVerifyEmptySecretStillSigns pins the behavior for a missing secret: the
// primitive stays total and verification still rejects tampering.
func TestVerifyEmptySecretStillSigns(t *testing.T) {
	sig := Sign(nil, []byte("body"))
	if sig == "" {
		t.Fatal("Sign(nil secret) returned an empty signature")
	}
	if !Verify(nil, []byte("body"), sig) {
		t.Error("Verify with the same empty secret and body = false, want true")
	}
	if Verify(nil, []byte("other"), sig) {
		t.Error("Verify accepted a different body")
	}
}

func TestEventJSONKeys(t *testing.T) {
	body, err := json.Marshal(testEvent())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"id", "event", "timestamp", "session_id", "data"}
	if len(got) != len(want) {
		t.Fatalf("envelope keys = %v, want %v", keys(got), want)
	}
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("envelope is missing %q; got %v", key, keys(got))
		}
	}
	if string(got["timestamp"]) != `"2026-11-15T00:00:00Z"` {
		t.Errorf("timestamp = %s, want RFC 3339 UTC", got["timestamp"])
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDeliverSuccess(t *testing.T) {
	var (
		hits     atomic.Int32
		gotBody  []byte
		gotEvent string
		gotSig   string
		gotID    string
		gotCT    string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		gotBody = body
		gotEvent = r.Header.Get(HeaderEvent)
		gotSig = r.Header.Get(HeaderSignature)
		gotID = r.Header.Get(HeaderDelivery)
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	secret := []byte("whsec_test")
	event := testEvent()
	records, err := testSender(Config{}).Deliver(context.Background(), srv.URL+"/hook", event, secret)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("handler hits = %d, want 1", hits.Load())
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	rec := records[0]
	if rec.Attempt != 1 || rec.StatusCode != http.StatusAccepted {
		t.Errorf("record = %+v, want attempt 1 status 202", rec)
	}
	if rec.EndpointID != "ep_test" || rec.EventID != event.ID || rec.ID == "" {
		t.Errorf("record ids = %+v, want endpoint_id ep_test, event_id %q, non-empty id", rec, event.ID)
	}
	if rec.DeliveredAt.IsZero() {
		t.Error("DeliveredAt is zero on a successful delivery")
	}
	if rec.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", rec.Duration)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotEvent != event.Event {
		t.Errorf("%s = %q, want %q", HeaderEvent, gotEvent, event.Event)
	}
	if gotID != rec.ID {
		t.Errorf("%s = %q, want delivery id %q", HeaderDelivery, gotID, rec.ID)
	}
	if !Verify(secret, gotBody, gotSig) {
		t.Error("delivered signature does not verify")
	}
	var envelope Event
	if err := json.Unmarshal(gotBody, &envelope); err != nil {
		t.Fatalf("body is not the event envelope: %v", err)
	}
	if envelope.ID != event.ID || envelope.Event != event.Event || string(envelope.Data) != string(event.Data) {
		t.Errorf("envelope = %+v, want %+v", envelope, event)
	}
}

func TestDeliverRetriesThenSucceeds(t *testing.T) {
	var (
		hits    atomic.Int32
		mu      sync.Mutex
		headers []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		headers = append(headers, r.Header.Get(HeaderDelivery))
		mu.Unlock()
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	records, err := testSender(Config{MaxAttempts: 3}).Deliver(context.Background(), srv.URL, testEvent(), []byte("k"))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if hits.Load() != 2 {
		t.Errorf("hits = %d, want 2", hits.Load())
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if records[0].StatusCode != http.StatusInternalServerError || records[0].Error == "" {
		t.Errorf("first record = %+v, want 500 with an error", records[0])
	}
	if records[1].StatusCode != http.StatusNoContent || records[1].Error != "" {
		t.Errorf("second record = %+v, want 204 without an error", records[1])
	}
	if records[0].ID != records[1].ID {
		t.Errorf("delivery ids differ across attempts: %q vs %q", records[0].ID, records[1].ID)
	}
	mu.Lock()
	deliveryHeaders := append([]string(nil), headers...)
	mu.Unlock()
	if len(deliveryHeaders) != 2 || deliveryHeaders[0] != records[0].ID || deliveryHeaders[1] != records[0].ID {
		t.Errorf("delivery headers = %v, want both %q", deliveryHeaders, records[0].ID)
	}
	for i, rec := range records {
		if rec.Attempt != i+1 {
			t.Errorf("records[%d].Attempt = %d, want %d", i, rec.Attempt, i+1)
		}
		if rec.DeliveredAt.IsZero() == (i == len(records)-1) {
			t.Errorf("records[%d].DeliveredAt = %v; only the successful attempt may set it", i, rec.DeliveredAt)
		}
	}
}

// TestDeliverUsesConfiguredBackoff pins that the delay before attempt n is
// Backoff(n-1), so a scheduler can reproduce the published policy.
func TestDeliverUsesConfiguredBackoff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var asked []int
	backoff := func(attempt int) time.Duration {
		asked = append(asked, attempt)
		return time.Millisecond
	}
	if _, err := New(Config{MaxAttempts: 4, Backoff: backoff}).Deliver(context.Background(), srv.URL, testEvent(), []byte("k")); !errors.Is(err, ErrRejected) {
		t.Fatalf("error = %v, want ErrRejected", err)
	}
	want := []int{1, 2, 3}
	if len(asked) != len(want) {
		t.Fatalf("backoff calls = %v, want %v", asked, want)
	}
	for i := range want {
		if asked[i] != want[i] {
			t.Fatalf("backoff calls = %v, want %v", asked, want)
		}
	}
	if hits.Load() != 4 {
		t.Errorf("hits = %d, want 4", hits.Load())
	}
}

func TestDeliverAllAttemptsFail(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	records, err := testSender(Config{MaxAttempts: 3}).Deliver(context.Background(), srv.URL, testEvent(), []byte("k"))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("error = %v, want ErrRejected", err)
	}
	if hits.Load() != 3 {
		t.Errorf("hits = %d, want 3", hits.Load())
	}
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3", len(records))
	}
	for i, rec := range records {
		if rec.StatusCode != http.StatusBadGateway {
			t.Errorf("records[%d].StatusCode = %d, want 502", i, rec.StatusCode)
		}
		if !rec.DeliveredAt.IsZero() {
			t.Errorf("records[%d].DeliveredAt set on a failed attempt", i)
		}
	}
	if !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "3 attempt") {
		t.Errorf("error %q should name the status and attempt count", err)
	}
}

func TestDeliverRedirectNotFollowed(t *testing.T) {
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	records, err := testSender(Config{MaxAttempts: 2}).Deliver(context.Background(), srv.URL, testEvent(), []byte("k"))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("error = %v, want ErrRejected", err)
	}
	if followed.Load() != 0 {
		t.Errorf("redirect target was called %d time(s), want 0", followed.Load())
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	for i, rec := range records {
		if rec.StatusCode != http.StatusTemporaryRedirect {
			t.Errorf("records[%d].StatusCode = %d, want 307 (the redirect itself)", i, rec.StatusCode)
		}
	}
}

// TestDeliverDoesNotMutateClient pins that New owns redirect policy without
// touching the caller's client.
func TestDeliverDoesNotMutateClient(t *testing.T) {
	called := false
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			called = true
			return nil
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := testSender(Config{Client: client}).Deliver(context.Background(), srv.URL, testEvent(), []byte("k")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if called || client.CheckRedirect == nil {
		t.Error("New mutated the caller's CheckRedirect")
	}
	if client.Jar != nil {
		t.Error("New mutated the caller's cookie jar")
	}
}

func TestDeliverRecordsNon2xx(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{name: "not found", status: http.StatusNotFound},
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "payload too large", status: http.StatusRequestEntityTooLarge},
		{name: "server error", status: http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			records, err := testSender(Config{MaxAttempts: 1}).Deliver(context.Background(), srv.URL, testEvent(), []byte("k"))
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("error = %v, want ErrRejected", err)
			}
			if len(records) != 1 || records[0].StatusCode != tc.status {
				t.Fatalf("records = %+v, want one record with status %d", records, tc.status)
			}
			if records[0].Error == "" {
				t.Error("record carries no error for a non-2xx status")
			}
		})
	}
}

func TestDeliverBodySizeCap(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	event := testEvent()
	event.Data = json.RawMessage(`{"text":"` + strings.Repeat("x", 256) + `"}`)

	records, err := testSender(Config{MaxBodyBytes: 128}).Deliver(context.Background(), srv.URL, event, []byte("k"))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
	if records != nil {
		t.Errorf("records = %+v, want nil (nothing was sent)", records)
	}
	if hits.Load() != 0 {
		t.Errorf("hits = %d, want 0", hits.Load())
	}
}

// TestDeliverBodyCapIsInclusive: a body exactly at the limit is sent.
func TestDeliverBodyCapIsInclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	body, err := json.Marshal(testEvent())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	records, err := testSender(Config{MaxBodyBytes: len(body)}).Deliver(context.Background(), srv.URL, testEvent(), []byte("k"))
	if err != nil {
		t.Fatalf("Deliver at exact limit: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
}

func TestDeliverInvalidEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "empty", endpoint: ""},
		{name: "no scheme", endpoint: "example.com/hook"},
		{name: "empty host", endpoint: "http://"},
		{name: "ftp", endpoint: "ftp://example.com/hook"},
		{name: "file", endpoint: "file:///etc/passwd"},
		{name: "javascript", endpoint: "javascript:alert(1)"},
		{name: "unparseable", endpoint: "http://exa mple.com/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			records, err := testSender(Config{}).Deliver(context.Background(), tc.endpoint, testEvent(), []byte("k"))
			if !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("error = %v, want ErrInvalidEndpoint", err)
			}
			if records != nil {
				t.Errorf("records = %+v, want nil", records)
			}
		})
	}
}

func TestDeliverInvalidEvent(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "empty id", mutate: func(e *Event) { e.ID = "" }},
		{name: "empty event", mutate: func(e *Event) { e.Event = "" }},
		{name: "zero timestamp", mutate: func(e *Event) { e.Timestamp = time.Time{} }},
		{name: "empty session", mutate: func(e *Event) { e.SessionID = "" }},
		{name: "nil data", mutate: func(e *Event) { e.Data = nil }},
		{name: "invalid json", mutate: func(e *Event) { e.Data = json.RawMessage(`{"oops"`) }},
		{name: "array data", mutate: func(e *Event) { e.Data = json.RawMessage(`[1,2]`) }},
		{name: "scalar data", mutate: func(e *Event) { e.Data = json.RawMessage(`"text"`) }},
		{name: "null data", mutate: func(e *Event) { e.Data = json.RawMessage(`null`) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := testEvent()
			tc.mutate(&event)

			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			records, err := testSender(Config{}).Deliver(context.Background(), srv.URL, event, []byte("k"))
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("error = %v, want ErrInvalidEvent", err)
			}
			if records != nil || hits.Load() != 0 {
				t.Errorf("records = %+v, hits = %d; want nil and 0", records, hits.Load())
			}
		})
	}
}

func TestDeliverTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := srv.URL
	srv.Close() // nothing is listening any more

	records, err := testSender(Config{MaxAttempts: 2}).Deliver(context.Background(), endpoint, testEvent(), []byte("k"))
	if err == nil {
		t.Fatal("Deliver to a closed server returned nil error")
	}
	if errors.Is(err, ErrRejected) {
		t.Errorf("error = %v, want a transport error rather than ErrRejected", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	for i, rec := range records {
		if rec.StatusCode != 0 {
			t.Errorf("records[%d].StatusCode = %d, want 0", i, rec.StatusCode)
		}
		if rec.Error == "" {
			t.Errorf("records[%d].Error is empty", i)
		}
	}
	if strings.Contains(err.Error(), "http://") {
		t.Errorf("error %q leaks the endpoint URL", err)
	}
}

func TestDeliverCancelledBeforeStart(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	records, err := testSender(Config{}).Deliver(ctx, srv.URL, testEvent(), []byte("k"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if records != nil || hits.Load() != 0 {
		t.Errorf("records = %+v, hits = %d; want nil and 0", records, hits.Load())
	}
}

func TestDeliverCancellationStopsRetries(t *testing.T) {
	firstAttempt := make(chan struct{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			close(firstAttempt)
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A backoff far longer than the test: cancellation, not the timer, must
	// end the sequence.
	sender := testSender(Config{MaxAttempts: 5, Backoff: func(int) time.Duration { return time.Hour }})

	done := make(chan struct{})
	var (
		records []Delivery
		err     error
	)
	go func() {
		records, err = sender.Deliver(ctx, srv.URL, testEvent(), []byte("k"))
		close(done)
	}()

	<-firstAttempt
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Deliver did not return after cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(records) != 1 {
		t.Errorf("records = %d, want 1 (cancellation during backoff)", len(records))
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}

func TestDeliverPerAttemptTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	records, err := testSender(Config{MaxAttempts: 1, Timeout: 20 * time.Millisecond}).
		Deliver(context.Background(), srv.URL, testEvent(), []byte("k"))
	if err == nil {
		t.Fatal("Deliver with a stuck endpoint returned nil error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded from the per-attempt timeout", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want a timeout rather than cancellation", err)
	}
	if len(records) != 1 || records[0].StatusCode != 0 {
		t.Fatalf("records = %+v, want one record with status 0", records)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("attempt took %v, want near the 20ms timeout", elapsed)
	}
}

func TestDeliverLargeResponseIsDiscarded(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("z", 1<<20)))
	}))
	defer srv.Close()

	records, err := testSender(Config{MaxResponseBytes: 1024}).Deliver(context.Background(), srv.URL, testEvent(), []byte("k"))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(records) != 1 || records[0].StatusCode != http.StatusOK {
		t.Fatalf("records = %+v, want one 200 record", records)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}

func TestExponentialBackoff(t *testing.T) {
	base := 100 * time.Millisecond
	maxDelay := time.Second
	backoff := ExponentialBackoff(base, maxDelay)

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: -5, want: 100 * time.Millisecond},
		{attempt: 0, want: 100 * time.Millisecond},
		{attempt: 1, want: 100 * time.Millisecond},
		{attempt: 2, want: 200 * time.Millisecond},
		{attempt: 3, want: 400 * time.Millisecond},
		{attempt: 4, want: 800 * time.Millisecond},
		{attempt: 5, want: time.Second},
		{attempt: 6, want: time.Second},
		{attempt: 63, want: time.Second},
		{attempt: 1 << 20, want: time.Second},
	}
	for _, tc := range tests {
		if got := backoff(tc.attempt); got != tc.want {
			t.Errorf("backoff(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestExponentialBackoffEdgeConfigs(t *testing.T) {
	tests := []struct {
		name    string
		base    time.Duration
		max     time.Duration
		attempt int
		want    time.Duration
	}{
		{name: "zero base", base: 0, max: time.Second, attempt: 3, want: 0},
		{name: "max below base clamps to base", base: time.Second, max: time.Millisecond, attempt: 1, want: time.Second},
		{name: "max below base at attempt 4", base: time.Second, max: time.Millisecond, attempt: 4, want: time.Second},
		{name: "negative base", base: -time.Second, max: time.Second, attempt: 2, want: 0},
		{name: "overflow guard", base: time.Hour, max: 2 * time.Hour, attempt: 62, want: 2 * time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExponentialBackoff(tc.base, tc.max)(tc.attempt); got != tc.want {
				t.Errorf("backoff(%d) = %v, want %v", tc.attempt, got, tc.want)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	s := New(Config{})
	if s.timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", s.timeout, DefaultTimeout)
	}
	if s.maxAttempts != DefaultMaxAttempts {
		t.Errorf("maxAttempts = %d, want %d", s.maxAttempts, DefaultMaxAttempts)
	}
	if s.maxBodyBytes != DefaultMaxBodyBytes {
		t.Errorf("maxBodyBytes = %d, want %d", s.maxBodyBytes, DefaultMaxBodyBytes)
	}
	if s.maxResponseBytes != DefaultMaxResponseBytes {
		t.Errorf("maxResponseBytes = %d, want %d", s.maxResponseBytes, DefaultMaxResponseBytes)
	}
	if s.backoff == nil || s.client == nil {
		t.Fatal("New left backoff or client nil")
	}
	if s.client.CheckRedirect == nil {
		t.Fatal("New did not install a redirect policy")
	}
	// A default sender is useful: exactly one attempt reaches the endpoint.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if _, err := s.Deliver(context.Background(), srv.URL, testEvent(), []byte("k")); err != nil {
		t.Fatalf("Deliver with defaults: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}

func TestSenderConcurrentUse(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := testSender(Config{})
	const workers = 8
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			_, err := sender.Deliver(context.Background(), srv.URL, testEvent(), []byte("k"))
			errs <- err
		}()
	}
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Deliver: %v", err)
		}
	}
	if hits.Load() != workers {
		t.Errorf("hits = %d, want %d", hits.Load(), workers)
	}
}

func TestDeliveryIDIsUUIDv4(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	records, err := testSender(Config{}).Deliver(context.Background(), srv.URL, testEvent(), []byte("k"))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	id := records[0].ID
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		t.Fatalf("delivery id %q is not a hyphenated UUID", id)
	}
	if id[14] != '4' {
		t.Errorf("delivery id %q is not version 4", id)
	}
	if !strings.ContainsRune("89ab", rune(id[19])) {
		t.Errorf("delivery id %q has a bad RFC 4122 variant", id)
	}
}
