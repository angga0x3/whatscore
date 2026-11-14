package transport

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

var errFakeDial = errors.New("fake dial failure")

// fakeDialer fails the first `failures` dials with errFakeDial, then succeeds
// with a stub connection. No network involved.
type fakeDialer struct {
	failures int

	mu    sync.Mutex
	calls int
	conn  FrameConn
}

func (f *fakeDialer) Dial(_ context.Context, _ Endpoint) (FrameConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failures {
		return nil, errFakeDial
	}
	if f.conn == nil {
		f.conn = &stubFrameConn{}
	}
	return f.conn, nil
}

func (f *fakeDialer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// stubFrameConn is a minimal FrameConn for dialers that never touch the wire.
type stubFrameConn struct{}

func (s *stubFrameConn) ReadFrame(_ context.Context) ([]byte, error) {
	return nil, ErrClosed
}

func (s *stubFrameConn) WriteFrame(_ context.Context, _ []byte) error { return nil }

func (s *stubFrameConn) Close() error { return nil }

// countingPolicy counts Reset calls while delegating to a wrapped policy.
type countingPolicy struct {
	ReconnectPolicy
	mu     sync.Mutex
	resets int
}

func (p *countingPolicy) Reset() {
	p.mu.Lock()
	p.resets++
	p.mu.Unlock()
}

func (p *countingPolicy) resetCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resets
}

// retryCall records one onRetry invocation.
type retryCall struct {
	attempt int
	delay   time.Duration
	err     error
}

// TestConnectWithRetrySucceedsAfterFailures: a dialer failing twice must be
// retried twice (onRetry called for attempts 1 and 2 with base-scaled delays)
// and succeed on the third dial, with the policy reset on success.
func TestConnectWithRetrySucceedsAfterFailures(t *testing.T) {
	fd := &fakeDialer{failures: 2}
	cp := &countingPolicy{
		ReconnectPolicy: NewExponentialBackoff(time.Millisecond, 5*time.Millisecond, 5),
	}

	var calls []retryCall
	fc, err := ConnectWithRetry(
		context.Background(), fd, Endpoint{}, cp,
		func(attempt int, delay time.Duration, err error) {
			calls = append(calls, retryCall{attempt: attempt, delay: delay, err: err})
		},
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if fc == nil {
		t.Fatal("nil connection on success")
	}
	if got := fd.callCount(); got != 3 {
		t.Fatalf("dial calls = %d, want 3 (fail, fail, succeed)", got)
	}
	if cp.resetCount() != 1 {
		t.Fatalf("policy Reset calls = %d, want 1 on success", cp.resetCount())
	}

	if len(calls) != 2 {
		t.Fatalf("onRetry calls = %d, want 2", len(calls))
	}
	for i, wantAttempt := range []int{1, 2} {
		if calls[i].attempt != wantAttempt {
			t.Errorf("onRetry %d attempt = %d, want %d", i, calls[i].attempt, wantAttempt)
		}
		if calls[i].err == nil || !errors.Is(calls[i].err, errFakeDial) {
			t.Errorf("onRetry %d err = %v, want errFakeDial", i, calls[i].err)
		}
	}
	if !inJitterBand(time.Millisecond, calls[0].delay) {
		t.Errorf("onRetry 1 delay = %v, want ±20%% of 1ms", calls[0].delay)
	}
	if !inJitterBand(2*time.Millisecond, calls[1].delay) {
		t.Errorf("onRetry 2 delay = %v, want ±20%% of 2ms", calls[1].delay)
	}
}

// TestConnectWithRetryGivesUp: a policy that reports false must stop retrying
// and return the last dial error wrapped with the attempt count. onRetry is
// nil here, which the loop must tolerate.
func TestConnectWithRetryGivesUp(t *testing.T) {
	fd := &fakeDialer{failures: 999} // always fails
	policy := NewExponentialBackoff(time.Millisecond, 5*time.Millisecond, 2)

	fc, err := ConnectWithRetry(context.Background(), fd, Endpoint{}, policy, nil)
	if err == nil || fc != nil {
		t.Fatalf("want error and nil connection, got conn=%v err=%v", fc, err)
	}
	if !errors.Is(err, errFakeDial) {
		t.Fatalf("returned error must wrap the last dial error, got %v", err)
	}
	if !strings.Contains(err.Error(), "2 attempt") {
		t.Errorf("error should mention the attempt count: %v", err)
	}
	if got := fd.callCount(); got != 2 {
		t.Fatalf("dial calls = %d, want 2", got)
	}
}

// TestConnectWithRetryCancelledDuringSleep: cancelling the context while a
// retry sleep is in flight must surface context.Canceled instead of a
// connection.
func TestConnectWithRetryCancelledDuringSleep(t *testing.T) {
	fd := &fakeDialer{failures: 999}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	policy := NewExponentialBackoff(50*time.Millisecond, 50*time.Millisecond, 10)
	_, err := ConnectWithRetry(ctx, fd, Endpoint{}, policy,
		func(int, time.Duration, error) { cancel() },
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled-wrapped error, got %v", err)
	}
}
