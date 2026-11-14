package transport

import (
	"testing"
	"time"
)

// inJitterBand reports whether d lies within ±20% of center, with 1ns of
// slack to absorb float truncation in the jitter multiply.
func inJitterBand(center, d time.Duration) bool {
	lo := time.Duration(float64(center)*(1-jitterFraction)) - time.Nanosecond
	hi := time.Duration(float64(center)*(1+jitterFraction)) + time.Nanosecond
	return d >= lo && d <= hi
}

// TestBackoffGrowthAndCap: delays grow monotonically (the ±20% bands of
// consecutive doublings do not overlap) until the cap flattens them.
func TestBackoffGrowthAndCap(t *testing.T) {
	base := 10 * time.Millisecond
	maxDelay := 100 * time.Millisecond
	b := NewExponentialBackoff(base, maxDelay, 8)

	// Attempts 1..3: centers 10ms, 20ms, 40ms — strictly increasing.
	for i, center := range []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond} {
		attempt := i + 1
		d, ok := b.Next(attempt)
		if !ok {
			t.Fatalf("Next(%d): want ok", attempt)
		}
		if !inJitterBand(center, d) {
			t.Fatalf("Next(%d) = %v, want ±20%% of %v", attempt, d, center)
		}
	}

	// From attempt 5 on (uncapped 160ms and beyond) the delay stays at the cap.
	for _, attempt := range []int{5, 6, 7} {
		d, ok := b.Next(attempt)
		if !ok {
			t.Fatalf("Next(%d): want ok", attempt)
		}
		if !inJitterBand(maxDelay, d) {
			t.Fatalf("Next(%d) = %v, want ±20%% of cap %v", attempt, d, maxDelay)
		}
	}
}

// TestBackoffJitterSpread: repeated calls for the same attempt spread across
// the ±20% band rather than clustering at the center.
func TestBackoffJitterSpread(t *testing.T) {
	b := NewExponentialBackoff(100*time.Millisecond, time.Second, 100)
	center := 100 * time.Millisecond
	lo := time.Duration(float64(center) * 0.85)
	hi := time.Duration(float64(center) * 1.15)
	var sawLow, sawHigh bool
	for i := 0; i < 500; i++ {
		d, ok := b.Next(1)
		if !ok {
			t.Fatalf("Next(1): want ok")
		}
		if !inJitterBand(center, d) {
			t.Fatalf("Next(1) = %v, want ±20%% of %v", d, center)
		}
		if d < lo {
			sawLow = true
		}
		if d > hi {
			sawHigh = true
		}
	}
	if !sawLow || !sawHigh {
		t.Fatalf("jitter never left the middle 30%% band (low=%v high=%v)", sawLow, sawHigh)
	}
}

// TestBackoffGivesUpAtMaxAttempts: Next reports false from maxAttempts on.
func TestBackoffGivesUpAtMaxAttempts(t *testing.T) {
	b := NewExponentialBackoff(time.Millisecond, 5*time.Millisecond, 4)
	for attempt := 1; attempt < 4; attempt++ {
		if _, ok := b.Next(attempt); !ok {
			t.Fatalf("Next(%d): want ok", attempt)
		}
	}
	if d, ok := b.Next(4); ok || d != 0 {
		t.Fatalf("Next(4) = (%v, %v), want (0, false)", d, ok)
	}
	if d, ok := b.Next(100); ok || d != 0 {
		t.Fatalf("Next(100) = (%v, %v), want (0, false)", d, ok)
	}
}

// TestBackoffOverflowGuard: shift amounts beyond 62 resolve to the cap
// instead of overflowing the duration.
func TestBackoffOverflowGuard(t *testing.T) {
	b := NewExponentialBackoff(time.Hour, 2*time.Hour, 100000)
	d, ok := b.Next(1000) // shift 999, far past 62
	if !ok {
		t.Fatal("Next(1000): want ok")
	}
	if !inJitterBand(2*time.Hour, d) {
		t.Fatalf("Next(1000) = %v, want ±20%% of cap 2h", d)
	}
}

// TestBackoffResetIsNoOp: Reset does not disturb the attempt-parameter-based
// state, and attempt 0 clamps to the base delay instead of shifting negative.
func TestBackoffResetIsNoOp(t *testing.T) {
	b := NewExponentialBackoff(10*time.Millisecond, 100*time.Millisecond, 10)
	b.Reset()
	if d, ok := b.Next(1); !ok || !inJitterBand(10*time.Millisecond, d) {
		t.Fatalf("Next(1) after Reset = (%v, %v), want ok with ±20%% of 10ms", d, ok)
	}
	if d, ok := b.Next(0); !ok || !inJitterBand(10*time.Millisecond, d) {
		t.Fatalf("Next(0) = (%v, %v), want ok with ±20%% of 10ms", d, ok)
	}
}
