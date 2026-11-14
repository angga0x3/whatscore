package transport

import (
	"bytes"
	"testing"
	"time"
)

// TestIntroHeaderBytes pins the intro header bytes: "WA" + magic 6 + dict
// version 3 (PF-003).
func TestIntroHeaderBytes(t *testing.T) {
	want := []byte{0x57, 0x41, 0x06, 0x03}
	if !bytes.Equal(IntroHeader, want) {
		t.Fatalf("IntroHeader = % x, want % x (PF-003)", IntroHeader, want)
	}
}

// TestFrameMaxSizeValue pins the 24-bit frame size limit (PF-003).
func TestFrameMaxSizeValue(t *testing.T) {
	if FrameMaxSize != 1<<24 {
		t.Fatalf("FrameMaxSize = %d, want 2^24 (PF-003)", FrameMaxSize)
	}
}

// TestDefaultURLValue pins the PF-002 endpoint URL.
func TestDefaultURLValue(t *testing.T) {
	if DefaultURL != "wss://web.whatsapp.com/ws/chat" {
		t.Fatalf("DefaultURL = %q, want %q (PF-002)", DefaultURL, "wss://web.whatsapp.com/ws/chat")
	}
}

// TestDefaultEndpoint pins the PF-002 endpoint values and checks that each
// call returns a fresh headers map.
func TestDefaultEndpoint(t *testing.T) {
	ep := DefaultEndpoint()

	if ep.URL != DefaultURL {
		t.Fatalf("URL = %q, want %q (PF-002)", ep.URL, DefaultURL)
	}
	if ep.HandshakeTimeout != 15*time.Second {
		t.Fatalf("HandshakeTimeout = %v, want 15s", ep.HandshakeTimeout)
	}

	want := map[string]string{
		"Origin":        "https://web.whatsapp.com",
		"Cache-Control": "no-cache",
		"Pragma":        "no-cache",
	}
	if len(ep.ExtraHeaders) != len(want) {
		t.Fatalf("ExtraHeaders = %v, want %v (PF-002)", ep.ExtraHeaders, want)
	}
	for k, v := range want {
		if got := ep.ExtraHeaders[k]; got != v {
			t.Fatalf("ExtraHeaders[%q] = %q, want %q (PF-002)", k, got, v)
		}
	}

	// Mutating one endpoint must not leak into the next.
	ep.ExtraHeaders["Origin"] = "tampered"
	if again := DefaultEndpoint(); again.ExtraHeaders["Origin"] != "https://web.whatsapp.com" {
		t.Fatal("DefaultEndpoint must return a fresh headers map per call")
	}
}
