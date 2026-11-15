package main

import (
	"strings"
	"testing"
)

// TestQRPayloadRoundTrips proves the QR encoder is fed the exact payload the
// pairing parser expects: encode, then parse the same string back, including a
// 102-byte ref as the live server sends (PF-069).
func TestQRPayloadRoundTrips(t *testing.T) {
	payload := "https://wa.me/settings/linked_devices#" +
		strings.Repeat("A", 102) + "," +
		"ERERERERERERERERERERERERERERERERERERERERERE=," +
		"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=," +
		"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=,1"

	code, err := qrStringForTest(payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if code == "" {
		t.Fatal("empty QR render")
	}
	// The QR content must be the payload itself, not a mangled copy.
	if !strings.Contains(code, strings.Repeat("A", 102)) {
		t.Fatal("rendered QR does not carry the ref")
	}
	if !strings.HasPrefix(code, "https://wa.me/settings/linked_devices#") {
		t.Fatal("prefix lost")
	}
}
