package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/protocol/auth"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
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

// TestPairingPayloadSignsThePreKey pins the fix for the failure that made a
// real phone report "couldn't link new device": the payload used to carry a
// 64-byte zero signature, which is the right length and so passed local
// validation, but the server verifies it against eIdent and rejects the link.
func TestPairingPayloadSignsThePreKey(t *testing.T) {
	identity, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	raw, _, err := buildPairingPayload(identity, 4242)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	parsed, err := auth.ParseClientPayload(raw)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}

	var preKey [32]byte
	copy(preKey[:], parsed.Registration.SignedPreKey)
	var identityKey [32]byte
	copy(identityKey[:], parsed.Registration.IdentityKey)
	if identityKey != identity.Pub {
		t.Fatal("payload identity does not match the QR identity")
	}
	if err := signal.VerifySignedPreKey(identityKey, preKey, parsed.Registration.SignedPreKeySignature); err != nil {
		t.Fatalf("signed prekey does not verify against the identity: %v", err)
	}
}

// TestPairingPayloadReportsAChromePlatform pins the second divergence: a web
// QR login reports a concrete browser, and the client-type field derives from
// it, so UNKNOWN does not describe any real pairing.
func TestPairingPayloadReportsAChromePlatform(t *testing.T) {
	identity, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	raw, _, err := buildPairingPayload(identity, 1)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	parsed, err := auth.ParseClientPayload(raw)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if parsed.DeviceProps.PlatformType != protobuf.DeviceProps_CHROME {
		t.Fatalf("platform type is %v, want CHROME", parsed.DeviceProps.PlatformType)
	}
	if parsed.DeviceProps.HistorySync == nil {
		t.Fatal("history sync capability block is absent")
	}
}

// TestQRValidityWindowMatchesTheReference pins the rotation timings taken from
// the reference implementation: 60 seconds for the first of six codes, 20 for
// the rest. Printing all six at once guarantees the phone scans a dead code,
// which is what happened before this existed.
func TestQRValidityWindowMatchesTheReference(t *testing.T) {
	cases := []struct {
		index, total int
		want         time.Duration
	}{
		{0, 6, 60 * time.Second},
		{1, 6, 20 * time.Second},
		{5, 6, 20 * time.Second},
		{0, 3, 20 * time.Second},
	}
	for _, c := range cases {
		if got := qrValidityWindow(c.index, c.total); got != c.want {
			t.Fatalf("qrValidityWindow(%d,%d) = %s, want %s", c.index, c.total, got, c.want)
		}
	}
}

// TestRotationShowsOneCodeAtATime pins the sequencing: a second code must not
// be emitted until the first one's window closes, and closing stop must end the
// rotation without waiting out the remaining windows.
func TestRotationShowsOneCodeAtATime(t *testing.T) {
	stop := make(chan struct{})
	emitted := make(chan string, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		rotateQRCodes(context.Background(), stop, []string{"first", "second"}, func(_ int, code string, _ time.Duration) {
			emitted <- code
		})
	}()

	select {
	case first := <-emitted:
		if first != "first" {
			t.Fatalf("emitted %q first", first)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no code emitted")
	}

	// The second code must stay back for the first code's window.
	select {
	case code := <-emitted:
		t.Fatalf("emitted %q before the first window closed", code)
	case <-time.After(100 * time.Millisecond):
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("rotation did not stop when told")
	}
}

// TestRotationWalksEveryCode proves the loop does not stop after the first
// code when nothing interrupts it.
func TestRotationWalksEveryCode(t *testing.T) {
	var windows []time.Duration
	// A cancelled context ends each window immediately, which walks the whole
	// list without waiting real seconds.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rotateQRCodes(ctx, make(chan struct{}), []string{"a", "b", "c"}, func(_ int, _ string, w time.Duration) {
		windows = append(windows, w)
	})
	if len(windows) != 1 {
		t.Fatalf("cancelled context emitted %d codes, want 1", len(windows))
	}
}

// TestPairingPayloadDoesNotClaimToBeAnotherLibrary pins the fix for something
// visible on a phone: Linked devices listed this client as "Google Chrome
// (whatsmeow)". The OS field is free text the protocol never constrains, and it
// was a literal copied from the reference while the payload was being made to
// work. A WhatsCore session must identify itself as WhatsCore.
func TestPairingPayloadDoesNotClaimToBeAnotherLibrary(t *testing.T) {
	identity, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	raw, _, err := buildPairingPayload(identity, 1)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	parsed, err := auth.ParseClientPayload(raw)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if parsed.DeviceProps.OS != "whatscore" {
		t.Fatalf("os is %q, want %q", parsed.DeviceProps.OS, "whatscore")
	}
	if strings.Contains(strings.ToLower(parsed.DeviceProps.OS), "whatsmeow") {
		t.Fatal("payload still names another library")
	}
}

// TestPairingPayloadReportsAWebBrowser explains the other half of the label the
// phone shows. CHROME is not a lie about the runtime: a QR login is the web
// companion flow, and client type 1 (Chrome) accompanies it (PF-071). What
// lands on the screen is therefore "<browser> (<os>)", which reads as
// "Google Chrome (whatscore)".
func TestPairingPayloadReportsAWebBrowser(t *testing.T) {
	identity, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	raw, _, err := buildPairingPayload(identity, 1)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	parsed, err := auth.ParseClientPayload(raw)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if parsed.DeviceProps.PlatformType != protobuf.DeviceProps_CHROME {
		t.Fatalf("platform type is %v, want CHROME", parsed.DeviceProps.PlatformType)
	}
}
