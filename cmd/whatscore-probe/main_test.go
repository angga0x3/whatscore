package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/gorilla/websocket"
)

// TestProbeAgainstFakeServer proves the probe tool itself works: it talks to a
// WebSocket server that speaks the recorded handshake, so a real-world failure
// means the endpoint diverged rather than the tool being broken.
func TestProbeAgainstFakeServer(t *testing.T) {
	serverEph, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverStatic, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rootEd, rootMont := probeTestKeypair(t)
	intEd, intMont := probeTestKeypair(t)
	certBlob := probeTestCertChain(t, rootEd, intEd, intMont, serverStatic.Pub[:])

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	serverErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = ws.Close() }()
		serverErr <- probeTestServer(context.Background(), ws, serverEph, serverStatic, certBlob)
	}))
	t.Cleanup(srv.Close)

	result, err := probeWithRoot(context.Background(), wsURL(srv.URL), 10*time.Second, false, rootMont[:])
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if result.Outcome != outcomeHandshakeCompleted {
		t.Fatalf("outcome = %s (%s)", result.Outcome, result.Detail)
	}
	if !strings.Contains(result.Detail, noise.CipherSuite) {
		t.Fatalf("detail = %q", result.Detail)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("fake server: %v", err)
	}
}

func TestProbeReportsDialFailure(t *testing.T) {
	result, err := probeWithRoot(context.Background(), "ws://127.0.0.1:1/ws/chat", 2*time.Second, false, waRootPub)
	if err == nil {
		t.Fatal("expected an error")
	}
	if result.Outcome != outcomeDialFailed {
		t.Fatalf("outcome = %s", result.Outcome)
	}
}

func TestProbeRootConstant(t *testing.T) {
	if len(waRootPub) != 32 {
		t.Fatalf("root key is %d bytes", len(waRootPub))
	}
	if hex.EncodeToString(waRootPub) != "142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b" {
		t.Fatal("root key does not match the recorded finding")
	}
}

func wsURL(httpURL string) string { return "ws" + strings.TrimPrefix(httpURL, "http") }
