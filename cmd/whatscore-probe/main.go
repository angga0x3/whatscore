// Command whatscore-probe performs a read-only reachability probe of the
// WhatsApp Web transport: dial, send the intro header, run Noise msg1, and read
// the server's msg2. It never pairs, never authenticates, and never sends a
// message.
//
// Its only purpose is to raise the confidence of the transport findings
// (PF-002, PF-003, PF-004..PF-009) against the real endpoint. A failure is also
// a result: it tells us which layer diverges first.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/angga0x3/whatscore/internal/waref"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// waRootPub is the pinned WhatsApp server certificate root key recorded in
// docs/protocol/noise.md (PF-009). It is a public constant, not a credential,
// and it lives in internal/waref so the probe and the server cannot pin
// different values.
var waRootPub = waref.RootPublicKey()

type outcome int

const (
	outcomeUnknown outcome = iota
	outcomeHandshakeCompleted
	outcomeServerRejected
	outcomeDialFailed
	outcomeTimeout
)

func (o outcome) String() string {
	switch o {
	case outcomeHandshakeCompleted:
		return "handshake-completed"
	case outcomeServerRejected:
		return "server-rejected"
	case outcomeDialFailed:
		return "dial-failed"
	case outcomeTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

func main() {
	endpoint := flag.String("endpoint", transport.DefaultURL, "WebSocket endpoint to probe")
	timeout := flag.Duration("timeout", 20*time.Second, "overall probe deadline")
	payload := flag.Bool("payload", false, "send a minimal synthetic ClientPayload in msg3 (still no auth)")
	printRoot := flag.Bool("root", false, "print the pinned root key and exit")
	flag.Parse()

	if *printRoot {
		fmt.Println(hex.EncodeToString(waRootPub))
		return
	}

	result, err := probe(context.Background(), *endpoint, *timeout, *payload)
	fmt.Printf("endpoint: %s\n", *endpoint)
	fmt.Printf("outcome:  %s\n", result.Outcome)
	if result.Detail != "" {
		fmt.Printf("detail:   %s\n", result.Detail)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	if result.Outcome == outcomeHandshakeCompleted {
		fmt.Println("interpretation: transport framing and Noise key schedule match the recorded findings")
	} else {
		fmt.Println("interpretation: the first diverging layer is reported above; record it as a finding")
	}
}

// Result is deliberately small so it can be pasted into a finding.
type Result struct {
	Outcome outcome
	Detail  string
}

func probe(ctx context.Context, endpoint string, timeout time.Duration, sendPayload bool) (Result, error) {
	return probeWithRoot(ctx, endpoint, timeout, sendPayload, waRootPub)
}

// probeWithRoot is probe with an injectable root key, so tests can run against
// a synthetic certificate chain while production pins the recorded constant.
func probeWithRoot(ctx context.Context, endpoint string, timeout time.Duration, sendPayload bool, rootPub []byte) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &transport.WebSocketDialer{HandshakeTimeoutOverride: timeout}
	fr, err := dialer.Dial(ctx, transport.Endpoint{
		URL:              endpoint,
		HandshakeTimeout: timeout,
		ExtraHeaders:     transport.DefaultEndpoint().ExtraHeaders,
	})
	if err != nil {
		return Result{Outcome: outcomeDialFailed, Detail: err.Error()}, err
	}
	defer func() { _ = fr.Close() }()

	// A fresh noise key pair stands in for the device identity: the probe only
	// needs a valid msg1/msg2 exchange, and nothing is persisted.
	noiseKey, err := noise.GenerateKeyPair()
	if err != nil {
		return Result{Outcome: outcomeUnknown, Detail: err.Error()}, err
	}

	var payload []byte
	if sendPayload {
		payload = syntheticPayload()
	}

	sc, err := noise.DoClientHandshake(ctx, fr, noiseKey, rootPub, payload)
	if err != nil {
		if ctx.Err() != nil {
			return Result{Outcome: outcomeTimeout, Detail: ctx.Err().Error()}, nil
		}
		return Result{Outcome: outcomeServerRejected, Detail: err.Error()}, nil
	}
	defer func() { _ = sc.Close() }()

	return Result{
		Outcome: outcomeHandshakeCompleted,
		Detail:  fmt.Sprintf("cipher suite %s established", sc.CipherSuiteName()),
	}, nil
}

// syntheticPayload is a minimal, obviously fake registration payload used only
// to exercise msg3. It carries no account material.
func syntheticPayload() []byte {
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return []byte("whatscore-probe")
	}
	return []byte("whatscore-probe:" + base64.RawURLEncoding.EncodeToString(buf[:]))
}
