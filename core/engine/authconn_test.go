package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// TestAuthConnectorWaitsForVerdict proves the connector does not report a
// healthy connection before the server answers the payload.
func TestAuthConnectorWaitsForVerdict(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	dialer := newFakeDialer(serveAfterHandshake(fs, &binary.Node{Tag: "success"}))
	crew, err := New(engineConfig(fs, dialer, t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dialer.Dial(ctx, transport.Endpoint{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	encrypted, err := crew.AuthConnector().Connect(ctx, raw)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if encrypted == nil {
		t.Fatal("nil connection")
	}
	if err := encrypted.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestAuthConnectorRejectsFailure proves a rejected payload becomes an error
// instead of a connected session.
func TestAuthConnectorRejectsFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	dialer := newFakeDialer(serveAfterHandshake(fs, &binary.Node{
		Tag:   "failure",
		Attrs: binary.Attrs{"reason": "401", "message": "not authorized"},
	}))
	crew, err := New(engineConfig(fs, dialer, t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dialer.Dial(ctx, transport.Endpoint{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if _, err := crew.AuthConnector().Connect(ctx, raw); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

// TestAuthConnectorStreamError covers the stream:error path.
func TestAuthConnectorStreamError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	dialer := newFakeDialer(serveAfterHandshake(fs, &binary.Node{
		Tag:      "stream:error",
		Attrs:    binary.Attrs{"code": "515"},
		Children: []binary.Node{{Tag: "conflict", Attrs: binary.Attrs{"type": "replaced"}}},
	}))
	crew, err := New(engineConfig(fs, dialer, t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dialer.Dial(ctx, transport.Endpoint{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if _, err := crew.AuthConnector().Connect(ctx, raw); !errors.Is(err, ErrStreamError) {
		t.Fatalf("want ErrStreamError, got %v", err)
	}
}

// TestAuthConnectorSkipsAck proves a benign ack does not end the wait.
func TestAuthConnectorSkipsAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	dialer := newFakeDialer(serveAfterHandshake(fs, &binary.Node{Tag: "ack"}, &binary.Node{Tag: "success"}))
	crew, err := New(engineConfig(fs, dialer, t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dialer.Dial(ctx, transport.Endpoint{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	encrypted, err := crew.AuthConnector().Connect(ctx, raw)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_ = encrypted.Close()
}
