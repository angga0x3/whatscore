package noise

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClientConnector(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientNoise, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverEph, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverStatic, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rootEd, rootMont := generateTestSigningKeypair(t)
	intEd, intMont := generateTestSigningKeypair(t)
	now := uint64(time.Now().Unix())
	certBlob := buildTestCertChain(t, buildTestCertChainOpts{
		rootEd: rootEd, intEd: intEd, intMont: intMont,
		leafKey: serverStatic.Pub[:], notBefore: now - 86400, notAfter: now + 86400,
	})

	clientPipe, serverPipe := newPipePair()
	go func() {
		_, _, _, _, _ = runTestServerHandshake(ctx, serverPipe, serverEph, serverStatic, certBlob)
	}()

	connector := &ClientConnector{Handshaker: &ClientHandshaker{
		NoiseKey:      clientNoise,
		RootPub:       rootMont[:],
		ClientPayload: []byte("payload"),
	}}
	conn, err := connector.Connect(ctx, clientPipe)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if conn == nil {
		t.Fatal("nil connection")
	}
	secure, ok := conn.(SecureConn)
	if !ok {
		t.Fatalf("connector returned %T, want SecureConn", conn)
	}
	if secure.CipherSuiteName() != CipherSuite {
		t.Fatalf("suite = %q", secure.CipherSuiteName())
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestClientConnectorNilHandshaker(t *testing.T) {
	client, _ := newPipePair()
	if _, err := (&ClientConnector{}).Connect(context.Background(), client); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("want ErrHandshakeFailed, got %v", err)
	}
	var nilConnector *ClientConnector
	if _, err := nilConnector.Connect(context.Background(), client); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("nil connector: %v", err)
	}
}
