package noise

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// runTestServerHandshake implements the server role of the PF-007
// handshake using the public Handshake state machine, mirroring the
// client flow:
//
//	read msg1 → Authenticate(clientEph)
//	mix ee = X25519(serverEph, clientEph)
//	Encrypt(server static); mix es = X25519(serverStatic, clientEph)
//	Encrypt(cert blob)
//	write msg2
//	read msg3 → Decrypt(client static), Decrypt(client payload)
//	mix se = X25519(serverEph, client static)
//	Finish (swapped write/read at usage, PF-008)
//
// It returns the raw Finish halves plus the decrypted client static and
// payload for assertions.
func runTestServerHandshake(ctx context.Context, fr transport.FrameConn, serverEph, serverStatic KeyPair, certBlob []byte) (rawWrite, rawRead [32]byte, clientStatic, clientPayload []byte, err error) {
	msg1, err := fr.ReadFrame(ctx)
	if err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	var m protobuf.HandshakeMessage
	if err := proto.Unmarshal(msg1, &m); err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	clientEphBytes := m.GetClientHello().GetEphemeral()
	if len(clientEphBytes) != 32 {
		return rawWrite, rawRead, nil, nil, errors.New("bad client ephemeral length")
	}
	var clientEph [32]byte
	copy(clientEph[:], clientEphBytes)

	hs := NewHandshake()
	hs.Start(transport.IntroHeader)
	hs.Authenticate(clientEph[:])
	hs.Authenticate(serverEph.Pub[:])
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientEph); err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	encStatic, err := hs.Encrypt(serverStatic.Pub[:])
	if err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	if err := hs.MixSharedSecretIntoKey(serverStatic.Priv, clientEph); err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	encPayload, err := hs.Encrypt(certBlob)
	if err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	msg2, err := proto.Marshal(&protobuf.HandshakeMessage{
		ServerHello: &protobuf.HandshakeMessage_ServerHello{
			Ephemeral: serverEph.Pub[:],
			Static:    encStatic,
			Payload:   encPayload,
		},
	})
	if err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	if err := fr.WriteFrame(ctx, msg2); err != nil {
		return rawWrite, rawRead, nil, nil, err
	}

	msg3, err := fr.ReadFrame(ctx)
	if err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	if err := proto.Unmarshal(msg3, &m); err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	finish := m.GetClientFinish()
	clientStatic, err = hs.Decrypt(finish.GetStatic())
	if err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	// Mirror the client exactly: it mixes se between encrypting its static
	// and encrypting the payload, so the server must mix between the two
	// decrypts.
	var clientStaticKey [32]byte
	copy(clientStaticKey[:], clientStatic)
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientStaticKey); err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	clientPayload, err = hs.Decrypt(finish.GetPayload())
	if err != nil {
		return rawWrite, rawRead, nil, nil, err
	}
	rawWrite, rawRead, err = hs.Finish()
	return rawWrite, rawRead, clientStatic, clientPayload, err
}

// TestHandshakeRoundTrip runs the full PF-007 handshake between
// DoClientHandshake and the in-test server role over an in-memory pipe,
// then exchanges encrypted frames in both directions (PF-008) and rejects
// a corrupted ciphertext.
func TestHandshakeRoundTrip(t *testing.T) {
	ctx := context.Background()

	clientNoise, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("client noise key: %v", err)
	}
	serverEph, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server ephemeral key: %v", err)
	}
	serverStatic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server static key: %v", err)
	}

	// Synthetic test-root certificate chain binding the server static key
	// (PF-009; helpers from cert_test.go).
	rootEd, rootMont := generateTestSigningKeypair(t)
	intEd, intMont := generateTestSigningKeypair(t)
	now := uint64(time.Now().Unix())
	certBlob := buildTestCertChain(t, buildTestCertChainOpts{
		rootEd:    rootEd,
		intEd:     intEd,
		intMont:   intMont,
		leafKey:   serverStatic.Pub[:],
		notBefore: now - 86400,
		notAfter:  now + 86400,
	})

	clientPipe, serverPipe := newPipePair()

	type serverResult struct {
		rawWrite, rawRead [32]byte
		clientStatic      []byte
		clientPayload     []byte
		err               error
	}
	serverDone := make(chan serverResult, 1)
	go func() {
		w, r, cs, cp, err := runTestServerHandshake(ctx, serverPipe, serverEph, serverStatic, certBlob)
		serverDone <- serverResult{w, r, cs, cp, err}
	}()

	sc, err := DoClientHandshake(ctx, clientPipe, clientNoise, rootMont[:], []byte(`{"connect":"synthetic"}`))
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	scImpl, ok := sc.(*secureConn)
	if !ok {
		t.Fatalf("DoClientHandshake returned %T, want *secureConn", sc)
	}

	res := <-serverDone
	if res.err != nil {
		t.Fatalf("server handshake failed: %v", res.err)
	}
	if !bytes.Equal(res.clientStatic, clientNoise.Pub[:]) {
		t.Fatalf("server decrypted client static mismatch: %x", res.clientStatic)
	}
	if string(res.clientPayload) != `{"connect":"synthetic"}` {
		t.Fatalf("server decrypted client payload mismatch: %x", res.clientPayload)
	}

	// PF-008 key agreement: both roles compute identical HKDF halves; the
	// server uses them swapped.
	if scImpl.writeKey != res.rawWrite {
		t.Fatal("client write key must equal the raw write half the server derived")
	}
	if scImpl.readKey != res.rawRead {
		t.Fatal("client read key must equal the raw read half the server derived")
	}

	serverSC, err := newSecureConn(serverPipe, res.rawRead, res.rawWrite) // swapped
	if err != nil {
		t.Fatalf("server secure conn: %v", err)
	}
	if sc.CipherSuiteName() != CipherSuite {
		t.Fatalf("CipherSuiteName = %q, want %q", sc.CipherSuiteName(), CipherSuite)
	}

	// Encrypted frames flow both ways, in order (PF-008).
	c2s1 := []byte("first client frame")
	c2s2 := []byte("second client frame")
	if err := sc.WriteFrame(ctx, c2s1); err != nil {
		t.Fatalf("client write 1: %v", err)
	}
	if err := sc.WriteFrame(ctx, c2s2); err != nil {
		t.Fatalf("client write 2: %v", err)
	}
	got1, err := serverSC.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("server read 1: %v", err)
	}
	got2, err := serverSC.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("server read 2: %v", err)
	}
	if !bytes.Equal(got1, c2s1) || !bytes.Equal(got2, c2s2) {
		t.Fatalf("server reads out of order: %q, %q", got1, got2)
	}

	s2c := []byte("server reply")
	if err := serverSC.WriteFrame(ctx, s2c); err != nil {
		t.Fatalf("server write: %v", err)
	}
	got, err := sc.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(got, s2c) {
		t.Fatalf("client read mismatch: %q", got)
	}
	if scImpl.writeCounter != 2 || scImpl.readCounter != 1 || serverSC.writeCounter != 1 || serverSC.readCounter != 2 {
		t.Fatalf("unexpected counters: client w=%d r=%d, server w=%d r=%d",
			scImpl.writeCounter, scImpl.readCounter, serverSC.writeCounter, serverSC.readCounter)
	}

	// A corrupted ciphertext must be rejected (PF-008 authentication).
	corrupted := append([]byte{}, s2c...)
	corrupted[0] ^= 0x01
	clientPipe.inject(corrupted)
	if _, err := sc.ReadFrame(ctx); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("corrupted frame: want ErrDecryptFailed, got %v", err)
	}

	if err := sc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := serverSC.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// evilServerAction selects what the failing server answers with.
type evilServerAction int

const (
	evilEmptyMessage   evilServerAction = iota // msg2 = empty HandshakeMessage
	evilShortEphemeral                         // msg2 = serverHello with a short ephemeral
	evilSilent                                 // no answer at all
)

// runEvilServer reads msg1 and answers with the selected malformed msg2.
func runEvilServer(ctx context.Context, fr transport.FrameConn, action evilServerAction) {
	if _, err := fr.ReadFrame(ctx); err != nil {
		return
	}
	switch action {
	case evilSilent:
		return
	case evilEmptyMessage:
		_ = fr.WriteFrame(ctx, nil) // empty HandshakeMessage: no serverHello
	case evilShortEphemeral:
		msg2, merr := proto.Marshal(&protobuf.HandshakeMessage{
			ServerHello: &protobuf.HandshakeMessage_ServerHello{
				Ephemeral: []byte{1, 2, 3},
				Static:    []byte{4},
				Payload:   []byte{5},
			},
		})
		if merr != nil {
			return
		}
		_ = fr.WriteFrame(ctx, msg2)
	}
}

// TestDoClientHandshakeErrors is table-driven over malformed msg2
// responses; every failure must wrap the right sentinel and close the
// frame connection (the Handshaker contract). The wrong-root and
// garbled-static cases need a custom server reply and run as subtests
// below.
func TestDoClientHandshakeErrors(t *testing.T) {
	clientNoise, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("client noise key: %v", err)
	}
	rootEd, rootMont := generateTestSigningKeypair(t)

	malformed := []struct {
		name    string
		action  evilServerAction
		wantErr error
	}{
		{name: "no serverHello", action: evilEmptyMessage, wantErr: ErrInvalidServerHello},
		{name: "short serverHello.ephemeral", action: evilShortEphemeral, wantErr: ErrInvalidServerHello},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			clientPipe, serverPipe := newPipePair()
			go runEvilServer(ctx, serverPipe, tc.action)
			_, err := DoClientHandshake(ctx, clientPipe, clientNoise, rootMont[:], nil)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
			assertPipeClosed(t, clientPipe)
		})
	}

	t.Run("silent server respects ctx deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		clientPipe, serverPipe := newPipePair()
		go runEvilServer(ctx, serverPipe, evilSilent)
		start := time.Now()
		_, err := DoClientHandshake(ctx, clientPipe, clientNoise, rootMont[:], nil)
		if err == nil {
			t.Fatal("silent server must fail the handshake")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("handshake must honor the caller deadline, took %s", elapsed)
		}
		if !errors.Is(err, ErrHandshakeFailed) {
			t.Fatalf("want ErrHandshakeFailed, got %v", err)
		}
		assertPipeClosed(t, clientPipe)
	})

	t.Run("wrong root", func(t *testing.T) {
		ctx := context.Background()
		serverEph, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		serverStatic, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		intEd, intMont := generateTestSigningKeypair(t)
		now := uint64(time.Now().Unix())
		certBlob := buildTestCertChain(t, buildTestCertChainOpts{
			rootEd:    rootEd,
			intEd:     intEd,
			intMont:   intMont,
			leafKey:   serverStatic.Pub[:],
			notBefore: now - 86400,
			notAfter:  now + 86400,
		})

		otherRoot := rootMont
		otherRoot[0] ^= 0x01

		clientPipe, serverPipe := newPipePair()
		go func() {
			_, _, _, _, _ = runTestServerHandshake(ctx, serverPipe, serverEph, serverStatic, certBlob)
		}()
		_, err = DoClientHandshake(ctx, clientPipe, clientNoise, otherRoot[:], nil)
		if !errors.Is(err, ErrCertificateInvalid) {
			t.Fatalf("want ErrCertificateInvalid, got %v", err)
		}
		if !errors.Is(err, ErrHandshakeFailed) {
			t.Fatalf("cert failures must also wrap ErrHandshakeFailed, got %v", err)
		}
		assertPipeClosed(t, clientPipe)
	})

	t.Run("garbled static ciphertext", func(t *testing.T) {
		ctx := context.Background()
		serverEph, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		clientPipe, serverPipe := newPipePair()
		go func() {
			// Server up to the same hash state as an honest msg2, but then
			// seals garbage instead of the real server static: the client
			// must abort with ErrDecryptFailed.
			msg1, rerr := serverPipe.ReadFrame(ctx)
			if rerr != nil {
				return
			}
			var m protobuf.HandshakeMessage
			if uerr := proto.Unmarshal(msg1, &m); uerr != nil {
				return
			}
			var clientEph [32]byte
			copy(clientEph[:], m.GetClientHello().GetEphemeral())
			hs := NewHandshake()
			hs.Start(transport.IntroHeader)
			hs.Authenticate(clientEph[:])
			hs.Authenticate(serverEph.Pub[:])
			if merr := hs.MixSharedSecretIntoKey(serverEph.Priv, clientEph); merr != nil {
				return
			}
			msg2, merr := proto.Marshal(&protobuf.HandshakeMessage{
				ServerHello: &protobuf.HandshakeMessage_ServerHello{
					Ephemeral: serverEph.Pub[:],
					Static:    []byte("garbage that will never authenticate"),
					Payload:   []byte("garbage"),
				},
			})
			if merr != nil {
				return
			}
			_ = serverPipe.WriteFrame(ctx, msg2)
		}()
		_, err = DoClientHandshake(ctx, clientPipe, clientNoise, rootMont[:], nil)
		if !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("want ErrDecryptFailed, got %v", err)
		}
		assertPipeClosed(t, clientPipe)
	})
}

// assertPipeClosed asserts a failed handshake closed the FrameConn.
func assertPipeClosed(t *testing.T, p *pipeConn) {
	t.Helper()
	select {
	case <-p.closed:
	default:
		t.Fatal("failed handshake must close the frame connection")
	}
}
