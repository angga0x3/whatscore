package noise

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// msg2Timeout bounds the wait for the server's msg2 response when the
// caller supplies a context without a deadline (PF-007: whatsmeow uses a
// 20 second timeout for this step).
const msg2Timeout = 20 * time.Second

// DoClientHandshake runs the client role of the WhatsApp Noise-mode
// handshake over fr (PF-007), mirrors the reference implementation
// exactly, and returns a SecureConn carrying the session keys.
//
// Message sequence (PF-007; frames are plaintext, only inner fields are
// encrypted):
//
//	msg1  clientHello{ephemeral = client ephemeral pub}        (plaintext)
//	msg2  serverHello{ephemeral, static = Enc(server static), payload = Enc(cert chain)}
//	msg3  clientFinish{static = Enc(client noise pub), payload = Enc(clientPayload)}
//
// Key schedule (PF-004..PF-006, PF-008):
//
//	h0 = "Noise_XX_25519_AESGCM_SHA256\0\0\0\0" (raw 32 bytes)
//	Authenticate(connHeader), Authenticate(clientEph)
//	Authenticate(serverEph); mix ee = X25519(clientEph, serverEph)
//	Decrypt(server static); mix es = X25519(clientEph, serverStatic)
//	Decrypt(cert chain) and verify it (PF-009)
//	Encrypt(client noise pub); mix se = X25519(clientNoise, serverEph)
//	Encrypt(clientPayload); Finish
//
// If ctx has no deadline, a 20 second timeout is applied for the duration
// of the handshake (PF-007: the reference implementation bounds the msg2
// wait at 20 seconds). On any failure fr is closed before the error is
// returned; every error wraps a package sentinel (see §8.1 of the
// technical specification).
func DoClientHandshake(ctx context.Context, fr transport.FrameConn, noiseKey KeyPair, rootPub []byte, clientPayload []byte) (SecureConn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, msg2Timeout)
		defer cancel()
	}

	hs := NewHandshake()
	hs.Start(transport.IntroHeader)

	eph, err := GenerateKeyPair()
	if err != nil {
		return failHandshake(fr, fmt.Errorf("%w: generating client ephemeral key: %w", ErrHandshakeFailed, err))
	}
	hs.Authenticate(eph.Pub[:]) // PF-004: client ephemeral joins the chain before msg1

	msg1, err := proto.Marshal(&protobuf.HandshakeMessage{
		ClientHello: &protobuf.HandshakeMessage_ClientHello{Ephemeral: eph.Pub[:]},
	})
	if err != nil {
		return failHandshake(fr, fmt.Errorf("%w: marshaling client hello: %w", ErrHandshakeFailed, err))
	}
	if err := fr.WriteFrame(ctx, msg1); err != nil {
		return failHandshake(fr, fmt.Errorf("%w: writing client hello: %w", ErrHandshakeFailed, err))
	}

	resp, err := fr.ReadFrame(ctx)
	if err != nil {
		return failHandshake(fr, fmt.Errorf("%w: reading server hello: %w", ErrHandshakeFailed, err))
	}
	var hello protobuf.HandshakeMessage
	if err := proto.Unmarshal(resp, &hello); err != nil {
		return failHandshake(fr, fmt.Errorf("%w: unmarshaling server hello: %w", ErrInvalidServerHello, err))
	}
	serverHello := hello.GetServerHello()
	switch {
	case serverHello == nil:
		return failHandshake(fr, fmt.Errorf("%w: message has no serverHello", ErrInvalidServerHello))
	case len(serverHello.GetEphemeral()) != 32:
		return failHandshake(fr, fmt.Errorf("%w: serverHello.ephemeral must be 32 bytes, got %d",
			ErrInvalidServerHello, len(serverHello.GetEphemeral())))
	case serverHello.GetStatic() == nil:
		return failHandshake(fr, fmt.Errorf("%w: serverHello.static is missing", ErrInvalidServerHello))
	case serverHello.GetPayload() == nil:
		return failHandshake(fr, fmt.Errorf("%w: serverHello.payload is missing", ErrInvalidServerHello))
	}

	var serverEph [32]byte
	copy(serverEph[:], serverHello.GetEphemeral())
	hs.Authenticate(serverEph[:]) // PF-004: server ephemeral joins the chain before the first decrypt
	if err := hs.MixSharedSecretIntoKey(eph.Priv, serverEph); err != nil {
		return failHandshake(fr, fmt.Errorf("%w: mixing ee shared secret: %w", ErrHandshakeFailed, err))
	}

	serverStatic, err := hs.Decrypt(serverHello.GetStatic())
	if err != nil {
		return failHandshake(fr, fmt.Errorf("%w: decrypting serverHello.static: %w", ErrHandshakeFailed, err))
	}
	if len(serverStatic) != 32 {
		return failHandshake(fr, fmt.Errorf("%w: decrypted server static must be 32 bytes, got %d",
			ErrInvalidServerHello, len(serverStatic)))
	}
	var serverStaticKey [32]byte
	copy(serverStaticKey[:], serverStatic)
	if err := hs.MixSharedSecretIntoKey(eph.Priv, serverStaticKey); err != nil {
		return failHandshake(fr, fmt.Errorf("%w: mixing es shared secret: %w", ErrHandshakeFailed, err))
	}

	certBytes, err := hs.Decrypt(serverHello.GetPayload())
	if err != nil {
		return failHandshake(fr, fmt.Errorf("%w: decrypting serverHello.payload: %w", ErrHandshakeFailed, err))
	}
	if err := VerifyServerCert(certBytes, serverStaticKey[:], rootPub); err != nil {
		return failHandshake(fr, fmt.Errorf("%w: verifying server certificate: %w", ErrHandshakeFailed, err))
	}

	encStatic, err := hs.Encrypt(noiseKey.Pub[:])
	if err != nil {
		return failHandshake(fr, fmt.Errorf("%w: encrypting client static: %w", ErrHandshakeFailed, err))
	}
	if err := hs.MixSharedSecretIntoKey(noiseKey.Priv, serverEph); err != nil {
		return failHandshake(fr, fmt.Errorf("%w: mixing se shared secret: %w", ErrHandshakeFailed, err))
	}
	encPayload, err := hs.Encrypt(clientPayload)
	if err != nil {
		return failHandshake(fr, fmt.Errorf("%w: encrypting client payload: %w", ErrHandshakeFailed, err))
	}

	msg3, err := proto.Marshal(&protobuf.HandshakeMessage{
		ClientFinish: &protobuf.HandshakeMessage_ClientFinish{Static: encStatic, Payload: encPayload},
	})
	if err != nil {
		return failHandshake(fr, fmt.Errorf("%w: marshaling client finish: %w", ErrHandshakeFailed, err))
	}
	if err := fr.WriteFrame(ctx, msg3); err != nil {
		return failHandshake(fr, fmt.Errorf("%w: writing client finish: %w", ErrHandshakeFailed, err))
	}

	writeKey, readKey, err := hs.Finish()
	if err != nil {
		return failHandshake(fr, fmt.Errorf("%w: deriving transport keys: %w", ErrHandshakeFailed, err))
	}
	sc, err := newSecureConn(fr, writeKey, readKey)
	if err != nil {
		return failHandshake(fr, err)
	}
	return sc, nil
}

// failHandshake enforces the Handshaker contract: on failure the frame
// connection is closed before the error is returned.
func failHandshake(fr transport.FrameConn, err error) (SecureConn, error) {
	_ = fr.Close()
	return nil, err
}

// ClientHandshaker adapts DoClientHandshake to the Handshaker interface
// by binding the client identity material: the long-lived Noise key pair,
// the pinned server root public key (PF-009), and the protobuf
// ClientPayload to send inside msg3 (PF-007).
type ClientHandshaker struct {
	// NoiseKey is the client's long-lived Curve25519 key pair. Its public
	// half is encrypted into msg3.static; its private half participates in
	// the final DH (PF-006, PF-007).
	NoiseKey KeyPair

	// RootPub is the pinned 32-byte Curve25519 server root public key used
	// to verify the certificate chain (PF-009).
	RootPub []byte

	// ClientPayload is the protobuf-serialized payload sent (encrypted)
	// inside msg3.payload (PF-007).
	ClientPayload []byte
}

// Handshake implements the Handshaker interface (PF-007).
func (c *ClientHandshaker) Handshake(ctx context.Context, fr transport.FrameConn) (SecureConn, error) {
	return DoClientHandshake(ctx, fr, c.NoiseKey, c.RootPub, c.ClientPayload)
}
