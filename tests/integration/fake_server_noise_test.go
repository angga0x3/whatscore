//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// This file is the tier-2 fake-server test from docs/architecture/
// technical-specification.md §6: a real WebSocket connection, the
// production client handshake, and a server role implemented from the
// PF-007/PF-009 findings. It proves the findings end to end over the
// actual transport rather than over an in-memory pipe:
//
//	transport framing (PF-003) → Noise handshake (PF-004..PF-009) →
//	encrypted frame exchange (PF-008)
//
// The server side deliberately re-implements framing and post-handshake
// AEAD locally instead of reusing package internals: an integration test
// that shared the client's helpers would only prove the code agrees with
// itself.

const (
	fakeServerClientPayload = `{"connect":"integration-fake-server"}`
	fakeServerRequest       = "hello from the integration client"
	fakeServerResponse      = "hello from the fake whatsapp server"
)

// TestFakeServerHandshakeRoundTrip runs dial → Noise handshake → encrypted
// frames against a fake WhatsApp-style server over a real WebSocket.
func TestFakeServerHandshakeRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	clientNoise, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client noise key: %v", err)
	}
	serverEph, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("server ephemeral key: %v", err)
	}
	serverStatic, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("server static key: %v", err)
	}

	rootEd, rootMont := integrationSigningKeypair(t)
	intEd, intMont := integrationSigningKeypair(t)
	certBlob := integrationCertChain(t, rootEd, intEd, intMont, serverStatic.Pub[:])

	serverErr := make(chan error, 1)
	srv := newFakeServer(t, func(ws *websocket.Conn) error {
		return runFakeServer(ctx, ws, serverEph, serverStatic, certBlob, clientNoise.Pub[:])
	}, serverErr)

	fc, err := (&transport.WebSocketDialer{}).Dial(ctx, transport.Endpoint{
		URL:              wsURL(srv.URL),
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial fake server: %v", err)
	}
	defer func() { _ = fc.Close() }()

	sc, err := noise.DoClientHandshake(ctx, fc, clientNoise, rootMont[:], []byte(fakeServerClientPayload))
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer func() { _ = sc.Close() }()

	if got := sc.CipherSuiteName(); got != noise.CipherSuite {
		t.Fatalf("CipherSuiteName = %q, want %q", got, noise.CipherSuite)
	}

	if err := sc.WriteFrame(ctx, []byte(fakeServerRequest)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("fake server: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("fake server did not finish: context expired")
	}

	got, err := sc.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != fakeServerResponse {
		t.Fatalf("client read = %q, want %q", got, fakeServerResponse)
	}
}

// runFakeServer implements the server role of PF-007 (msg1→msg3), verifies
// the certificate chain it presents, derives the PF-008 keys, and exchanges
// one encrypted frame in each direction.
func runFakeServer(ctx context.Context, ws *websocket.Conn, serverEph, serverStatic noise.KeyPair, certBlob, wantClientStatic []byte) error {
	fc := newServerFrameConn(ws)

	msg1, err := fc.ReadFrame(ctx)
	if err != nil {
		return fmt.Errorf("read client hello: %w", err)
	}
	var hello protobuf.HandshakeMessage
	if err := proto.Unmarshal(msg1, &hello); err != nil {
		return fmt.Errorf("unmarshal client hello: %w", err)
	}
	clientEphBytes := hello.GetClientHello().GetEphemeral()
	if len(clientEphBytes) != 32 {
		return fmt.Errorf("client ephemeral must be 32 bytes, got %d", len(clientEphBytes))
	}
	var clientEph [32]byte
	copy(clientEph[:], clientEphBytes)

	hs := noise.NewHandshake()
	hs.Start(transport.IntroHeader)
	hs.Authenticate(clientEph[:])
	hs.Authenticate(serverEph.Pub[:])
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientEph); err != nil {
		return fmt.Errorf("mix ee: %w", err)
	}
	encStatic, err := hs.Encrypt(serverStatic.Pub[:])
	if err != nil {
		return fmt.Errorf("encrypt server static: %w", err)
	}
	if err := hs.MixSharedSecretIntoKey(serverStatic.Priv, clientEph); err != nil {
		return fmt.Errorf("mix es: %w", err)
	}
	encPayload, err := hs.Encrypt(certBlob)
	if err != nil {
		return fmt.Errorf("encrypt cert chain: %w", err)
	}

	msg2, err := proto.Marshal(&protobuf.HandshakeMessage{
		ServerHello: &protobuf.HandshakeMessage_ServerHello{
			Ephemeral: serverEph.Pub[:],
			Static:    encStatic,
			Payload:   encPayload,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal server hello: %w", err)
	}
	if err := fc.WriteFrame(ctx, msg2); err != nil {
		return fmt.Errorf("write server hello: %w", err)
	}

	msg3, err := fc.ReadFrame(ctx)
	if err != nil {
		return fmt.Errorf("read client finish: %w", err)
	}
	var finishMsg protobuf.HandshakeMessage
	if err := proto.Unmarshal(msg3, &finishMsg); err != nil {
		return fmt.Errorf("unmarshal client finish: %w", err)
	}
	finish := finishMsg.GetClientFinish()
	clientStatic, err := hs.Decrypt(finish.GetStatic())
	if err != nil {
		return fmt.Errorf("decrypt client static: %w", err)
	}
	if !bytes.Equal(clientStatic, wantClientStatic) {
		return fmt.Errorf("client static mismatch: got %x, want %x", clientStatic, wantClientStatic)
	}

	// Mirror the client exactly: it mixes se between encrypting its static
	// and encrypting the payload, so the server mixes between the two
	// decrypts.
	var clientStaticKey [32]byte
	copy(clientStaticKey[:], clientStatic)
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientStaticKey); err != nil {
		return fmt.Errorf("mix se: %w", err)
	}

	payload, err := hs.Decrypt(finish.GetPayload())
	if err != nil {
		return fmt.Errorf("decrypt client payload: %w", err)
	}
	if string(payload) != fakeServerClientPayload {
		return fmt.Errorf("client payload = %q, want %q", payload, fakeServerClientPayload)
	}

	rawWrite, rawRead, err := hs.Finish()
	if err != nil {
		return fmt.Errorf("derive transport keys: %w", err)
	}

	// PF-008: the server perspective swaps the client's write/read halves.
	secure, err := newServerSecureConn(fc, rawRead, rawWrite)
	if err != nil {
		return err
	}

	got, err := secure.ReadFrame(ctx)
	if err != nil {
		return fmt.Errorf("read encrypted frame: %w", err)
	}
	if string(got) != fakeServerRequest {
		return fmt.Errorf("request = %q, want %q", got, fakeServerRequest)
	}
	if err := secure.WriteFrame(ctx, []byte(fakeServerResponse)); err != nil {
		return fmt.Errorf("write encrypted frame: %w", err)
	}
	return nil
}

// newFakeServer starts an httptest WebSocket server running handler for each
// accepted connection and reports its outcome on errCh.
func newFakeServer(t *testing.T, handler func(*websocket.Conn) error, errCh chan<- error) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, http.Header(nil))
		if err != nil {
			errCh <- fmt.Errorf("upgrade: %w", err)
			return
		}
		defer func() { _ = ws.Close() }()
		errCh <- handler(ws)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(srv.CloseClientConnections)
	return srv
}

func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}

// serverFrameConn is the fake server's independent implementation of the
// PF-003 frame stream: it consumes the one-time intro header, reassembles
// 3-byte-length frames across WebSocket messages, and writes one frame per
// binary message.
type serverFrameConn struct {
	ws    *websocket.Conn
	mu    sync.Mutex
	buf   []byte
	intro bool
}

func newServerFrameConn(ws *websocket.Conn) *serverFrameConn {
	return &serverFrameConn{ws: ws}
}

func (c *serverFrameConn) ReadFrame(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		if !c.intro {
			if len(c.buf) < len(transport.IntroHeader) {
				if err := c.readMore(ctx); err != nil {
					return nil, err
				}
				continue
			}
			if !bytes.Equal(c.buf[:len(transport.IntroHeader)], transport.IntroHeader) {
				return nil, fmt.Errorf("bad intro header %x", c.buf[:len(transport.IntroHeader)])
			}
			c.buf = c.buf[len(transport.IntroHeader):]
			c.intro = true
		}

		if len(c.buf) >= 3 {
			n := int(c.buf[0])<<16 | int(c.buf[1])<<8 | int(c.buf[2])
			if len(c.buf) >= 3+n {
				frame := append([]byte(nil), c.buf[3:3+n]...)
				c.buf = c.buf[3+n:]
				return frame, nil
			}
		}
		if err := c.readMore(ctx); err != nil {
			return nil, err
		}
	}
}

func (c *serverFrameConn) readMore(ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.ws.SetReadDeadline(deadline)
	} else {
		_ = c.ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	msgType, data, err := c.ws.ReadMessage()
	if err != nil {
		return fmt.Errorf("read websocket message: %w", err)
	}
	if msgType != websocket.BinaryMessage {
		return fmt.Errorf("unexpected websocket message type %d", msgType)
	}
	c.buf = append(c.buf, data...)
	return nil
}

func (c *serverFrameConn) WriteFrame(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	if len(frame) >= transport.FrameMaxSize {
		return fmt.Errorf("write frame: %w", transport.ErrFrameTooLarge)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	msg := make([]byte, 0, 3+len(frame))
	n := len(frame)
	msg = append(msg, byte(n>>16), byte(n>>8), byte(n))
	msg = append(msg, frame...)
	return c.ws.WriteMessage(websocket.BinaryMessage, msg)
}

func (c *serverFrameConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.Close()
}

// serverSecureConn is the fake server's post-handshake AEAD layer (PF-008):
// per-direction AES-256-GCM keys, counter nonces, empty AAD.
type serverSecureConn struct {
	fr        transport.FrameConn
	writeAEAD cipher.AEAD
	readAEAD  cipher.AEAD
	writeCtr  uint32
	readCtr   uint32
	mu        sync.Mutex
}

func newServerSecureConn(fr transport.FrameConn, writeKey, readKey [32]byte) (*serverSecureConn, error) {
	writeAEAD, err := newServerAEAD(writeKey)
	if err != nil {
		return nil, fmt.Errorf("server write key: %w", err)
	}
	readAEAD, err := newServerAEAD(readKey)
	if err != nil {
		return nil, fmt.Errorf("server read key: %w", err)
	}
	return &serverSecureConn{fr: fr, writeAEAD: writeAEAD, readAEAD: readAEAD}, nil
}

func newServerAEAD(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *serverSecureConn) ReadFrame(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ct, err := c.fr.ReadFrame(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := c.readAEAD.Open(nil, serverFrameIV(c.readCtr), ct, nil)
	if err != nil {
		return nil, fmt.Errorf("server frame %d: %w", c.readCtr, err)
	}
	c.readCtr++
	return pt, nil
}

func (c *serverSecureConn) WriteFrame(ctx context.Context, plaintext []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ct := c.writeAEAD.Seal(nil, serverFrameIV(c.writeCtr), plaintext, nil)
	c.writeCtr++
	return c.fr.WriteFrame(ctx, ct)
}

func serverFrameIV(counter uint32) []byte {
	iv := make([]byte, 12)
	binary.BigEndian.PutUint32(iv[8:12], counter)
	return iv
}

// synthetic chain helpers -------------------------------------------------
//
// PF-009 fixes the chain shape. These helpers build a two-certificate
// chain signed by a throwaway Ed25519 root, with all keys generated from
// crypto/rand per test run — nothing here is or was a real credential.

var integrationP25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

func integrationCertChain(t *testing.T, rootEd, intEd ed25519.PrivateKey, intMont [32]byte, leafKey []byte) []byte {
	t.Helper()
	now := uint64(time.Now().Unix())
	intDetails := integrationCertDetails(t, 1, 0, intMont[:], now-86400, now+86400)
	leafDetails := integrationCertDetails(t, 2, 1, leafKey, now-86400, now+86400)
	raw, err := proto.Marshal(&protobuf.CertChain{
		Leaf:         &protobuf.CertChain_NoiseCertificate{Details: leafDetails, Signature: ed25519.Sign(intEd, leafDetails)},
		Intermediate: &protobuf.CertChain_NoiseCertificate{Details: intDetails, Signature: ed25519.Sign(rootEd, intDetails)},
	})
	if err != nil {
		t.Fatalf("marshal cert chain: %v", err)
	}
	return raw
}

func integrationCertDetails(t *testing.T, serial, issuerSerial uint32, key []byte, notBefore, notAfter uint64) []byte {
	t.Helper()
	s, i := serial, issuerSerial
	nb, na := notBefore, notAfter
	raw, err := proto.Marshal(&protobuf.CertChain_NoiseCertificate_Details{
		Serial:       &s,
		IssuerSerial: &i,
		Key:          append([]byte(nil), key...),
		NotBefore:    &nb,
		NotAfter:     &na,
	})
	if err != nil {
		t.Fatalf("marshal cert details: %v", err)
	}
	return raw
}

// integrationSigningKeypair returns an Ed25519 key pair whose public point
// has an even Edwards x coordinate, plus the matching Montgomery u
// coordinate the certificate details carry (PF-009). The production
// verifier converts Montgomery→Edwards, so the pair must survive that
// conversion: the self-check below applies the same map the client uses.
func integrationSigningKeypair(t *testing.T) (ed25519.PrivateKey, [32]byte) {
	t.Helper()
	for attempt := 0; attempt < 1000; attempt++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 keygen: %v", err)
		}
		if pub[31]&0x80 != 0 {
			continue // odd Edwards x: the conversion would clear the sign bit
		}

		yBytes := make([]byte, 32)
		for i := range pub {
			yBytes[i] = pub[31-i]
		}
		yBytes[31] &= 0x7f
		y := new(big.Int).SetBytes(yBytes)

		denom := new(big.Int).Sub(big.NewInt(1), y)
		denom.Mod(denom, integrationP25519)
		if denom.Sign() == 0 {
			continue
		}
		inv := new(big.Int).ModInverse(denom, integrationP25519)
		if inv == nil {
			continue
		}
		u := new(big.Int).Mul(new(big.Int).Add(big.NewInt(1), y), inv)
		u.Mod(u, integrationP25519)
		uPlus1 := new(big.Int).Add(u, big.NewInt(1))
		uPlus1.Mod(uPlus1, integrationP25519)
		if uPlus1.Sign() == 0 {
			continue
		}

		var mont [32]byte
		ube := u.FillBytes(make([]byte, 32))
		for i := range ube {
			mont[i] = ube[31-i]
		}

		// Self-check: the reverse map must reproduce the verified Edwards
		// point for a signature made with this key.
		msg := []byte("whatscore integration fake-server key self-check")
		if !ed25519.Verify(edwardsYFromMontgomery(mont), msg, ed25519.Sign(priv, msg)) {
			continue
		}
		return priv, mont
	}
	t.Fatal("could not generate a usable XEdDSA keypair in 1000 attempts")
	return nil, [32]byte{}
}

// edwardsYFromMontgomery implements y = (u−1)/(u+1) mod p, the PF-009
// Montgomery→Edwards conversion, encoded little-endian with the sign bit
// cleared.
func edwardsYFromMontgomery(mont [32]byte) ed25519.PublicKey {
	uBytes := make([]byte, 32)
	for i := range mont {
		uBytes[i] = mont[31-i]
	}
	u := new(big.Int).SetBytes(uBytes)
	uPlus1 := new(big.Int).Add(u, big.NewInt(1))
	uPlus1.Mod(uPlus1, integrationP25519)
	inv := new(big.Int).ModInverse(uPlus1, integrationP25519)
	if inv == nil {
		return nil
	}
	y := new(big.Int).Mul(new(big.Int).Sub(u, big.NewInt(1)), inv)
	y.Mod(y, integrationP25519)
	be := y.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := range be {
		out[i] = be[31-i]
	}
	out[31] &= 0x7f
	return out
}
