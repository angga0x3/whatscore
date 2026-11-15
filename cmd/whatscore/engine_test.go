package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	binenc "encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/config"
	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/core/session"
	"github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	"github.com/angga0x3/whatscore/protocol/transport"
	storagecredentials "github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
)

// This file exercises the factory and its connector wrapper without touching
// the network. The fake dialer returns one end of an in-memory frame pipe and
// runs the server side of the Noise handshake on the other, so a session walks
// the same dial → handshake → CONNECTED path it walks against WhatsApp.

// fakeDialer hands out in-memory connections and runs a fake WhatsApp server on
// each one. It records how often it was asked to dial.
type fakeDialer struct {
	rootEd   ed25519.PrivateKey
	rootMont [32]byte
	intEd    ed25519.PrivateKey
	intMont  [32]byte
	tb       testing.TB

	mu    sync.Mutex
	dials int
	// dialErr, when set, makes every Dial fail before a connection exists.
	dialErr error
	// noVerdict suppresses the post-handshake auth stanza, for tests that
	// want the session to stay in CONNECTING.
	noVerdict bool
	// rejectAuth, when set, is sent instead of <success/> so a test can prove
	// a rejected payload never becomes CONNECTED.
	rejectAuth *binary.Node
	// peerErr receives the server-side handshake outcome.
	peerErr chan error
	// release keeps an established connection open until the test ends; a
	// peer that hung up immediately would race the CONNECTED assertion.
	release chan struct{}
}

func newFakeDialer(t *testing.T) *fakeDialer {
	t.Helper()
	rootEd, rootMont := testSigningKeypair(t)
	intEd, intMont := testSigningKeypair(t)
	return &fakeDialer{
		rootEd:   rootEd,
		rootMont: rootMont,
		intEd:    intEd,
		intMont:  intMont,
		tb:       t,
		peerErr:  make(chan error, 4),
		release:  make(chan struct{}),
	}
}

// Dial implements transport.Dialer.
func (d *fakeDialer) Dial(ctx context.Context, _ transport.Endpoint) (transport.FrameConn, error) {
	d.mu.Lock()
	d.dials++
	dialErr := d.dialErr
	d.mu.Unlock()
	if dialErr != nil {
		return nil, dialErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	client, server := newPipePair()
	serverEph, err := noise.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	serverStatic, err := noise.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	certBlob := testCertChain(d.tb, d.rootEd, d.intEd, d.intMont, serverStatic.Pub[:])

	go func() {
		srv, err := serveHandshake(ctx, server, serverEph, serverStatic, certBlob)
		// Report the handshake outcome before holding the connection open:
		// the test waits on this channel while the session is still connected.
		d.peerErr <- err
		if err == nil && !d.noVerdict {
			// The session waits for the post-handshake verdict before it
			// reports CONNECTED, so the fake server must send one.
			verdict := d.rejectAuth
			if writeErr := serveAuthVerdict(ctx, srv, verdict); writeErr != nil {
				d.peerErr <- writeErr
				_ = server.Close()
				return
			}
		}
		if err == nil {
			// Hold the connection open, dropping whatever the client writes,
			// until the test releases it.
			select {
			case <-d.release:
			case <-ctx.Done():
			}
		}
		_ = server.Close()
	}()
	return client, nil
}

func (d *fakeDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

// serveAuthVerdict answers the client payload the way the real server does
// before a session may be considered connected (PF-028). The stanza travels
// inside the negotiated cipher, so this reuses the same server-side frame
// layer the handshake produced.
func serveAuthVerdict(ctx context.Context, srv *serverNodeConn, reject *binary.Node) error {
	if srv == nil {
		return errors.New("no server connection")
	}
	success := &binary.Node{Tag: "success"}
	if reject != nil {
		success = reject
	}
	for _, node := range []*binary.Node{{Tag: "ack"}, success} {
		if err := srv.writeNode(ctx, node); err != nil {
			return err
		}
	}
	return nil
}

// serveHandshake is the server half of PF-007: read msg1, answer msg2 with a
// certificate chain signed by the injected root, decrypt msg3.
func serveHandshake(ctx context.Context, fc transport.FrameConn, serverEph, serverStatic noise.KeyPair, certBlob []byte) (*serverNodeConn, error) {
	msg1, err := fc.ReadFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("read client hello: %w", err)
	}
	var hello protobuf.HandshakeMessage
	if err := proto.Unmarshal(msg1, &hello); err != nil {
		return nil, fmt.Errorf("unmarshal client hello: %w", err)
	}
	var clientEph [32]byte
	copy(clientEph[:], hello.GetClientHello().GetEphemeral())
	if clientEph == ([32]byte{}) {
		return nil, errors.New("empty client ephemeral")
	}

	hs := noise.NewHandshake()
	hs.Start(transport.IntroHeader)
	hs.Authenticate(clientEph[:])
	hs.Authenticate(serverEph.Pub[:])
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientEph); err != nil {
		return nil, err
	}
	encStatic, err := hs.Encrypt(serverStatic.Pub[:])
	if err != nil {
		return nil, err
	}
	if err := hs.MixSharedSecretIntoKey(serverStatic.Priv, clientEph); err != nil {
		return nil, err
	}
	encCert, err := hs.Encrypt(certBlob)
	if err != nil {
		return nil, err
	}
	msg2, err := proto.Marshal(&protobuf.HandshakeMessage{
		ServerHello: &protobuf.HandshakeMessage_ServerHello{
			Ephemeral: serverEph.Pub[:], Static: encStatic, Payload: encCert,
		},
	})
	if err != nil {
		return nil, err
	}
	if err := fc.WriteFrame(ctx, msg2); err != nil {
		return nil, fmt.Errorf("write server hello: %w", err)
	}

	msg3, err := fc.ReadFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("read client finish: %w", err)
	}
	var finish protobuf.HandshakeMessage
	if err := proto.Unmarshal(msg3, &finish); err != nil {
		return nil, err
	}
	clientStaticBytes, err := hs.Decrypt(finish.GetClientFinish().GetStatic())
	if err != nil {
		return nil, fmt.Errorf("decrypt client static: %w", err)
	}
	if len(clientStaticBytes) != 32 {
		return nil, fmt.Errorf("client static is %d bytes", len(clientStaticBytes))
	}
	var clientStatic [32]byte
	copy(clientStatic[:], clientStaticBytes)
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientStatic); err != nil {
		return nil, err
	}
	if _, err := hs.Decrypt(finish.GetClientFinish().GetPayload()); err != nil {
		return nil, fmt.Errorf("decrypt client payload: %w", err)
	}

	rawWrite, rawRead, err := hs.Finish()
	if err != nil {
		return nil, err
	}
	// The server perspective swaps the client's write/read halves (PF-008).
	return newServerNodeConn(fc, rawRead, rawWrite)
}

// serverNodeConn writes encrypted node frames as the fake server, so tests can
// answer the client payload (PF-028) the way the real server does.
type serverNodeConn struct {
	fc        transport.FrameConn
	writeAEAD cipher.AEAD
	writeCtr  uint32
	codec     binary.Codec
}

func newServerNodeConn(fc transport.FrameConn, writeKey, _ [32]byte) (*serverNodeConn, error) {
	writeAEAD, err := newServerAEAD(writeKey)
	if err != nil {
		return nil, err
	}
	return &serverNodeConn{fc: fc, writeAEAD: writeAEAD, codec: binary.NewCodec(nil)}, nil
}

func newServerAEAD(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *serverNodeConn) writeNode(ctx context.Context, node *binary.Node) error {
	frame, err := c.codec.Encode(node)
	if err != nil {
		return err
	}
	iv := make([]byte, 12)
	binenc.BigEndian.PutUint32(iv[8:], c.writeCtr)
	c.writeCtr++
	return c.fc.WriteFrame(ctx, c.writeAEAD.Seal(nil, iv, frame, nil))
}

// pipeConn is an in-memory transport.FrameConn pair. Frames written to one end
// become readable at the other, matching the one-reader/one-writer contract.
//
// Unlike transport.WebSocketConn it adds no intro header: session and engine do
// not require the bytes on the wire, and both sides still authenticate the
// constant through the handshake state machine.
type pipeConn struct {
	in         chan []byte
	peerIn     chan []byte
	closed     chan struct{}
	peerClosed chan struct{}
	closeOnce  sync.Once
}

func newPipePair() (*pipeConn, *pipeConn) {
	aClosed, bClosed := make(chan struct{}), make(chan struct{})
	aIn, bIn := make(chan []byte, 16), make(chan []byte, 16)
	a := &pipeConn{in: aIn, peerIn: bIn, closed: aClosed, peerClosed: bClosed}
	b := &pipeConn{in: bIn, peerIn: aIn, closed: bClosed, peerClosed: aClosed}
	return a, b
}

func (p *pipeConn) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case frame, ok := <-p.in:
		if !ok {
			return nil, fmt.Errorf("pipe read: %w", transport.ErrClosed)
		}
		return frame, nil
	case <-p.closed:
		return nil, fmt.Errorf("pipe read: %w", transport.ErrClosed)
	case <-ctx.Done():
		return nil, fmt.Errorf("pipe read: %w", ctx.Err())
	}
}

func (p *pipeConn) WriteFrame(ctx context.Context, frame []byte) error {
	select {
	case <-p.closed:
		return fmt.Errorf("pipe write: %w", transport.ErrClosed)
	case <-p.peerClosed:
		return fmt.Errorf("pipe write: peer closed: %w", transport.ErrClosed)
	default:
	}
	select {
	case p.peerIn <- append([]byte(nil), frame...):
		return nil
	case <-p.closed:
		return fmt.Errorf("pipe write: %w", transport.ErrClosed)
	case <-ctx.Done():
		return fmt.Errorf("pipe write: %w", ctx.Err())
	}
}

func (p *pipeConn) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

// testFactory builds a factory against an in-memory vault and the fake dialer.
func testFactory(t *testing.T, dialer *fakeDialer) (*sessionFactory, *storagecredentials.Vault, *storagecredentials.MemoryBackend) {
	t.Helper()
	key, err := envelope.NewKey(bytes32(0x42))
	if err != nil {
		t.Fatal(err)
	}
	backend := storagecredentials.NewMemoryBackend()
	vault, err := storagecredentials.NewVault(backend, key)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := newSessionFactory(sessionFactoryOptions{
		vault:    vault,
		bus:      events.NewBus(),
		logger:   slog.New(slog.DiscardHandler),
		dialer:   dialer,
		endpoint: transport.Endpoint{URL: "ws://fake.invalid/ws/chat"},
		rootPub:  dialer.rootMont[:],
	})
	if err != nil {
		t.Fatalf("newSessionFactory: %v", err)
	}
	t.Cleanup(factory.bus.Close)
	return factory, vault, backend
}

// TestSessionFactoryConnects proves the factory is not a stub: a created
// session dials through the injected dialer, runs the Noise handshake against
// the fake server, and reaches CONNECTED.
func TestSessionFactoryConnects(t *testing.T) {
	dialer := newFakeDialer(t)
	factory, _, _ := testFactory(t, dialer)
	t.Cleanup(func() { close(dialer.release) })

	// Subscribe before creating the session so the publication cannot be
	// missed; the bus is what the SSE routes stream from.
	sub := factory.bus.Subscribe()
	t.Cleanup(sub.Close)

	sess, err := factory.newSession("session-1")
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	t.Cleanup(func() { _ = sess.Stop(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := sess.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	state, err := sess.State(ctx)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if state != session.StateConnected {
		t.Fatalf("state = %s, want CONNECTED", state)
	}
	if got := dialer.dialCount(); got != 1 {
		t.Fatalf("dial count = %d, want 1", got)
	}
	if err := <-dialer.peerErr; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	// The factory must wire the shared bus, not a private one: the event is
	// how clients learn the session became usable.
	select {
	case ev := <-sub.C:
		if ev.Type != events.TypeConnected || ev.SessionID != "session-1" {
			t.Fatalf("first event = %s for %q, want connected for session-1", ev.Type, ev.SessionID)
		}
	case <-ctx.Done():
		t.Fatal("no connected event was published")
	}
}

// TestSessionFactoryReusesPersistedIdentity proves the second factory over the
// same vault reuses the device instead of minting a new one: the server would
// reject a client whose identity changed between restarts.
func TestSessionFactoryReusesPersistedIdentity(t *testing.T) {
	ctx := context.Background()
	dialer := newFakeDialer(t)
	factory, _, _ := testFactory(t, dialer)
	t.Cleanup(func() { close(dialer.release) })

	first, err := factory.loadKeys(ctx, "session-1")
	if err != nil {
		t.Fatalf("loadKeys (first): %v", err)
	}

	// A second factory over the same vault stands in for a restart.
	second, err := newSessionFactory(sessionFactoryOptions{
		vault:   factory.vault,
		bus:     events.NewBus(),
		logger:  slog.New(slog.DiscardHandler),
		dialer:  dialer,
		rootPub: dialer.rootMont[:],
	})
	if err != nil {
		t.Fatalf("newSessionFactory: %v", err)
	}
	t.Cleanup(second.bus.Close)

	reloaded, err := second.loadKeys(ctx, "session-1")
	if err != nil {
		t.Fatalf("loadKeys (reload): %v", err)
	}
	if reloaded.noiseKey != first.noiseKey {
		t.Fatal("noise key changed across a restart")
	}
	if reloaded.identity != first.identity {
		t.Fatal("identity key changed across a restart")
	}
	if reloaded.registrationID != first.registrationID {
		t.Fatal("registration id changed across a restart")
	}
	if reloaded.advSecret != first.advSecret {
		t.Fatal("adv secret changed across a restart")
	}
	// The reload path must find the prekey store too, not regenerate it.
	firstBundle := first.preKeys.Bundle(false)
	reloadedBundle := reloaded.preKeys.Bundle(false)
	if firstBundle.SignedPreKeyID != reloadedBundle.SignedPreKeyID ||
		firstBundle.SignedPreKey != reloadedBundle.SignedPreKey {
		t.Fatal("signed prekey changed across a restart")
	}
	// The server verifies the signed prekey against the identity we advertise.
	if err := signal.ParsePreKeyBundle(reloadedBundle); err != nil {
		t.Fatalf("signed prekey does not verify under the identity: %v", err)
	}
}

// TestSessionFactoryDialFailureIsTerminal proves the connector wrapper runs
// inside the dial path: a transport failure surfaces from Connect and the
// session lands in ERROR rather than pretending to be connected.
func TestSessionFactoryDialFailureIsTerminal(t *testing.T) {
	dialer := newFakeDialer(t)
	dialer.dialErr = errors.New("synthetic transport failure")
	factory, _, _ := testFactory(t, dialer)

	sess, err := factory.newSession("session-1")
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	t.Cleanup(func() { _ = sess.Stop(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = sess.Connect(ctx)
	if err == nil {
		t.Fatal("Connect succeeded against a failing dialer")
	}
	state, stateErr := sess.State(ctx)
	if stateErr != nil {
		t.Fatalf("State: %v", stateErr)
	}
	if state != session.StateError {
		t.Fatalf("state = %s, want ERROR", state)
	}
}

// TestProductionWithoutKeyFailsClosed proves the "never unencrypted" rule: a
// production config with no ENCRYPTION_KEY yields a typed error instead of an
// in-memory fallback, and no factory can be built without a vault.
func TestProductionWithoutKeyFailsClosed(t *testing.T) {
	prod := &config.Config{App: config.AppConfig{Env: "production"}}
	_, err := newCredentialVault(prod, storagecredentials.NewMemoryBackend(), slog.New(slog.DiscardHandler))
	if !errors.Is(err, ErrEncryptionKeyRequired) {
		t.Fatalf("want ErrEncryptionKeyRequired, got %v", err)
	}

	dev := &config.Config{App: config.AppConfig{Env: "development"}}
	if _, err := newCredentialVault(dev, storagecredentials.NewMemoryBackend(), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("development fallback: %v", err)
	}

	if _, err := newSessionFactory(sessionFactoryOptions{bus: events.NewBus()}); !errors.Is(err, ErrNoCredentialVault) {
		t.Fatalf("want ErrNoCredentialVault, got %v", err)
	}
}

// TestInvalidEncryptionKeyIsTyped proves a malformed key is reported as such,
// not silently ignored.
func TestInvalidEncryptionKeyIsTyped(t *testing.T) {
	cfg := &config.Config{
		App:      config.AppConfig{Env: "production"},
		Security: config.SecurityConfig{EncryptionKey: "not-base64!"},
	}
	_, err := newCredentialVault(cfg, storagecredentials.NewMemoryBackend(), slog.New(slog.DiscardHandler))
	if !errors.Is(err, ErrEncryptionKeyInvalid) {
		t.Fatalf("want ErrEncryptionKeyInvalid, got %v", err)
	}
}

// TestEngineConnectorRequiresVault proves the connector wrapper refuses to
// build an engine without encrypted key material.
func TestEngineConnectorRequiresVault(t *testing.T) {
	f := &sessionFactory{bus: events.NewBus(), logger: slog.New(slog.DiscardHandler)}
	t.Cleanup(f.bus.Close)

	if _, err := f.engineConnector(context.Background(), "session-1"); !errors.Is(err, ErrNoCredentialVault) {
		t.Fatalf("want ErrNoCredentialVault, got %v", err)
	}
}

// TestCredentialRecordIsCiphertext proves the factory never writes plaintext
// key material: the vault's backend only sees sealed bytes.
func TestCredentialRecordIsCiphertext(t *testing.T) {
	dialer := newFakeDialer(t)
	factory, _, backend := testFactory(t, dialer)
	t.Cleanup(func() { close(dialer.release) })

	keys, err := factory.loadKeys(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	// The backend holds only ciphertext: version || nonce || sealed record.
	raw, err := backend.Get(context.Background(), "sessions/session-1/credentials")
	if err != nil {
		t.Fatalf("backend.Get: %v", err)
	}
	if len(raw) == 0 || raw[0] != envelope.Version {
		t.Fatalf("stored record is not an envelope: %x", raw[:1])
	}
	if indexOf(raw, keys.noiseKey.Priv[:]) >= 0 || indexOf(raw, keys.identity.Private[:]) >= 0 {
		t.Fatal("credential record contains plaintext private key material")
	}
}

// testSigningKeypair returns an Ed25519 key whose Edwards x is even plus the
// matching Montgomery u coordinate, which is what the Noise certificate chain
// signs and verifies with (PF-009).
func testSigningKeypair(t testing.TB) (ed25519.PrivateKey, [32]byte) {
	t.Helper()
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	p.Sub(p, big.NewInt(19))

	for attempt := 0; attempt < 1000; attempt++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if pub[31]&0x80 != 0 {
			continue
		}
		yBytes := make([]byte, 32)
		for i := range pub {
			yBytes[i] = pub[31-i]
		}
		yBytes[0] &= 0x7f
		y := new(big.Int).SetBytes(yBytes)
		den := new(big.Int).Sub(big.NewInt(1), y)
		den.Mod(den, p)
		inv := new(big.Int).ModInverse(den, p)
		if inv == nil {
			continue
		}
		u := new(big.Int).Mul(new(big.Int).Add(big.NewInt(1), y), inv)
		u.Mod(u, p)
		be := u.FillBytes(make([]byte, 32))
		var mont [32]byte
		for i := range be {
			mont[i] = be[31-i]
		}
		return priv, mont
	}
	t.Fatal("could not build a usable test key pair")
	return nil, [32]byte{}
}

// testCertChain builds a two-certificate chain: intermediate signed by root,
// leaf (carrying serverStatic) signed by the intermediate.
func testCertChain(t testing.TB, rootEd, intEd ed25519.PrivateKey, intMont [32]byte, leafKey []byte) []byte {
	t.Helper()
	now := uint64(time.Now().Unix())
	details := func(serial, issuer uint32, key []byte) []byte {
		s, i := serial, issuer
		nb, na := now-86400, now+86400
		raw, err := proto.Marshal(&protobuf.CertChain_NoiseCertificate_Details{
			Serial: &s, IssuerSerial: &i, Key: append([]byte(nil), key...),
			NotBefore: &nb, NotAfter: &na,
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	intDetails := details(1, 0, intMont[:])
	leafDetails := details(2, 1, leafKey)
	raw, err := proto.Marshal(&protobuf.CertChain{
		Leaf: &protobuf.CertChain_NoiseCertificate{
			Details: leafDetails, Signature: ed25519.Sign(intEd, leafDetails),
		},
		Intermediate: &protobuf.CertChain_NoiseCertificate{
			Details: intDetails, Signature: ed25519.Sign(rootEd, intDetails),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func bytes32(b byte) []byte {
	out := make([]byte, envelope.KeySize)
	for i := range out {
		out[i] = b
	}
	return out
}

// indexOf reports the first offset of needle in haystack (or -1); a local copy
// keeps the assertion readable without importing bytes just for one call.
func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestSessionRejectsFailedAuth proves the REST-visible state is not CONNECTED
// when the server rejects the payload: the session must report an error instead
// of a healthy connection.
func TestSessionRejectsFailedAuth(t *testing.T) {
	dialer := newFakeDialer(t)
	dialer.rejectAuth = &binary.Node{
		Tag:   "failure",
		Attrs: binary.Attrs{"reason": "401", "message": "not authorized"},
	}
	factory, _, _ := testFactory(t, dialer)
	t.Cleanup(func() { close(dialer.release) })

	sess, err := factory.newSession("session-1")
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	t.Cleanup(func() { _ = sess.Stop(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := sess.Connect(ctx); err == nil {
		t.Fatal("Connect must fail when the server rejects the payload")
	}
	state, err := sess.State(ctx)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if state == session.StateConnected {
		t.Fatalf("state = %s, want a non-connected state", state)
	}
}
