package engine

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	stdbinary "encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/internal/xeddsa"
	"github.com/angga0x3/whatscore/protocol/auth"
	"github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/pairing"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// This file builds a fake WhatsApp server in the test binary: an in-memory
// transport pair, the server role of the PF-007 Noise handshake written
// against noise.NewHandshake (no helpers imported from protocol/noise's
// tests), a synthetic PF-009 certificate chain, and a server-side AEAD frame
// layer for PF-008. The production client is exercised through the engine's
// real Connect/StartPairing paths.

// --- in-memory transport -------------------------------------------------

// pipeConn is an in-memory transport.FrameConn: writes on one end are reads
// on the other. It follows the transport contract (one reader, one writer,
// idempotent Close).
type pipeConn struct {
	name       string
	in         chan []byte
	peerIn     chan []byte
	peerClosed chan struct{}
	closed     chan struct{}
	closeOnce  sync.Once
}

func newPipePair() (*pipeConn, *pipeConn) {
	aClosed := make(chan struct{})
	bClosed := make(chan struct{})
	aIn := make(chan []byte, 64)
	bIn := make(chan []byte, 64)
	a := &pipeConn{name: "client", in: aIn, peerIn: bIn, closed: aClosed, peerClosed: bClosed}
	b := &pipeConn{name: "server", in: bIn, peerIn: aIn, closed: bClosed, peerClosed: aClosed}
	return a, b
}

func (p *pipeConn) ReadFrame(ctx context.Context) ([]byte, error) {
	// Drain buffered frames before reporting a close: a real transport
	// delivers everything the peer wrote before it went away.
	select {
	case f := <-p.in:
		return f, nil
	default:
	}
	select {
	case f := <-p.in:
		return f, nil
	case <-p.closed:
		return nil, fmt.Errorf("pipe %s read: %w", p.name, transport.ErrClosed)
	case <-p.peerClosed:
		return nil, fmt.Errorf("pipe %s read: peer closed: %w", p.name, transport.ErrClosed)
	case <-ctx.Done():
		return nil, fmt.Errorf("pipe %s read: %w", p.name, ctx.Err())
	}
}

func (p *pipeConn) WriteFrame(ctx context.Context, frame []byte) error {
	select {
	case <-p.closed:
		return fmt.Errorf("pipe %s write: %w", p.name, transport.ErrClosed)
	case <-p.peerClosed:
		return fmt.Errorf("pipe %s write: peer closed: %w", p.name, transport.ErrClosed)
	default:
	}
	select {
	case p.peerIn <- append([]byte(nil), frame...):
		return nil
	case <-p.closed:
		return fmt.Errorf("pipe %s write: %w", p.name, transport.ErrClosed)
	case <-p.peerClosed:
		return fmt.Errorf("pipe %s write: peer closed: %w", p.name, transport.ErrClosed)
	case <-ctx.Done():
		return fmt.Errorf("pipe %s write: %w", p.name, ctx.Err())
	}
}

func (p *pipeConn) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

// fakeDialer hands each Dial the client end of a fresh in-memory pair and
// runs serve on the server end.
type fakeDialer struct {
	serve func(ctx context.Context, fr transport.FrameConn) error
	errs  chan error
}

func newFakeDialer(serve func(ctx context.Context, fr transport.FrameConn) error) *fakeDialer {
	return &fakeDialer{serve: serve, errs: make(chan error, 1)}
}

func (d *fakeDialer) Dial(ctx context.Context, _ transport.Endpoint) (transport.FrameConn, error) {
	client, server := newPipePair()
	go func() {
		err := d.serve(ctx, server)
		d.errs <- err
		_ = server.Close()
	}()
	return client, nil
}

// wait blocks for the server goroutine's result.
func (d *fakeDialer) wait(ctx context.Context, t *testing.T) {
	t.Helper()
	select {
	case err := <-d.errs:
		if err != nil {
			t.Fatalf("fake server: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("fake server did not finish before the context expired")
	}
}

// --- synthetic PF-009 certificate chain ----------------------------------

var curvePrime = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// testSigningKey returns an Ed25519 key whose public point has an even
// Edwards x coordinate, plus the matching Montgomery u coordinate, verified
// with the production xeddsa verifier.
func testSigningKey(t *testing.T) (ed25519.PrivateKey, [32]byte) {
	t.Helper()
	for attempt := 0; attempt < 1000; attempt++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 keygen: %v", err)
		}
		if pub[31]&0x80 != 0 {
			continue // odd Edwards x: mapping would need the flipped sign bit
		}
		yBytes := make([]byte, 32)
		for i := range pub {
			yBytes[i] = pub[31-i]
		}
		yBytes[0] &= 0x7f
		y := new(big.Int).SetBytes(yBytes)

		denom := new(big.Int).Sub(big.NewInt(1), y)
		denom.Mod(denom, curvePrime)
		if denom.Sign() == 0 {
			continue
		}
		inv := new(big.Int).ModInverse(denom, curvePrime)
		if inv == nil {
			continue
		}
		u := new(big.Int).Mul(new(big.Int).Add(big.NewInt(1), y), inv)
		u.Mod(u, curvePrime)

		var mont [32]byte
		be := u.FillBytes(make([]byte, 32))
		for i := range be {
			mont[i] = be[31-i]
		}

		msg := []byte("whatscore engine test key self-check")
		if err := xeddsa.Verify(mont, msg, ed25519.Sign(priv, msg)); err != nil {
			continue
		}
		return priv, mont
	}
	t.Fatal("no usable XEdDSA test key in 1000 attempts")
	return nil, [32]byte{}
}

// testRoot is the pinned server root for one fake server.
type testRoot struct {
	priv ed25519.PrivateKey
	mont [32]byte
}

func newTestRoot(t *testing.T) testRoot {
	t.Helper()
	priv, mont := testSigningKey(t)
	return testRoot{priv: priv, mont: mont}
}

func marshalCertDetails(t *testing.T, serial, issuerSerial uint32, key []byte, notBefore, notAfter uint64) []byte {
	t.Helper()
	raw, err := proto.Marshal(&protobuf.CertChain_NoiseCertificate_Details{
		Serial:       &serial,
		IssuerSerial: &issuerSerial,
		Key:          append([]byte(nil), key...),
		NotBefore:    &notBefore,
		NotAfter:     &notAfter,
	})
	if err != nil {
		t.Fatalf("marshal cert details: %v", err)
	}
	return raw
}

// certChain builds the PF-009 chain binding leafKey == server static.
func certChain(t *testing.T, root testRoot, leafKey []byte) []byte {
	t.Helper()
	intEd, intMont := testSigningKey(t)
	now := uint64(time.Now().Unix())
	intDetails := marshalCertDetails(t, 1, 0, intMont[:], now-86400, now+86400)
	leafDetails := marshalCertDetails(t, 2, 1, leafKey, now-86400, now+86400)
	raw, err := proto.Marshal(&protobuf.CertChain{
		Leaf: &protobuf.CertChain_NoiseCertificate{
			Details:   leafDetails,
			Signature: ed25519.Sign(intEd, leafDetails),
		},
		Intermediate: &protobuf.CertChain_NoiseCertificate{
			Details:   intDetails,
			Signature: ed25519.Sign(root.priv, intDetails),
		},
	})
	if err != nil {
		t.Fatalf("marshal cert chain: %v", err)
	}
	return raw
}

// --- server-side Noise handshake -----------------------------------------

// serverHello is what serverHandshake yields: the server's view of the
// connection before post-handshake encryption is applied.
type serverHello struct {
	conn       transport.FrameConn
	clientPub  []byte
	clientData []byte
	rawWrite   [32]byte
	rawRead    [32]byte
}

// serverHandshake runs PF-007 with noise.NewHandshake exactly as the client
// does, in reverse, and returns the decrypted client static and payload.
func serverHandshake(ctx context.Context, fr transport.FrameConn, serverEph, serverStatic noise.KeyPair, certBlob []byte) (*serverHello, error) {
	msg1, err := fr.ReadFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("read client hello: %w", err)
	}
	var hello protobuf.HandshakeMessage
	if err := proto.Unmarshal(msg1, &hello); err != nil {
		return nil, fmt.Errorf("unmarshal client hello: %w", err)
	}
	clientEphBytes := hello.GetClientHello().GetEphemeral()
	if len(clientEphBytes) != 32 {
		return nil, fmt.Errorf("client ephemeral is %d bytes, want 32", len(clientEphBytes))
	}
	var clientEph [32]byte
	copy(clientEph[:], clientEphBytes)

	hs := noise.NewHandshake()
	hs.Start(transport.IntroHeader)
	hs.Authenticate(clientEph[:])
	hs.Authenticate(serverEph.Pub[:])
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientEph); err != nil {
		return nil, fmt.Errorf("mix ee: %w", err)
	}
	encStatic, err := hs.Encrypt(serverStatic.Pub[:])
	if err != nil {
		return nil, fmt.Errorf("encrypt server static: %w", err)
	}
	if err := hs.MixSharedSecretIntoKey(serverStatic.Priv, clientEph); err != nil {
		return nil, fmt.Errorf("mix es: %w", err)
	}
	encPayload, err := hs.Encrypt(certBlob)
	if err != nil {
		return nil, fmt.Errorf("encrypt cert chain: %w", err)
	}
	msg2, err := proto.Marshal(&protobuf.HandshakeMessage{
		ServerHello: &protobuf.HandshakeMessage_ServerHello{
			Ephemeral: serverEph.Pub[:],
			Static:    encStatic,
			Payload:   encPayload,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal server hello: %w", err)
	}
	if err := fr.WriteFrame(ctx, msg2); err != nil {
		return nil, fmt.Errorf("write server hello: %w", err)
	}

	msg3, err := fr.ReadFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("read client finish: %w", err)
	}
	var finishMsg protobuf.HandshakeMessage
	if err := proto.Unmarshal(msg3, &finishMsg); err != nil {
		return nil, fmt.Errorf("unmarshal client finish: %w", err)
	}
	finish := finishMsg.GetClientFinish()
	clientStatic, err := hs.Decrypt(finish.GetStatic())
	if err != nil {
		return nil, fmt.Errorf("decrypt client static: %w", err)
	}
	var clientStaticKey [32]byte
	copy(clientStaticKey[:], clientStatic)
	// The client mixes se between encrypting its static and its payload, so
	// the server mirrors that between the two decrypts.
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientStaticKey); err != nil {
		return nil, fmt.Errorf("mix se: %w", err)
	}
	clientPayload, err := hs.Decrypt(finish.GetPayload())
	if err != nil {
		return nil, fmt.Errorf("decrypt client payload: %w", err)
	}
	rawWrite, rawRead, err := hs.Finish()
	if err != nil {
		return nil, fmt.Errorf("derive transport keys: %w", err)
	}
	return &serverHello{
		conn:       fr,
		clientPub:  clientStatic,
		clientData: clientPayload,
		rawWrite:   rawWrite,
		rawRead:    rawRead,
	}, nil
}

// --- server-side PF-008 framing ------------------------------------------

// serverSecure applies the PF-008 transport keys from the server
// perspective (write/read swapped relative to the client's raw halves) and
// carries binary nodes.
type serverSecure struct {
	fr    transport.FrameConn
	codec binary.Codec

	readAEAD  cipher.AEAD
	writeAEAD cipher.AEAD
	readSeq   uint32
	writeSeq  uint32
	mu        sync.Mutex
	capture   func([]byte) // test hook: sees decrypted frame plaintext
}

func newServerSecure(fr transport.FrameConn, sh *serverHello, codec binary.Codec) (*serverSecure, error) {
	if codec == nil {
		codec = binary.NewCodec(nil)
	}
	// The server reads with the client's write half and writes with the
	// client's read half (PF-008).
	read, err := aes.NewCipher(sh.rawWrite[:])
	if err != nil {
		return nil, err
	}
	ra, err := cipher.NewGCM(read)
	if err != nil {
		return nil, err
	}
	write, err := aes.NewCipher(sh.rawRead[:])
	if err != nil {
		return nil, err
	}
	wa, err := cipher.NewGCM(write)
	if err != nil {
		return nil, err
	}
	return &serverSecure{fr: fr, codec: codec, readAEAD: ra, writeAEAD: wa}, nil
}

func frameNonce(counter uint32) []byte {
	nonce := make([]byte, 12)
	stdbinary.BigEndian.PutUint32(nonce[8:], counter)
	return nonce
}

func (s *serverSecure) ReadNode(ctx context.Context) (*binary.Node, error) {
	frame, err := s.fr.ReadFrame(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	plain, err := s.readAEAD.Open(nil, frameNonce(s.readSeq), frame, nil)
	if err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("server decrypt: %w", err)
	}
	s.readSeq++
	capture := s.capture
	s.mu.Unlock()
	if capture != nil {
		capture(plain)
	}
	return s.codec.Decode(bytes.NewReader(plain))
}

func (s *serverSecure) WriteNode(ctx context.Context, node *binary.Node) error {
	raw, err := s.codec.Encode(node)
	if err != nil {
		return err
	}
	s.mu.Lock()
	sealed := s.writeAEAD.Seal(nil, frameNonce(s.writeSeq), raw, nil)
	s.writeSeq++
	s.mu.Unlock()
	return s.fr.WriteFrame(ctx, sealed)
}

// --- fake server fixtures -------------------------------------------------

// fakeServer bundles the key material one in-memory fake server presents.
type fakeServer struct {
	root   testRoot
	eph    noise.KeyPair
	static noise.KeyPair
	cert   []byte
	codec  binary.Codec // nil means binary.NewCodec(nil)
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	root := newTestRoot(t)
	eph, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("server ephemeral key: %v", err)
	}
	static, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("server static key: %v", err)
	}
	return &fakeServer{root: root, eph: eph, static: static, cert: certChain(t, root, static.Pub[:])}
}

// handshake runs the server handshake and wraps the connection for nodes.
func (s *fakeServer) handshake(ctx context.Context, fr transport.FrameConn) (*serverSecure, *serverHello, error) {
	sh, err := serverHandshake(ctx, fr, s.eph, s.static, s.cert)
	if err != nil {
		return nil, nil, err
	}
	ss, err := newServerSecure(fr, sh, s.codec)
	if err != nil {
		return nil, nil, err
	}
	return ss, sh, nil
}

// engineConfig is the minimum valid configuration; tests tweak it.
func engineConfig(fs *fakeServer, dialer transport.Dialer, t *testing.T) Config {
	t.Helper()
	noiseKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("noise key: %v", err)
	}
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity key: %v", err)
	}
	return Config{
		SessionID:      "test-session",
		Endpoint:       transport.Endpoint{URL: "ws://fake.invalid/ws"},
		Dialer:         dialer,
		NoiseKey:       noiseKey,
		RootPub:        fs.root.mont[:],
		Identity:       identity,
		RegistrationID: 4242,
		PreKeys:        fakePreKeys{},
		AdvSecret:      [32]byte{1, 2, 3},
		ClientType:     "test",
		ConnectType:    protobuf.ClientPayload_WIFI_UNKNOWN,
		ConnectReason:  protobuf.ClientPayload_USER_ACTIVATED,
	}
}

// fakePreKeys supplies a static bundle for the registration payload.
type fakePreKeys struct{}

func (fakePreKeys) Bundle(includeOneTime bool) signal.PreKeyBundle {
	var signed [32]byte
	for i := range signed {
		signed[i] = byte(i + 1)
	}
	signature := make([]byte, signal.SignatureSize)
	for i := range signature {
		signature[i] = byte(i)
	}
	bundle := signal.PreKeyBundle{
		SignedPreKeyID:        7,
		SignedPreKey:          signed,
		SignedPreKeySignature: signature,
	}
	if includeOneTime {
		var oneTime [32]byte
		bundle.OneTimePreKeyID = 9
		bundle.OneTimePreKey = &oneTime
	}
	return bundle
}

// --- pairing stanza fixtures ---------------------------------------------

func pairDeviceNode(id, from string, refs ...string) *binary.Node {
	children := make([]binary.Node, 0, len(refs))
	for _, ref := range refs {
		children = append(children, binary.Node{Tag: "ref", Bytes: []byte(ref)})
	}
	return &binary.Node{
		Tag:   "iq",
		Attrs: binary.Attrs{"id": id, "from": from, "type": "get"},
		Children: []binary.Node{
			{Tag: "pair-device", Children: children},
		},
	}
}

// deviceIdentityContainer builds a valid PF-017 ADVSignedDeviceIdentityHMAC
// for the given adv secret and identity public key.
func deviceIdentityContainer(t *testing.T, advSecret, identityPub []byte, rawID uint32) []byte {
	t.Helper()
	accountEd, accountMont := testSigningKey(t)

	now := uint64(time.Now().Unix())
	deviceDetails, err := proto.Marshal(&protobuf.ADVDeviceIdentity{
		RawID:       proto.Uint32(rawID),
		Timestamp:   proto.Uint64(now),
		KeyIndex:    proto.Uint32(1),
		AccountType: protobuf.ADVEncryptionType_E2EE.Enum(),
		DeviceType:  protobuf.ADVEncryptionType_E2EE.Enum(),
	})
	if err != nil {
		t.Fatalf("marshal device identity: %v", err)
	}

	prefix := []byte{6, 0} // E2EE account-signature prefix (PF-017)
	message := make([]byte, 0, len(prefix)+len(deviceDetails)+len(identityPub))
	message = append(message, prefix...)
	message = append(message, deviceDetails...)
	message = append(message, identityPub...)

	signed, err := proto.Marshal(&protobuf.ADVSignedDeviceIdentity{
		Details:             deviceDetails,
		AccountSignatureKey: accountMont[:],
		AccountSignature:    ed25519.Sign(accountEd, message),
	})
	if err != nil {
		t.Fatalf("marshal signed device identity: %v", err)
	}

	mac := hmac.New(sha256.New, advSecret)
	mac.Write(signed)
	container, err := proto.Marshal(&protobuf.ADVSignedDeviceIdentityHMAC{
		Details:     signed,
		HMAC:        mac.Sum(nil),
		AccountType: protobuf.ADVEncryptionType_E2EE.Enum(),
	})
	if err != nil {
		t.Fatalf("marshal device identity hmac: %v", err)
	}
	return container
}

func pairSuccessNode(t *testing.T, id string, container []byte) *binary.Node {
	t.Helper()
	return &binary.Node{
		Tag:   "iq",
		Attrs: binary.Attrs{"id": id, "type": "result"},
		Children: []binary.Node{
			{
				Tag: "pair-success",
				Children: []binary.Node{
					{Tag: "device", Attrs: binary.Attrs{"jid": "5511999999999:8@s.whatsapp.net", "lid": "100000000000001:8@lid"}},
					{Tag: "biz", Attrs: binary.Attrs{"name": "Test Biz"}},
					{Tag: "platform", Attrs: binary.Attrs{"name": "android"}},
					{Tag: "client-props", Bytes: []byte{0x01, 0x02}},
					{Tag: "device-identity", Bytes: container},
				},
			},
		},
	}
}

// --- tests ----------------------------------------------------------------

// TestConnectRegistrationPayload proves the default sequence: dial, the
// registration ClientPayload inside msg3, and node round-trip afterwards.
func TestConnectRegistrationPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	payloads := make(chan []byte, 1)
	var wantClientPub []byte

	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		secure, sh, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		payloads <- append([]byte(nil), sh.clientData...)
		if !bytes.Equal(sh.clientPub, wantClientPub) {
			return fmt.Errorf("client static %x does not match the configured noise key", sh.clientPub)
		}
		if err := secure.WriteNode(ctx, &binary.Node{
			Tag:   "iq",
			Attrs: binary.Attrs{"id": "srv-1", "type": "result"},
			Children: []binary.Node{
				{Tag: "ping", Attrs: binary.Attrs{"kind": "hello"}},
			},
		}); err != nil {
			return fmt.Errorf("server write: %w", err)
		}
		got, err := secure.ReadNode(ctx)
		if err != nil {
			return fmt.Errorf("server read: %w", err)
		}
		if got.Tag != "iq" || got.Attrs["id"] != "cli-1" {
			return fmt.Errorf("server read unexpected node %q id=%q", got.Tag, got.Attrs["id"])
		}
		return nil
	})

	cfg := engineConfig(fs, dialer, t)
	wantClientPub = cfg.NoiseKey.Pub[:]
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := eng.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if conn.CipherSuite() != noise.CipherSuite {
		t.Fatalf("CipherSuite = %q, want %q", conn.CipherSuite(), noise.CipherSuite)
	}

	select {
	case raw := <-payloads:
		parsed, err := auth.ParseClientPayload(raw)
		if err != nil {
			t.Fatalf("registration payload rejected: %v", err)
		}
		if parsed.Registration.RegistrationID != cfg.RegistrationID {
			t.Fatalf("registration id = %d, want %d", parsed.Registration.RegistrationID, cfg.RegistrationID)
		}
		if !bytes.Equal(parsed.Registration.IdentityKey, cfg.Identity.Public[:]) {
			t.Fatal("registration payload carries the wrong identity key")
		}
		if _, err := auth.ParseLoginPayload(raw); err == nil {
			t.Fatal("registration payload must be rejected by the login parser (PF-027)")
		}
	case <-ctx.Done():
		t.Fatal("server never received the client payload")
	}

	node, err := conn.ReadNode(ctx)
	if err != nil {
		t.Fatalf("ReadNode: %v", err)
	}
	if node.Tag != "iq" || len(node.Children) != 1 || node.Children[0].Tag != "ping" {
		t.Fatalf("ReadNode decoded %#v", node)
	}
	if err := conn.WriteNode(ctx, &binary.Node{Tag: "iq", Attrs: binary.Attrs{"id": "cli-1", "type": "result"}}); err != nil {
		t.Fatalf("WriteNode: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dialer.wait(ctx, t)
}

// TestConnectLoginPayload proves the login form is selected when credentials
// are supplied, and that the parsers reject each other's form (PF-027).
func TestConnectLoginPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	payloads := make(chan []byte, 1)
	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		_, sh, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		payloads <- append([]byte(nil), sh.clientData...)
		// Keep the connection open until the client closes it.
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})

	cfg := engineConfig(fs, dialer, t)
	cfg.PreKeys = nil // login needs no prekeys
	cfg.Credentials = &Credentials{Username: 5511999999999, Device: 8}
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := eng.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case raw := <-payloads:
		login, err := auth.ParseLoginPayload(raw)
		if err != nil {
			t.Fatalf("login payload rejected: %v", err)
		}
		if login.Username != 5511999999999 || login.Device != 8 {
			t.Fatalf("login identity = %d:%d", login.Username, login.Device)
		}
		if !login.Passive || !login.Pull || !login.LidDbMigrated {
			t.Fatalf("login flags passive=%v pull=%v lid=%v", login.Passive, login.Pull, login.LidDbMigrated)
		}
		if _, err := auth.ParseClientPayload(raw); err == nil {
			t.Fatal("login payload must be rejected by the registration parser (PF-027)")
		}
	case <-ctx.Done():
		t.Fatal("server never received the client payload")
	}

	if eng.payloadForm() != "login" {
		t.Fatalf("payloadForm = %q, want login", eng.payloadForm())
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dialer.wait(ctx, t)
}

// TestStartPairingEmitsQRPayloads drives <pair-device>: the engine acks the
// iq and emits one QR payload per ref (PF-015, PF-016).
func TestStartPairingEmitsQRPayloads(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	refs := []string{"ref-alpha", "ref-beta"}
	ackSeen := make(chan binary.Attrs, 1)

	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		secure, _, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		if err := secure.WriteNode(ctx, pairDeviceNode("pair-1", "s.whatsapp.net", refs...)); err != nil {
			return fmt.Errorf("server pair-device: %w", err)
		}
		ack, err := secure.ReadNode(ctx)
		if err != nil {
			return fmt.Errorf("server read ack: %w", err)
		}
		if ack.Tag != "iq" || ack.Attrs["type"] != "result" ||
			ack.Attrs["id"] != "pair-1" || ack.Attrs["to"] != "s.whatsapp.net" {
			return fmt.Errorf("bad pair-device ack: %#v", ack)
		}
		ackSeen <- ack.Attrs
		// Wait for the client to give up and close.
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})

	cfg := engineConfig(fs, dialer, t)
	bus := events.NewBus()
	defer bus.Close()
	cfg.Bus = bus
	sub := bus.Subscribe()
	defer sub.Close()

	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := crew.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	codes, err := conn.StartPairing(ctx)
	if err != nil {
		t.Fatalf("StartPairing: %v", err)
	}
	select {
	case batch, ok := <-codes:
		if !ok {
			t.Fatal("pairing channel closed before any QR payload")
		}
		if len(batch) != len(refs) {
			t.Fatalf("got %d QR payloads, want %d", len(batch), len(refs))
		}
		for i, payload := range batch {
			if payload.Ref != refs[i] {
				t.Fatalf("payload %d ref = %q, want %q", i, payload.Ref, refs[i])
			}
			code, err := payload.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			parsed, err := pairing.ParseQR(code)
			if err != nil {
				t.Fatalf("ParseQR(%q): %v", code, err)
			}
			if parsed.NoisePublicKey != cfg.NoiseKey.Pub {
				t.Fatal("QR payload carries the wrong noise key")
			}
			if parsed.IdentityPublicKey != cfg.Identity.Public {
				t.Fatal("QR payload carries the wrong identity key")
			}
			if parsed.AdvSecret != cfg.AdvSecret {
				t.Fatal("QR payload carries the wrong adv secret")
			}
		}
	case <-ctx.Done():
		t.Fatal("no QR payload emitted")
	}
	select {
	case attrs := <-ackSeen:
		if attrs["id"] != "pair-1" {
			t.Fatalf("ack id = %q", attrs["id"])
		}
	case <-ctx.Done():
		t.Fatal("server never received the pair-device ack")
	}

	// Each ref also surfaces as a pairing-code event carrying the encoded QR
	// string for callers that render it.
	for i := range refs {
		select {
		case ev := <-sub.C:
			if ev.Type != events.TypePairingCode || ev.PairingCode == nil {
				t.Fatalf("event %d = %#v", i, ev)
			}
			if ev.SessionID != cfg.SessionID {
				t.Fatalf("event session = %q", ev.SessionID)
			}
			if _, err := pairing.ParseQR(ev.PairingCode.Code); err != nil {
				t.Fatalf("event QR %q: %v", ev.PairingCode.Code, err)
			}
		case <-ctx.Done():
			t.Fatalf("no pairing-code event %d", i)
		}
	}

	// The pairing flow is still reading; closing the connection must end it
	// with ErrPairingFailed rather than hanging.
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if _, err := conn.WaitPairing(waitCtx); !errors.Is(err, ErrPairingFailed) {
		t.Fatalf("WaitPairing after close = %v, want ErrPairingFailed", err)
	}
	dialer.wait(ctx, t)
}

// TestPairingSuccessRequiresSigner proves the verification path: the server
// container authenticates, and the missing device-identity signer surfaces as
// ErrSignerRequired instead of a silent unsigned credential.
func TestPairingSuccessRequiresSigner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	cfg := engineConfig(fs, nil, t) // dialer filled in below

	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		secure, _, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		if err := secure.WriteNode(ctx, pairDeviceNode("pair-2", "s.whatsapp.net", "ref-1")); err != nil {
			return err
		}
		if _, err := secure.ReadNode(ctx); err != nil { // ack
			return fmt.Errorf("server read ack: %w", err)
		}
		container := deviceIdentityContainer(t, cfg.AdvSecret[:], cfg.Identity.Public[:], 77)
		if err := secure.WriteNode(ctx, pairSuccessNode(t, "pair-2", container)); err != nil {
			return err
		}
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})
	cfg.Dialer = dialer

	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := crew.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	codes, err := conn.StartPairing(ctx)
	if err != nil {
		t.Fatalf("StartPairing: %v", err)
	}
	if _, ok := <-codes; !ok {
		t.Fatal("no QR payload before pair-success")
	}

	result, err := conn.WaitPairing(ctx)
	if !errors.Is(err, ErrSignerRequired) {
		t.Fatalf("WaitPairing = (%v, %v), want ErrSignerRequired", result, err)
	}
	if result != nil {
		t.Fatalf("result = %#v, want nil when signing is unavailable", result)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dialer.wait(ctx, t)
}

// deterministicSigner stands in for a real XEdDSA signer: it records the
// message it was asked to sign and returns a fixed-length signature, so the
// test asserts the flow without depending on curve arithmetic.
type deterministicSigner struct {
	details, identityPub, accountKey []byte
}

func (d *deterministicSigner) SignDeviceIdentity(details, identityPub, accountKey []byte) ([]byte, error) {
	d.details = append([]byte(nil), details...)
	d.identityPub = append([]byte(nil), identityPub...)
	d.accountKey = append([]byte(nil), accountKey...)
	signature := make([]byte, signal.SignatureSize)
	signature[0] = 0x01
	return signature, nil
}

// TestPairingSuccessWithSigner covers the completed path: with a signer
// injected, the verified identity is returned with the local credentials.
func TestPairingSuccessWithSigner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	cfg := engineConfig(fs, nil, t)
	signer := &deterministicSigner{}
	cfg.Signer = signer

	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		secure, _, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		if err := secure.WriteNode(ctx, pairDeviceNode("pair-3", "s.whatsapp.net", "ref-1")); err != nil {
			return err
		}
		if _, err := secure.ReadNode(ctx); err != nil {
			return fmt.Errorf("server read ack: %w", err)
		}
		container := deviceIdentityContainer(t, cfg.AdvSecret[:], cfg.Identity.Public[:], 88)
		if err := secure.WriteNode(ctx, pairSuccessNode(t, "pair-3", container)); err != nil {
			return err
		}
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})
	cfg.Dialer = dialer

	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := crew.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	codes, err := conn.StartPairing(ctx)
	if err != nil {
		t.Fatalf("StartPairing: %v", err)
	}
	if _, ok := <-codes; !ok {
		t.Fatal("no QR payload before pair-success")
	}
	result, err := conn.WaitPairing(ctx)
	if err != nil {
		t.Fatalf("WaitPairing: %v", err)
	}
	if result.JID != "5511999999999:8@s.whatsapp.net" {
		t.Fatalf("JID = %q", result.JID)
	}
	if result.LID != "100000000000001:8@lid" {
		t.Fatalf("LID = %q", result.LID)
	}
	if result.BusinessName != "Test Biz" || result.Platform != "android" {
		t.Fatalf("metadata = %q/%q", result.BusinessName, result.Platform)
	}
	if result.Device == nil || result.Device.RawID != 88 {
		t.Fatalf("device identity = %#v", result.Device)
	}
	if result.NoiseKey.Pub != cfg.NoiseKey.Pub || result.Identity.Public != cfg.Identity.Public {
		t.Fatal("result carries the wrong local key material")
	}
	if len(result.DeviceSignature) != signal.SignatureSize {
		t.Fatalf("device signature length = %d, want %d", len(result.DeviceSignature), signal.SignatureSize)
	}
	if result.DeviceSignature[0] != 0x01 {
		t.Fatalf("device signature came from another signer: %x", result.DeviceSignature[:4])
	}
	// PF-017: the signer must receive the server's details, our identity key,
	// and the server-issued account signature key.
	if len(signer.details) == 0 || len(signer.identityPub) != signal.KeySize || len(signer.accountKey) != signal.KeySize {
		t.Fatalf("signer inputs = details:%d identity:%d account:%d",
			len(signer.details), len(signer.identityPub), len(signer.accountKey))
	}
	if !bytes.Equal(signer.identityPub, cfg.Identity.Public[:]) {
		t.Fatal("signer received the wrong identity key")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dialer.wait(ctx, t)
}

// TestPairingRejectsTamperedIdentity proves the HMAC check fails closed.
func TestPairingRejectsTamperedIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	cfg := engineConfig(fs, nil, t)

	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		secure, _, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		if err := secure.WriteNode(ctx, pairDeviceNode("pair-4", "s.whatsapp.net", "ref-1")); err != nil {
			return err
		}
		if _, err := secure.ReadNode(ctx); err != nil {
			return fmt.Errorf("server read ack: %w", err)
		}
		container := deviceIdentityContainer(t, cfg.AdvSecret[:], cfg.Identity.Public[:], 99)
		container[len(container)-1] ^= 0xff // corrupt the container
		if err := secure.WriteNode(ctx, pairSuccessNode(t, "pair-4", container)); err != nil {
			return err
		}
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})
	cfg.Dialer = dialer

	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := crew.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if _, err := conn.StartPairing(ctx); err != nil {
		t.Fatalf("StartPairing: %v", err)
	}
	if _, err := conn.WaitPairing(ctx); !errors.Is(err, ErrPairingFailed) {
		t.Fatalf("WaitPairing = %v, want ErrPairingFailed", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dialer.wait(ctx, t)
}

// TestConnectRejectsUnknownServerRoot proves a handshake failure is reported
// as ErrAuthFailed and the transport is closed.
func TestConnectRejectsUnknownServerRoot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		_, err := serverHandshake(ctx, fr, fs.eph, fs.static, fs.cert)
		if err != nil {
			// The client aborts the handshake after the certificate check;
			// the server sees the close.
			if errors.Is(err, transport.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return nil
		}
		return nil
	})
	cfg := engineConfig(fs, dialer, t)
	cfg.RootPub = bytes.Repeat([]byte{0xAA}, 32) // not the signing root

	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := crew.Connect(ctx); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Connect = %v, want ErrAuthFailed", err)
	}
	dialer.wait(ctx, t)
}

// TestPumpAndClose proves the frame pump consumes frames, rejects a second
// reader, and ends when the connection closes.
func TestPumpAndClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	nodes := make(chan *binary.Node, 1)
	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		secure, _, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		if err := secure.WriteNode(ctx, &binary.Node{Tag: "message", Attrs: binary.Attrs{"id": "m-1"}}); err != nil {
			return err
		}
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})

	cfg := engineConfig(fs, dialer, t)
	cfg.FrameHandler = FrameHandlerFunc(func(_ context.Context, frame []byte) error {
		node, err := binary.NewCodec(nil).Decode(bytes.NewReader(frame))
		if err != nil {
			return err
		}
		nodes <- node
		return nil
	})

	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := crew.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	done, err := conn.StartPump(ctx)
	if err != nil {
		t.Fatalf("StartPump: %v", err)
	}
	// A second reader must be refused while the pump owns the connection.
	if _, err := conn.ReadNode(ctx); !errors.Is(err, ErrReaderBusy) {
		t.Fatalf("ReadNode during pump = %v, want ErrReaderBusy", err)
	}
	select {
	case node := <-nodes:
		if node.Tag != "message" || node.Attrs["id"] != "m-1" {
			t.Fatalf("handler got %#v", node)
		}
	case <-ctx.Done():
		t.Fatal("frame handler never ran")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("pump must report the close")
		}
	case <-ctx.Done():
		t.Fatal("pump did not stop on close")
	}

	// A closed Conn refuses further use.
	if err := conn.WriteNode(ctx, &binary.Node{Tag: "iq"}); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("WriteNode after Close = %v, want ErrNotConnected", err)
	}
	if _, err := conn.ReadNode(ctx); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("ReadNode after Close = %v, want ErrNotConnected", err)
	}
	// Close is idempotent.
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	dialer.wait(ctx, t)
}

// TestNewValidation locks the configuration contract.
func TestNewValidation(t *testing.T) {
	fs := newFakeServer(t)
	base := engineConfig(fs, newFakeDialer(func(context.Context, transport.FrameConn) error { return nil }), t)

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty session", func(c *Config) { c.SessionID = "" }},
		{"nil dialer", func(c *Config) { c.Dialer = nil }},
		{"short root", func(c *Config) { c.RootPub = []byte{1, 2} }},
		{"zero noise key", func(c *Config) { c.NoiseKey = noise.KeyPair{} }},
		{"zero identity", func(c *Config) { c.Identity = signal.KeyPair{} }},
		{"no prekeys", func(c *Config) { c.PreKeys = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New = %v, want ErrInvalidConfig", err)
			}
		})
	}

	// Defaults are applied without error.
	cfg := base
	cfg.Version = auth.Version{}
	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New(defaults): %v", err)
	}
	if crew.Config().Version != DefaultVersion {
		t.Fatalf("default version = %#v", crew.Config().Version)
	}
	if crew.Config().Codec == nil {
		t.Fatal("default codec is nil")
	}
}

// TestConnectUsesInjectedCodec proves the dictionary-injected codec is used
// on the wire: the same node encodes differently under a custom dictionary,
// the server sees those exact bytes, and the default codec cannot read them.
func TestConnectUsesInjectedCodec(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dict := binary.NewDictionary()
	if err := dict.SetSingle(1, "iq"); err != nil {
		t.Fatalf("set token: %v", err)
	}
	if err := dict.SetSingle(2, "ping"); err != nil {
		t.Fatalf("set token: %v", err)
	}
	codec := binary.NewCodec(dict)

	node := &binary.Node{Tag: "iq", Children: []binary.Node{{Tag: "ping"}}}
	withDict, err := codec.Encode(node)
	if err != nil {
		t.Fatalf("encode with dictionary: %v", err)
	}
	withoutDict, err := binary.NewCodec(nil).Encode(node)
	if err != nil {
		t.Fatalf("encode without dictionary: %v", err)
	}
	if bytes.Equal(withDict, withoutDict) {
		t.Fatal("dictionary tokens did not change the encoding; the test proves nothing")
	}

	fs := newFakeServer(t)
	fs.codec = codec
	plaintext := make(chan []byte, 1)

	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		secure, _, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		secure.capture = func(plain []byte) { plaintext <- append([]byte(nil), plain...) }
		if _, err := secure.ReadNode(ctx); err != nil {
			return fmt.Errorf("server read: %w", err)
		}
		secure.capture = nil
		if err := secure.WriteNode(ctx, node); err != nil {
			return err
		}
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})

	cfg := engineConfig(fs, dialer, t)
	cfg.Codec = codec

	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := crew.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.WriteNode(ctx, node); err != nil {
		t.Fatalf("WriteNode: %v", err)
	}
	select {
	case plain := <-plaintext:
		if !bytes.Equal(plain, withDict) {
			t.Fatalf("wire plaintext %x, want the injected codec's %x", plain, withDict)
		}
		if _, err := binary.NewCodec(nil).Decode(bytes.NewReader(plain)); err == nil {
			t.Fatal("the default codec decoded a dictionary-encoded node; test is not proving the injection")
		}
	case <-ctx.Done():
		t.Fatal("server never saw the node")
	}

	// The server's dictionary-encoded reply round-trips through the engine.
	ping, err := conn.ReadNode(ctx)
	if err != nil {
		t.Fatalf("ReadNode: %v", err)
	}
	if ping.Tag != "iq" || len(ping.Children) != 1 || ping.Children[0].Tag != "ping" {
		t.Fatalf("ReadNode decoded %#v", ping)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dialer.wait(ctx, t)
}

// TestReaderOwnershipContract covers the single-reader rule and the pairing
// entry errors: pairing owns the reader, a second pairing or a ReadNode is
// refused, and WaitPairing without StartPairing fails.
func TestReaderOwnershipContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		secure, _, err := fs.handshake(ctx, fr)
		if err != nil {
			return err
		}
		if err := secure.WriteNode(ctx, pairDeviceNode("pair-5", "s.whatsapp.net", "ref-1")); err != nil {
			return err
		}
		if _, err := secure.ReadNode(ctx); err != nil {
			return fmt.Errorf("server read ack: %w", err)
		}
		_, err = fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})

	cfg := engineConfig(fs, dialer, t)
	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := crew.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if _, err := conn.WaitPairing(ctx); !errors.Is(err, ErrPairingFailed) {
		t.Fatalf("WaitPairing before StartPairing = %v, want ErrPairingFailed", err)
	}

	codes, err := conn.StartPairing(ctx)
	if err != nil {
		t.Fatalf("StartPairing: %v", err)
	}
	if _, ok := <-codes; !ok {
		t.Fatal("no QR payload")
	}

	if _, err := conn.StartPairing(ctx); !errors.Is(err, ErrPairingFailed) {
		t.Fatalf("second StartPairing = %v, want ErrPairingFailed", err)
	}
	if _, err := conn.ReadNode(ctx); !errors.Is(err, ErrReaderBusy) {
		t.Fatalf("ReadNode during pairing = %v, want ErrReaderBusy", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	busyCtx, busyCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer busyCancel()
	if _, err := conn.WaitPairing(busyCtx); !errors.Is(err, ErrPairingFailed) {
		t.Fatalf("WaitPairing after close = %v, want ErrPairingFailed", err)
	}
	dialer.wait(ctx, t)
}

// TestPairingNeedsAdvSecret proves a zero adv secret is rejected before the
// reader is claimed, so the Conn stays usable for a pump.
func TestPairingNeedsAdvSecret(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		if _, _, err := fs.handshake(ctx, fr); err != nil {
			return err
		}
		_, err := fr.ReadFrame(ctx)
		if err != nil && !errors.Is(err, transport.ErrClosed) && ctx.Err() == nil {
			return fmt.Errorf("server idle read: %w", err)
		}
		return nil
	})

	cfg := engineConfig(fs, dialer, t)
	cfg.AdvSecret = [32]byte{}
	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := crew.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if _, err := conn.StartPairing(ctx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("StartPairing without adv secret = %v, want ErrInvalidConfig", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dialer.wait(ctx, t)
}

// TestConnectRejectsMismatchedPreKeyIdentity proves the payload is checked
// before any dial: a provider whose identity differs from the configured one
// cannot produce a coherent registration.
func TestConnectRejectsMismatchedPreKeyIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	var dialed atomic.Bool
	dialer := newFakeDialer(func(context.Context, transport.FrameConn) error {
		dialed.Store(true)
		return nil
	})
	cfg := engineConfig(fs, dialer, t)
	cfg.PreKeys = mismatchedPreKeys{}

	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := crew.Connect(ctx); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Connect = %v, want ErrAuthFailed", err)
	}
	if dialed.Load() {
		t.Fatal("Connect dialed before rejecting the mismatched prekey identity")
	}
}

// mismatchedPreKeys claims a different identity key than the engine's.
type mismatchedPreKeys struct{}

func (mismatchedPreKeys) Bundle(bool) signal.PreKeyBundle {
	var identity [32]byte
	identity[0] = 0xFF
	return signal.PreKeyBundle{IdentityKey: identity}
}
