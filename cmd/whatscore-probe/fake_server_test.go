package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// probeTestServer runs the server side of PF-007 over a real WebSocket so the
// probe tool is exercised end to end, not against mocks.
func probeTestServer(ctx context.Context, ws *websocket.Conn, serverEph, serverStatic noise.KeyPair, certBlob []byte) error {
	fc := newProbeFrameConn(ws)

	msg1, err := fc.readFrame(ctx)
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	var hello protobuf.HandshakeMessage
	if err := proto.Unmarshal(msg1, &hello); err != nil {
		return fmt.Errorf("unmarshal hello: %w", err)
	}
	var clientEph [32]byte
	copy(clientEph[:], hello.GetClientHello().GetEphemeral())
	if clientEph == ([32]byte{}) {
		return fmt.Errorf("empty client ephemeral")
	}

	hs := noise.NewHandshake()
	hs.Start(transport.IntroHeader)
	hs.Authenticate(clientEph[:])
	hs.Authenticate(serverEph.Pub[:])
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientEph); err != nil {
		return err
	}
	encStatic, err := hs.Encrypt(serverStatic.Pub[:])
	if err != nil {
		return err
	}
	if err := hs.MixSharedSecretIntoKey(serverStatic.Priv, clientEph); err != nil {
		return err
	}
	encCert, err := hs.Encrypt(certBlob)
	if err != nil {
		return err
	}
	msg2, err := proto.Marshal(&protobuf.HandshakeMessage{
		ServerHello: &protobuf.HandshakeMessage_ServerHello{
			Ephemeral: serverEph.Pub[:], Static: encStatic, Payload: encCert,
		},
	})
	if err != nil {
		return err
	}
	if err := fc.writeFrame(ctx, msg2); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}

	msg3, err := fc.readFrame(ctx)
	if err != nil {
		return fmt.Errorf("read finish: %w", err)
	}
	var finish protobuf.HandshakeMessage
	if err := proto.Unmarshal(msg3, &finish); err != nil {
		return err
	}
	clientStaticBytes, err := hs.Decrypt(finish.GetClientFinish().GetStatic())
	if err != nil {
		return fmt.Errorf("decrypt static: %w", err)
	}
	if len(clientStaticBytes) != 32 {
		return fmt.Errorf("client static is %d bytes", len(clientStaticBytes))
	}
	var clientStatic [32]byte
	copy(clientStatic[:], clientStaticBytes)
	if err := hs.MixSharedSecretIntoKey(serverEph.Priv, clientStatic); err != nil {
		return err
	}
	if _, err := hs.Decrypt(finish.GetClientFinish().GetPayload()); err != nil {
		return fmt.Errorf("decrypt payload: %w", err)
	}
	return nil
}

type probeFrameConn struct {
	ws      *websocket.Conn
	buf     []byte
	hasInit bool
}

func newProbeFrameConn(ws *websocket.Conn) *probeFrameConn { return &probeFrameConn{ws: ws} }

func (c *probeFrameConn) readFrame(ctx context.Context) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.ws.SetReadDeadline(deadline)
	} else {
		_ = c.ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	for {
		if !c.hasInit {
			if len(c.buf) < len(transport.IntroHeader) {
				if err := c.readMore(); err != nil {
					return nil, err
				}
				continue
			}
			if !bytes.Equal(c.buf[:len(transport.IntroHeader)], transport.IntroHeader) {
				return nil, fmt.Errorf("bad intro header %x", c.buf[:4])
			}
			c.buf = c.buf[len(transport.IntroHeader):]
			c.hasInit = true
		}
		if len(c.buf) >= 3 {
			n := int(c.buf[0])<<16 | int(c.buf[1])<<8 | int(c.buf[2])
			if len(c.buf) >= 3+n {
				frame := append([]byte(nil), c.buf[3:3+n]...)
				c.buf = c.buf[3+n:]
				return frame, nil
			}
		}
		if err := c.readMore(); err != nil {
			return nil, err
		}
	}
}

func (c *probeFrameConn) readMore() error {
	msgType, data, err := c.ws.ReadMessage()
	if err != nil {
		return err
	}
	if msgType != websocket.BinaryMessage {
		return fmt.Errorf("unexpected message type %d", msgType)
	}
	c.buf = append(c.buf, data...)
	return nil
}

func (c *probeFrameConn) writeFrame(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n := len(frame)
	msg := []byte{byte(n >> 16), byte(n >> 8), byte(n)}
	msg = append(msg, frame...)
	return c.ws.WriteMessage(websocket.BinaryMessage, msg)
}

var probeP = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// probeTestKeypair returns an Ed25519 key whose Edwards x is even, plus the
// matching Montgomery u coordinate (PF-009).
func probeTestKeypair(t *testing.T) (ed25519.PrivateKey, [32]byte) {
	t.Helper()
	for attempt := 0; attempt < 1000; attempt++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if pub[31]&0x80 != 0 {
			continue
		}
		yb := make([]byte, 32)
		for i := range pub {
			yb[i] = pub[31-i]
		}
		yb[0] &= 0x7f
		y := new(big.Int).SetBytes(yb)
		den := new(big.Int).Sub(big.NewInt(1), y)
		den.Mod(den, probeP)
		inv := new(big.Int).ModInverse(den, probeP)
		if inv == nil {
			continue
		}
		u := new(big.Int).Mul(new(big.Int).Add(big.NewInt(1), y), inv)
		u.Mod(u, probeP)
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

func probeTestCertChain(t *testing.T, rootEd, intEd ed25519.PrivateKey, intMont [32]byte, leafKey []byte) []byte {
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
		Leaf:         &protobuf.CertChain_NoiseCertificate{Details: leafDetails, Signature: ed25519.Sign(intEd, leafDetails)},
		Intermediate: &protobuf.CertChain_NoiseCertificate{Details: intDetails, Signature: ed25519.Sign(rootEd, intDetails)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
