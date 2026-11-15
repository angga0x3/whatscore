package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// TestPairingConnectorPairsThenLogsIn drives the full pairing-over-Connect
// flow: registration payload → pair-device → QR event on the bus →
// pair-success verified → pair-device-sign received by the server (PF-073) →
// credentials handed to the persistence hook → fresh dial with the login
// payload → <success>. The session actor sees one Connect that ends CONNECTED.
func TestPairingConnectorPairsThenLogsIn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fs := newFakeServer(t)
	cfg := engineConfig(fs, nil, t)
	cfg.Signer = &deterministicSigner{}
	cfg.Bus = events.NewBus()
	defer cfg.Bus.Close()
	qrSub := cfg.Bus.Subscribe()
	defer qrSub.Close()

	var dials atomic.Int64
	var sawSignNode bool
	var diagMu sync.Mutex
	serverDiag := "not read yet"
	record := func(format string, args ...any) {
		diagMu.Lock()
		serverDiag = fmt.Sprintf(format, args...)
		diagMu.Unlock()
	}
	dialer := newFakeDialer(func(ctx context.Context, fr transport.FrameConn) error {
		switch dials.Add(1) {
		case 1: // the pairing connection
			secure, _, err := fs.handshake(ctx, fr)
			if err != nil {
				return err
			}
			if err := secure.WriteNode(ctx, pairDeviceNode("pair-p", "s.whatsapp.net", "ref-1")); err != nil {
				return err
			}
			if _, err := secure.ReadNode(ctx); err != nil {
				return fmt.Errorf("server read ack: %w", err)
			}
			container := deviceIdentityContainer(t, cfg.AdvSecret[:], cfg.Identity.Public[:], 88)
			if err := secure.WriteNode(ctx, pairSuccessNode(t, "pair-p", container)); err != nil {
				return err
			}
			// PF-073: the client must answer with <iq><pair-device-sign>
			// carrying the self-signed device identity.
			sign, err := secure.ReadNode(ctx)
			if err != nil {
				record("read error: %v", err)
				return fmt.Errorf("server read pair-device-sign: %w", err)
			}
			record("node: tag=%q attrs=%v children=%d", sign.Tag, sign.Attrs, len(sign.Children))
			check := func() error {
				if sign.Tag != "iq" || sign.Attrs["type"] != "result" || sign.Attrs["id"] != "pair-p" {
					return fmt.Errorf("pair-device-sign wrapper = %#v", sign)
				}
				signChild := childOf(sign, "pair-device-sign")
				if signChild == nil {
					return errors.New("no pair-device-sign child")
				}
				identity := childOf(signChild, "device-identity")
				if identity == nil || len(identity.Bytes) == 0 {
					return errors.New("pair-device-sign carries no device-identity blob")
				}
				if got := identity.Attrs["key-index"]; got != "1" {
					return fmt.Errorf("key-index = %q, want 1", got)
				}
				return nil
			}
			if err := check(); err != nil {
				record("check failed: %v", err)
				return err
			}
			record("pair-device-sign verified")
			diagMu.Lock()
			sawSignNode = true
			diagMu.Unlock()
			_, _ = fr.ReadFrame(ctx) // hold until the client retires the pairing connection
			return nil
		case 2: // the login connection
			secure, _, err := fs.handshake(ctx, fr)
			if err != nil {
				return err
			}
			if err := secure.WriteNode(ctx, &binary.Node{Tag: "success"}); err != nil {
				return err
			}
			_, _ = fr.ReadFrame(ctx) // hold until the session hands the conn over
			return nil
		default:
			return errors.New("unexpected extra dial")
		}
	})
	cfg.Dialer = dialer

	crew, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var paired CredentialResult
	var pairedCalled atomic.Bool
	pc := crew.PairingConnector(func(result CredentialResult) error {
		paired = result
		pairedCalled.Store(true)
		return nil
	})

	raw, err := dialer.Dial(ctx, cfg.Endpoint)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	secure, err := pc.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if dials.Load() != 2 {
		t.Fatalf("dial count = %d, want 2 (pairing then login)", dials.Load())
	}
	diagMu.Lock()
	signSeen, diag := sawSignNode, serverDiag
	diagMu.Unlock()
	if !signSeen {
		t.Fatalf("the server never received pair-device-sign (server diag: %s)", diag)
	}
	if !pairedCalled.Load() {
		t.Fatal("onPaired was never called")
	}
	if paired.JID != "5511999999999:8@s.whatsapp.net" {
		t.Fatalf("paired JID = %q", paired.JID)
	}
	if len(paired.SignedIdentity) == 0 {
		t.Fatal("result carries no SignedIdentity blob")
	}
	select {
	case ev := <-qrSub.C:
		if ev.Type != events.TypePairingCode || ev.PairingCode == nil || ev.PairingCode.Code == "" {
			t.Fatalf("QR event = %#v", ev)
		}
	default:
		t.Fatal("no QR event was published to the bus")
	}
	if secure == nil {
		t.Fatal("Connect returned a nil login connection")
	}
	_ = secure.Close()
	dialer.wait(ctx, t)
}

// TestPairingConnectorRefusesPairedEngine pins the mode guard: a pairing
// connector handed an engine that already carries credentials is a wiring
// mistake and must fail instead of pair.
func TestPairingConnectorRefusesPairedEngine(t *testing.T) {
	fs := newFakeServer(t)
	cfg := engineConfig(fs, newFakeDialer(func(context.Context, transport.FrameConn) error {
		return nil
	}), t)
	cfg.Credentials = &Credentials{Username: 628123, Device: 37}
	crew, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pc := crew.PairingConnector(nil)
	client, _ := newPipePair()
	if _, err := pc.Connect(context.Background(), client); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
}
