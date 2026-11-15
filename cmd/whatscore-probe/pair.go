package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/angga0x3/whatscore/internal/tokendict"
	"github.com/angga0x3/whatscore/internal/waref"
	"github.com/angga0x3/whatscore/protocol/auth"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/pairing"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// pairConfig collects everything one pairing attempt needs.
type pairConfig struct {
	Endpoint   string
	DictPath   string
	Timeout    time.Duration
	OutPath    string
	RenderOnly bool
}

// runPair performs the pairing exchange: handshake, decode pair-device, render
// the refs as QR payloads, answer keepalives, and wait for pair-success.
//
// It stops at the first thing it cannot do and says so, because a partial
// pairing is worse than none: the credential record would be unusable.
func runPair(cfg pairConfig) error {
	dictionary, err := loadDictionary(cfg.DictPath)
	if err != nil {
		return err
	}
	codec := wabinary.NewCodec(dictionary)

	// Fresh key material: pairing binds the noise key, the identity key, and the
	// advertising secret into the QR payload.
	noiseKey, err := noise.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("noise key: %w", err)
	}
	identity, err := noise.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("identity key: %w", err)
	}
	var advSecret [32]byte
	if _, err := rand.Read(advSecret[:]); err != nil {
		return fmt.Errorf("adv secret: %w", err)
	}
	var regIDBytes [4]byte
	if _, err := rand.Read(regIDBytes[:]); err != nil {
		return fmt.Errorf("registration id: %w", err)
	}
	registrationID := binary.BigEndian.Uint32(regIDBytes[:])

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	dialer := &transport.WebSocketDialer{HandshakeTimeoutOverride: 20 * time.Second}
	endpoint := transport.DefaultEndpoint()
	if cfg.Endpoint != "" {
		endpoint.URL = cfg.Endpoint
	}
	fr, err := dialer.Dial(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = fr.Close() }()

	payload, err := buildPairingPayload(identity, registrationID)
	if err != nil {
		return err
	}
	sc, err := noise.DoClientHandshake(ctx, fr, noiseKey, waref.RootPublicKey(), payload)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	defer func() { _ = sc.Close() }()
	fmt.Println("handshake: ok")

	for {
		frame, err := sc.ReadFrame(ctx)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		node, err := codec.Decode(bytes.NewReader(frame))
		if err != nil {
			// The only decoding failure that is not fatal here is an unknown
			// token on a stanza we do not need yet; report and continue so the
			// operator can extend the table instead of losing the session.
			fmt.Printf("undecodable stanza (%d bytes): %v\n", len(frame), err)
			continue
		}

		switch {
		case node.Tag == "iq" && hasChild(node, "pair-device"):
			if err := handlePairDevice(ctx, sc, codec, node, noiseKey, identity, advSecret); err != nil {
				return err
			}
			if cfg.RenderOnly {
				fmt.Println("\n-render-only: stopping after the QR payloads")
				return nil
			}
		case node.Tag == "iq" && hasChild(node, "pair-success"):
			return handlePairSuccess(node, noiseKey, identity, advSecret, registrationID, cfg.OutPath)
		case node.Tag == "iq" && node.Attrs["xmlns"] == "urn:xmpp:ping":
			if err := answerPing(ctx, sc, codec, node); err != nil {
				return fmt.Errorf("answer ping: %w", err)
			}
		default:
			fmt.Printf("stanza: %s %v\n", node.Tag, node.Attrs)
		}
	}
}

// handlePairDevice acknowledges the stanza and prints one QR payload per ref.
func handlePairDevice(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, node *wabinary.Node, noiseKey noise.KeyPair, identity noise.KeyPair, advSecret [32]byte) error {
	refs, err := pairing.ParsePairDevice(node)
	if err != nil {
		return fmt.Errorf("parse pair-device: %w", err)
	}
	ack, err := pairing.PairDeviceAck(node)
	if err != nil {
		return fmt.Errorf("build ack: %w", err)
	}
	frame, err := codec.Encode(ack)
	if err != nil {
		return fmt.Errorf("encode ack: %w", err)
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		return fmt.Errorf("send ack: %w", err)
	}

	fmt.Printf("\n%d pairing refs received. Scan ONE of these with the phone\n", len(refs))
	fmt.Println("(WhatsApp > Linked devices > Link a device):")
	for i, ref := range refs {
		payload := pairing.QRPayload{
			Ref:               ref,
			NoisePublicKey:    noiseKey.Pub,
			IdentityPublicKey: identity.Pub,
			AdvSecret:         advSecret,
			ClientType:        "1",
		}
		code, err := payload.Encode()
		if err != nil {
			return fmt.Errorf("encode QR payload %d: %w", i, err)
		}
		fmt.Printf("\n--- code %d/%d ---\n%s\n", i+1, len(refs), code)
	}
	fmt.Println()
	return nil
}

// answerPing replies to the keepalive so the server keeps the socket open
// (PF-070). Without this the connection drops after roughly 30 seconds.
func answerPing(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, node *wabinary.Node) error {
	pong := &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to":   "s.whatsapp.net",
			"type": "result",
			"id":   node.Attrs["id"],
		},
	}
	frame, err := codec.Encode(pong)
	if err != nil {
		return err
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		return err
	}
	fmt.Printf("keepalive answered (t=%s)\n", node.Attrs["t"])
	return nil
}

// handlePairSuccess decodes the credential material and writes it to OutPath.
//
// Decoding needs tokens that only appear in this stanza, so a partial table
// fails here with a clear message rather than a wrong credential.
func handlePairSuccess(node *wabinary.Node, noiseKey, identity noise.KeyPair, advSecret [32]byte, registrationID uint32, outPath string) error {
	success, err := pairing.ParsePairSuccess(node)
	if err != nil {
		return fmt.Errorf("parse pair-success: %w", err)
	}
	verified, err := pairing.VerifyDeviceIdentity(success.DeviceIdentity, advSecret[:], identity.Pub[:])
	if err != nil {
		return fmt.Errorf("verify device identity: %w", err)
	}
	fmt.Printf("\nPAIRED: jid=%s lid=%s platform=%s\n", success.ID, success.LID, success.Platform)

	record := &credentialRecord{
		JID:            success.ID,
		LID:            success.LID,
		Platform:       success.Platform,
		BusinessName:   success.BusinessName,
		RegistrationID: registrationID,
		NoisePriv:      noiseKey.Priv,
		NoisePub:       noiseKey.Pub,
		IdentityPriv:   identity.Priv,
		IdentityPub:    identity.Pub,
		AdvSecret:      advSecret,
	}
	record.Device.RawID = verified.RawID
	record.Device.Timestamp = verified.Timestamp
	record.Device.KeyIndex = verified.KeyIndex
	record.Device.AccountType = int32(verified.AccountType)
	record.Device.DeviceType = int32(verified.DeviceType)
	record.Device.Details = verified.Details
	record.Device.AccountKey = verified.AccountKey
	record.Device.AccountSignature = verified.AccountSignature

	if outPath == "" {
		fmt.Println("\nno -out given; credentials not written")
		return nil
	}
	if err := writeCredentialRecord(outPath, record); err != nil {
		return err
	}
	fmt.Printf("credentials written to %s (mode 0600)\n", outPath)
	return nil
}

// loadDictionary requires a table: pairing cannot decode anything without one.
func loadDictionary(path string) (*wabinary.Dictionary, error) {
	if path == "" {
		return nil, errors.New("pairing needs a token table: pass -dict (see deployments/tokendict)")
	}
	table, err := tokendict.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load dictionary: %w", err)
	}
	return tokendict.Build(table)
}

// buildPairingPayload is the payload the server needs before it speaks (PF-068),
// bound to the identity key that will appear in the QR so the certificate chain
// and the pairing payload describe the same device.
func buildPairingPayload(identity noise.KeyPair, registrationID uint32) ([]byte, error) {
	signed, err := noise.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return auth.BuildClientPayload(auth.Input{
		Version: auth.Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849},
		UserAgent: auth.UserAgent{
			Platform:       protobuf.ClientPayload_UserAgent_WEB,
			ReleaseChannel: protobuf.ClientPayload_UserAgent_RELEASE,
			MCC:            "000",
			MNC:            "000",
			OSVersion:      "0.1",
			Device:         "Desktop",
			OSBuildNumber:  "0.1",
			LocaleLanguage: "en",
			LocaleCountry:  "US",
		},
		WebInfo:       auth.WebInfo{SubPlatform: protobuf.ClientPayload_WebInfo_WEB_BROWSER},
		ConnectType:   protobuf.ClientPayload_WIFI_UNKNOWN,
		ConnectReason: protobuf.ClientPayload_USER_ACTIVATED,
		Registration: auth.Registration{
			RegistrationID:        registrationID,
			IdentityKey:           identity.Pub[:],
			SignedPreKeyID:        1,
			SignedPreKey:          signed.Pub[:],
			SignedPreKeySignature: make([]byte, 64),
		},
		DeviceProps: auth.DeviceProps{
			OS:           "whatsmeow",
			Version:      auth.Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849},
			PlatformType: protobuf.DeviceProps_UNKNOWN,
		},
	})
}

func hasChild(node *wabinary.Node, tag string) bool {
	for i := range node.Children {
		if node.Children[i].Tag == tag {
			return true
		}
	}
	return false
}

// credentialRecord is the on-disk shape this command writes. It is deliberately
// its own struct: the probe must not depend on the application layer.
type credentialRecord struct {
	JID            string    `json:"jid"`
	LID            string    `json:"lid,omitempty"`
	Platform       string    `json:"platform,omitempty"`
	BusinessName   string    `json:"business_name,omitempty"`
	RegistrationID uint32    `json:"registration_id"`
	NoisePriv      [32]byte  `json:"noise_private_key"`
	NoisePub       [32]byte  `json:"noise_public_key"`
	IdentityPriv   [32]byte  `json:"identity_private_key"`
	IdentityPub    [32]byte  `json:"identity_public_key"`
	AdvSecret      [32]byte  `json:"adv_secret"`
	Device         deviceRec `json:"device_identity"`
	PairedAt       time.Time `json:"paired_at"`
}

type deviceRec struct {
	RawID            uint32 `json:"raw_id"`
	Timestamp        uint64 `json:"timestamp"`
	KeyIndex         uint32 `json:"key_index"`
	AccountType      int32  `json:"account_type"`
	DeviceType       int32  `json:"device_type"`
	Details          []byte `json:"details"`
	AccountKey       []byte `json:"account_key"`
	AccountSignature []byte `json:"account_signature"`
}

func writeCredentialRecord(path string, record *credentialRecord) error {
	record.PairedAt = time.Now().UTC()
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
