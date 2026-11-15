package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	gosignal "os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/angga0x3/whatscore/internal/waref"
	"github.com/angga0x3/whatscore/protocol/auth"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// loginConfig is one attempt to authenticate a paired device.
type loginConfig struct {
	Endpoint string
	CredPath string
	DictPath string
	Timeout  time.Duration
}

// runLogin reconnects with the credentials a pairing run wrote and reports the
// server's verdict.
//
// Pairing and logging in are separate acts (PF-077). Pairing proves the device
// to the account; the phone stops waiting only when that same device connects
// and the server answers "success". A tool that stops at the credential file
// leaves the phone spinning forever.
func runLogin(cfg loginConfig) error {
	record, err := loadCredentialRecord(cfg.CredPath)
	if err != nil {
		return err
	}
	jid, err := messaging.ParseJID(record.JID)
	if err != nil {
		return fmt.Errorf("parse jid %q: %w", record.JID, err)
	}
	if jid.User == "" {
		return fmt.Errorf("credential jid %q has no user part", record.JID)
	}
	username, err := strconv.ParseUint(jid.User, 10, 64)
	if err != nil {
		return fmt.Errorf("credential jid user %q is not a number: %w", jid.User, err)
	}

	dict, err := loadDictionary(cfg.DictPath)
	if err != nil {
		return err
	}
	codec := wabinary.NewCodec(dict)

	ctx, stop := gosignal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	// The noise static key must be the one the QR advertised: the server ties
	// the device to it during pairing.
	noiseKey := noise.KeyPair{Priv: record.NoisePriv, Pub: record.NoisePub}
	payload, err := auth.BuildLoginPayload(auth.LoginInput{
		Version:       loginVersion,
		UserAgent:     loginUserAgent,
		WebInfo:       auth.WebInfo{SubPlatform: protobuf.ClientPayload_WebInfo_WEB_BROWSER},
		ConnectType:   protobuf.ClientPayload_WIFI_UNKNOWN,
		ConnectReason: protobuf.ClientPayload_USER_ACTIVATED,
		Username:      username,
		Device:        uint32(jid.Device),
	})
	if err != nil {
		return fmt.Errorf("build login payload: %w", err)
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

	sc, err := noise.DoClientHandshake(ctx, fr, noiseKey, waref.RootPublicKey(), payload)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	defer func() { _ = sc.Close() }()
	fmt.Printf("handshake: ok — logging in as %s device %d\n", jid.User, jid.Device)

	authenticated := false
	for {
		frame, err := sc.ReadFrame(ctx)
		if err != nil {
			// After <success> the login is already decided; a later read failure
			// is the server idling the stream, not a rejected login.
			if authenticated {
				fmt.Println("\nsession stayed authenticated; stream closed by the server")
				return nil
			}
			if ctx.Err() != nil {
				return fmt.Errorf("stopped after %s with no verdict from the server (raise -timeout): %w", cfg.Timeout, err)
			}
			return fmt.Errorf("read: %w", err)
		}
		node, err := codec.Decode(bytes.NewReader(frame))
		if err != nil {
			path, werr := dumpFrame(frame)
			if werr != nil {
				fmt.Printf("undecodable stanza (%d bytes): %v (dump failed: %v)\n", len(frame), err, werr)
			} else {
				fmt.Printf("undecodable stanza (%d bytes): %v\n  raw frame kept at %s\n", len(frame), err, path)
			}
			continue
		}
		ok, err := handleLoginNode(ctx, sc, codec, node)
		if err != nil {
			return err
		}
		if ok {
			authenticated = true
		}
	}
}

// handleLoginNode interprets the nodes that decide whether the login worked.
func handleLoginNode(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, node *wabinary.Node) (bool, error) {
	switch {
	case node.Tag == "success":
		fmt.Println("\nLOGIN OK: the server authenticated this device")
		printAttrs(node)
		return true, nil
	case node.Tag == "failure":
		fmt.Println("\nLOGIN FAILED: the server rejected the login payload")
		printAttrs(node)
		return false, fmt.Errorf("login rejected: reason=%q", node.Attrs["reason"])
	case node.Tag == "stream:error":
		fmt.Println("\nSTREAM ERROR")
		printAttrs(node)
		for i := range node.Children {
			fmt.Printf("  child: %s %v\n", node.Children[i].Tag, node.Children[i].Attrs)
		}
		return false, nil
	case node.Tag == "iq" && node.Attrs["xmlns"] == "urn:xmpp:ping":
		if err := answerPing(ctx, sc, codec, node); err != nil {
			return false, fmt.Errorf("answer ping: %w", err)
		}
		return false, nil
	case node.Tag == "ib":
		// Initial data: the server's first push after login. Printing the child
		// tags is enough to show the session is live without parsing them.
		for i := range node.Children {
			fmt.Printf("ib: %s %v\n", node.Children[i].Tag, node.Children[i].Attrs)
		}
		return false, nil
	default:
		fmt.Printf("stanza: %s %v\n", node.Tag, node.Attrs)
		return false, nil
	}
}

func printAttrs(node *wabinary.Node) {
	for k, v := range node.Attrs {
		fmt.Printf("  %s=%s\n", k, v)
	}
}

// loginVersion and loginUserAgent describe the same client the pairing run
// reported, so the server sees one consistent device across both connections.
var loginVersion = auth.Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849}

var loginUserAgent = auth.UserAgent{
	Platform:       protobuf.ClientPayload_UserAgent_WEB,
	ReleaseChannel: protobuf.ClientPayload_UserAgent_RELEASE,
	MCC:            "000",
	MNC:            "000",
	OSVersion:      "0.1",
	Device:         "Desktop",
	OSBuildNumber:  "0.1",
	LocaleLanguage: "en",
	LocaleCountry:  "US",
}

func loadCredentialRecord(path string) (*credentialRecord, error) {
	if path == "" {
		return nil, fmt.Errorf("login needs credentials: pass -creds with the file -pair wrote")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	var record credentialRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	if record.NoisePriv == ([32]byte{}) || record.IdentityPriv == ([32]byte{}) {
		return nil, fmt.Errorf("credentials at %s have no key material", path)
	}
	if record.AdvSecret == ([32]byte{}) {
		return nil, fmt.Errorf("credentials at %s have no adv secret", path)
	}
	if record.JID == "" {
		return nil, fmt.Errorf("credentials at %s have no jid", path)
	}
	return &record, nil
}
