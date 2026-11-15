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
	gosignal "os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/angga0x3/whatscore/internal/tokendict"
	"github.com/angga0x3/whatscore/internal/waref"
	"github.com/angga0x3/whatscore/protocol/auth"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/pairing"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	wasignal "github.com/angga0x3/whatscore/protocol/signal"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// pairingClientType is the web client type the reference sends for a browser
// QR login (PairClientChrome).
const pairingClientType = "1"

// serverJID is the routing target for iq stanzas addressed to the server.
const serverJID = "s.whatsapp.net"

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

	ctx, stop := gosignal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
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

	stopQR := make(chan struct{})
	// Closing twice would panic, and both the success path and the deferred
	// cleanup can run, so this closes at most once per channel.
	stopRotation := func() {
		select {
		case <-stopQR:
		default:
			close(stopQR)
		}
	}
	defer stopRotation()

	for {
		frame, err := sc.ReadFrame(ctx)
		if err != nil {
			// A deadline that fires mid-pairing is the operator's own -timeout,
			// not a rejected link. Say which, so the next step is obvious.
			if ctx.Err() != nil {
				return fmt.Errorf("stopped after %s with no pairing verdict (raise -timeout to keep waiting): %w", cfg.Timeout, err)
			}
			return fmt.Errorf("read: %w", err)
		}
		node, err := codec.Decode(bytes.NewReader(frame))
		if err != nil {
			// An unknown token on a stanza we do not need yet is reportable,
			// not fatal: the operator extends the table instead of losing the
			// session. The raw frame is kept because it is the only evidence
			// that names the missing token, and re-deriving it needs a phone.
			path, werr := dumpFrame(frame)
			if werr != nil {
				fmt.Printf("undecodable stanza (%d bytes): %v (dump failed: %v)\n", len(frame), err, werr)
			} else {
				fmt.Printf("undecodable stanza (%d bytes): %v\n  raw frame kept at %s\n", len(frame), err, path)
			}
			continue
		}

		switch {
		case node.Tag == "iq" && hasChild(node, "pair-device"):
			refs, err := acknowledgePairDevice(ctx, sc, codec, node)
			if err != nil {
				return err
			}
			if cfg.RenderOnly {
				printAllCodes(refs, noiseKey, identity, advSecret)
				fmt.Println("\n-render-only: stopping after the QR payloads")
				return nil
			}
			startQRRotation(ctx, stopQR, refs, noiseKey, identity, advSecret)
		case node.Tag == "iq" && hasChild(node, "pair-success"):
			stopRotation()
			return handlePairSuccess(ctx, sc, codec, node, noiseKey, identity, advSecret, registrationID, cfg.OutPath)
		case node.Tag == "iq" && node.Attrs["xmlns"] == "urn:xmpp:ping":
			if err := answerPing(ctx, sc, codec, node); err != nil {
				return fmt.Errorf("answer ping: %w", err)
			}
		default:
			fmt.Printf("stanza: %s %v\n", node.Tag, node.Attrs)
		}
	}
}

// acknowledgePairDevice answers the pair-device iq and returns its refs.
func acknowledgePairDevice(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, node *wabinary.Node) ([]string, error) {
	refs, err := pairing.ParsePairDevice(node)
	if err != nil {
		return nil, fmt.Errorf("parse pair-device: %w", err)
	}
	ack, err := pairing.PairDeviceAck(node)
	if err != nil {
		return nil, fmt.Errorf("build ack: %w", err)
	}
	frame, err := codec.Encode(ack)
	if err != nil {
		return nil, fmt.Errorf("encode ack: %w", err)
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		return nil, fmt.Errorf("send ack: %w", err)
	}
	return refs, nil
}

// qrValidityWindow returns how long one ref stays usable. The reference uses 60
// seconds for the first of six codes and 20 seconds for the rest; printing all
// six at once therefore guarantees the phone scans an expired code.
func qrValidityWindow(index, total int) time.Duration {
	if total == 6 && index == 0 {
		return 60 * time.Second
	}
	return 20 * time.Second
}

// printAllCodes prints every code at once. Only useful for inspection: the
// server expires refs, so a human cannot scan more than the current one.
func printAllCodes(refs []string, noiseKey, identity noise.KeyPair, advSecret [32]byte) {
	for i, ref := range refs {
		payload := pairing.QRPayload{
			Ref:               ref,
			NoisePublicKey:    noiseKey.Pub,
			IdentityPublicKey: identity.Pub,
			AdvSecret:         advSecret,
			ClientType:        pairingClientType,
		}
		code, err := payload.Encode()
		if err != nil {
			fmt.Printf("encode QR payload %d: %v\n", i, err)
			continue
		}
		fmt.Printf("\n--- code %d/%d ---\n", i+1, len(refs))
		if qr, qerr := qrcode.New(code, qrcode.Medium); qerr == nil {
			fmt.Println(qr.ToSmallString(false))
		}
		fmt.Println(code)
	}
}

// startQRRotation shows one code at a time for its validity window, clearing
// the screen between codes. It stops when done or when stop is closed.
func startQRRotation(ctx context.Context, stop <-chan struct{}, refs []string, noiseKey, identity noise.KeyPair, advSecret [32]byte) {
	codes := make([]string, 0, len(refs))
	for i, ref := range refs {
		payload := pairing.QRPayload{
			Ref:               ref,
			NoisePublicKey:    noiseKey.Pub,
			IdentityPublicKey: identity.Pub,
			AdvSecret:         advSecret,
			ClientType:        pairingClientType,
		}
		code, err := payload.Encode()
		if err != nil {
			fmt.Printf("encode QR payload %d: %v\n", i, err)
			return
		}
		codes = append(codes, code)
	}

	go func() {
		completed := rotateQRCodes(ctx, stop, codes, func(index int, code string, window time.Duration) {
			clearScreen()
			fmt.Printf("code %d/%d — valid for %s. Scan now:\n", index+1, len(codes), window)
			fmt.Println("(WhatsApp > Linked devices > Link a device)")
			if qr, qerr := qrcode.New(code, qrcode.Medium); qerr == nil {
				// Small string halves the height by packing two module rows per
				// terminal line, which most phone cameras still read.
				fmt.Println(qr.ToSmallString(false))
			} else {
				fmt.Printf("(QR render failed: %v)\n", qerr)
			}
			fmt.Println(code)
		})
		if completed {
			fmt.Println("\nall codes shown; waiting for the server's answer")
		}
	}()
}

// rotateQRCodes walks the refs, handing each code to emit for exactly its
// validity window. The loop is separated from printing so the sequencing can be
// tested without a terminal or a phone.
// rotateQRCodes reports whether every ref was shown; false means it was cut
// short, so the caller does not claim the rotation finished.
func rotateQRCodes(ctx context.Context, stop <-chan struct{}, refs []string, emit func(index int, code string, window time.Duration)) bool {
	for i, ref := range refs {
		window := qrValidityWindow(i, len(refs))
		emit(i, ref, window)

		timer := time.NewTimer(window)
		select {
		case <-timer.C:
		case <-stop:
			timer.Stop()
			return false
		case <-ctx.Done():
			timer.Stop()
			return false
		}
	}
	return true
}

// clearScreen homes the cursor and clears when stdout is a terminal. Redirected
// output keeps every code, which is what a log needs.
func clearScreen() {
	if fi, err := os.Stdout.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Println()
		return
	}
	fmt.Print("\033[2J\033[H")
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

// handlePairSuccess decodes the credential material, confirms the link to the
// server, and writes the record to OutPath.
//
// The confirmation is not optional: the reference sends an iq result carrying
// <pair-device-sign><device-identity> with the self-signed identity, and only
// then does the linking complete. Skipping it leaves the phone showing a device
// that never finishes linking.
//
// Decoding needs tokens that only appear in this stanza, so a partial table
// fails here with a clear message rather than a wrong credential.
func handlePairSuccess(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, node *wabinary.Node, noiseKey, identity noise.KeyPair, advSecret [32]byte, registrationID uint32, outPath string) error {
	success, err := pairing.ParsePairSuccess(node)
	if err != nil {
		sendPairError(ctx, sc, codec, node.Attrs["id"], 500, "internal-error")
		return fmt.Errorf("parse pair-success: %w", err)
	}
	verified, err := pairing.VerifyDeviceIdentity(success.DeviceIdentity, advSecret[:], identity.Pub[:])
	if err != nil {
		// The server signed with a different account key than the one our QR
		// advertised, or the HMAC does not match. Telling the server lets the
		// phone show a reason instead of waiting forever.
		sendPairError(ctx, sc, codec, success.RequestID, 401, "signature-mismatch")
		return fmt.Errorf("verify device identity: %w", err)
	}

	signed, err := pairing.SignDeviceIdentity(verified, identity.Pub[:], wasignal.XEdDSASigner{Private: identity.Priv})
	if err != nil {
		return fmt.Errorf("sign device identity: %w", err)
	}
	if err := sendPairDeviceSign(ctx, sc, codec, success.RequestID, verified.KeyIndex, signed); err != nil {
		return fmt.Errorf("confirm pairing: %w", err)
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
	record.Device.DeviceSignature = signed

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

// sendPairDeviceSign tells the server which identity this device will present.
// The server treats the pairing as complete only after this arrives.
func sendPairDeviceSign(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, requestID string, keyIndex uint32, signedIdentity []byte) error {
	confirm := &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to":   serverJID,
			"type": "result",
			"id":   requestID,
		},
		Children: []wabinary.Node{{
			Tag: "pair-device-sign",
			Children: []wabinary.Node{{
				Tag:   "device-identity",
				Attrs: wabinary.Attrs{"key-index": strconv.FormatUint(uint64(keyIndex), 10)},
				Bytes: signedIdentity,
			}},
		}},
	}
	frame, err := codec.Encode(confirm)
	if err != nil {
		return fmt.Errorf("encode pair-device-sign: %w", err)
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		return fmt.Errorf("send pair-device-sign: %w", err)
	}
	fmt.Println("pair-device-sign sent")
	return nil
}

// sendPairError reports a failure to the server the way the reference does, so
// the phone shows a specific reason instead of a generic link failure.
func sendPairError(ctx context.Context, sc noise.SecureConn, codec wabinary.Codec, requestID string, code int, text string) {
	errNode := &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to":   serverJID,
			"type": "error",
			"id":   requestID,
		},
		Children: []wabinary.Node{{
			Tag:   "error",
			Attrs: wabinary.Attrs{"code": strconv.Itoa(code), "text": text},
		}},
	}
	frame, err := codec.Encode(errNode)
	if err != nil {
		fmt.Printf("could not encode pair error: %v\n", err)
		return
	}
	if err := sc.WriteFrame(ctx, frame); err != nil {
		fmt.Printf("could not send pair error: %v\n", err)
	}
}

// dumpFrame writes an undecodable frame to a file so the missing token can be
// recovered later. The bytes are the only record of a stanza that a phone scan
// produced, and producing it again costs another pairing attempt.
func dumpFrame(frame []byte) (string, error) {
	dir := "undecoded"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, time.Now().UTC().Format("20060102T150405.000000000")+".bin")
	if err := os.WriteFile(path, frame, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// qrStringForTest renders a payload and returns the string the encoder was
// given, so a test can assert the QR carries it verbatim.
func qrStringForTest(payload string) (string, error) {
	if _, err := qrcode.New(payload, qrcode.Medium); err != nil {
		return "", err
	}
	return payload, nil
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
//
// The signed prekey must be signed by that same identity key: the server
// verifies eSkeySig with eIdent before it will let the phone link the device.
// A zero-filled signature passes local validation (it is 64 bytes) but fails
// that check, and the phone then reports only "couldn't link new device".
func buildPairingPayload(identity noise.KeyPair, registrationID uint32) ([]byte, error) {
	identityPair := wasignal.KeyPair{Private: identity.Priv, Public: identity.Pub}
	signed, err := wasignal.GenerateSignedPreKey(1, wasignal.XEdDSASigner{Private: identity.Priv})
	if err != nil {
		return nil, fmt.Errorf("signed prekey: %w", err)
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
			IdentityKey:           identityPair.Public[:],
			SignedPreKeyID:        signed.ID,
			SignedPreKey:          signed.Pair.Public[:],
			SignedPreKeySignature: signed.Signature,
		},
		DeviceProps: auth.DeviceProps{
			OS:      "whatsmeow",
			Version: auth.Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849},
			// The reference reports a concrete browser platform for a QR
			// login, and its client-type field derives from it. UNKNOWN is
			// not what a web pairing ever sends.
			PlatformType: protobuf.DeviceProps_CHROME,
			HistorySync:  pairingHistorySync(),
		},
	})
}

// pairingHistorySync mirrors the capability block the reference advertises for
// a companion device. It is sent, not negotiated: the phone decides what to
// sync from these flags.
func pairingHistorySync() *auth.HistorySync {
	return &auth.HistorySync{
		StorageQuotaMB:                 10240,
		InlineInitialPayload:           true,
		SupportCallLogHistory:          true,
		SupportBotUserAgentChatHistory: true,
		SupportCagReactionsAndPolls:    true,
		SupportBizHostedMsg:            true,
		SupportRecentSyncChunkTuning:   true,
		SupportHostedGroupMsg:          true,
		SupportFbidBotChatHistory:      true,
		SupportMessageAssociation:      true,
		SupportGroupHistory:            true,
		ThumbnailSyncDaysLimit:         60,
		SupportManusHistory:            true,
		SupportHatchHistory:            true,
	}
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
	DeviceSignature  []byte `json:"device_signature"`
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
