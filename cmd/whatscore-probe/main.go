// Command whatscore-probe performs a read-only reachability probe of the
// WhatsApp Web transport: dial, send the intro header, run the Noise handshake
// with a real registration ClientPayload, then read what the server answers.
//
// It never pairs, never authenticates an account, and never sends a message.
// Its purpose is to prove the transport, the handshake, and the auth payload
// against the real endpoint; a failure is also a result, because it names the
// layer that diverges first.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/angga0x3/whatscore/internal/waref"
	"github.com/angga0x3/whatscore/protocol/auth"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// waRootPub is the pinned WhatsApp server certificate root key recorded in
// docs/protocol/noise.md (PF-009). It is a public constant, not a credential,
// and it lives in internal/waref so the probe and the server cannot pin
// different values.
var waRootPub = waref.RootPublicKey()

type outcome int

const (
	outcomeUnknown outcome = iota
	outcomeHandshakeCompleted
	outcomeServerRejected
	outcomeDialFailed
	outcomeTimeout
)

func (o outcome) String() string {
	switch o {
	case outcomeHandshakeCompleted:
		return "handshake-completed"
	case outcomeServerRejected:
		return "server-rejected"
	case outcomeDialFailed:
		return "dial-failed"
	case outcomeTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

func main() {
	endpoint := flag.String("endpoint", transport.DefaultURL, "WebSocket endpoint to probe")
	timeout := flag.Duration("timeout", 20*time.Second, "overall probe deadline")
	payload := flag.Bool("payload", false, "send a complete registration ClientPayload and read the server's answer")
	pair := flag.Bool("pair", false, "run the pairing exchange: decode pair-device, print QR payloads, and wait for pair-success")
	pairDict := flag.String("dict", "", "token table for -pair (see deployments/tokendict)")
	pairOut := flag.String("out", "", "write paired credentials to this path (mode 0600) when -pair succeeds")
	renderOnly := flag.Bool("render-only", false, "with -pair, stop after printing the QR payloads")
	loginFlag := flag.Bool("login", false, "log in with credentials a previous -pair run wrote")
	credPath := flag.String("creds", "", "credentials file for -login (the -out file from -pair)")
	loginDict := flag.String("login-dict", "", "token table for -login (defaults to -dict)")
	sendFlag := flag.Bool("send", false, "send one message using credentials a previous -pair run wrote")
	sendTo := flag.String("to", "", "recipient JID for -send")
	sendText := flag.String("text", "", "message body for -send")
	sendFile := flag.String("file", "", "file to send as media with -send (encrypted, uploaded, then messaged)")
	sendMime := flag.String("mime", "", "MIME type for -file (default: from the extension)")
	sendCaption := flag.String("caption", "", "caption for -file")
	uploadOnly := flag.Bool("upload-only", false, "with -file, upload to the CDN and stop without sending")
	listenFlag := flag.Bool("listen", false, "log in, publish prekeys, and decrypt inbound messages")
	keyPath := flag.String("keys", "", "key file for -listen (default: <creds>.keys.json)")
	mediaDir := flag.String("media", "media", "directory inbound media is written to")
	dumpPath := flag.String("dump", "", "decode one saved undecoded/*.bin frame with -dict and print its tree")
	printRoot := flag.Bool("root", false, "print the pinned root key and exit")
	flag.Parse()

	if *printRoot {
		fmt.Println(hex.EncodeToString(waRootPub))
		return
	}

	if *dumpPath != "" {
		if err := dumpUndecoded(*pairDict, *dumpPath); err != nil {
			fmt.Fprintf(os.Stderr, "dump: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *listenFlag {
		resolvedKeys := *keyPath
		if resolvedKeys == "" && *credPath != "" {
			resolvedKeys = strings.TrimSuffix(*credPath, filepath.Ext(*credPath)) + ".keys.json"
		}
		err := runListen(sendConfig{
			Endpoint: *endpoint,
			CredPath: *credPath,
			DictPath: *pairDict,
			Timeout:  *timeout,
			KeyPath:  resolvedKeys,
			MediaDir: *mediaDir,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "listen: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *sendFlag {
		// The send path shares -listen's session file: that is where the
		// peer and phone ratchets live, and a send that starts from an empty
		// store re-initiates every session. Resolve the same default.
		resolvedKeys := *keyPath
		if resolvedKeys == "" && *credPath != "" {
			resolvedKeys = strings.TrimSuffix(*credPath, filepath.Ext(*credPath)) + ".keys.json"
		}
		err := runSend(sendConfig{
			Endpoint:   *endpoint,
			CredPath:   *credPath,
			DictPath:   *pairDict,
			To:         *sendTo,
			Text:       *sendText,
			FilePath:   *sendFile,
			MimeType:   *sendMime,
			Caption:    *sendCaption,
			UploadOnly: *uploadOnly,
			Timeout:    *timeout,
			KeyPath:    resolvedKeys,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "send: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *loginFlag {
		dictPath := *loginDict
		if dictPath == "" {
			dictPath = *pairDict
		}
		err := runLogin(loginConfig{
			Endpoint: *endpoint,
			CredPath: *credPath,
			DictPath: dictPath,
			Timeout:  *timeout,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "login: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *pair {
		err := runPair(pairConfig{
			Endpoint:   *endpoint,
			DictPath:   *pairDict,
			Timeout:    *timeout,
			OutPath:    *pairOut,
			RenderOnly: *renderOnly,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "pairing: %v\n", err)
			os.Exit(1)
		}
		return
	}

	result, err := probe(context.Background(), *endpoint, *timeout, *payload)
	fmt.Printf("endpoint: %s\n", *endpoint)
	fmt.Printf("outcome:  %s\n", result.Outcome)
	if result.Detail != "" {
		fmt.Printf("detail:   %s\n", result.Detail)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	if result.Outcome == outcomeHandshakeCompleted {
		fmt.Println("interpretation: transport framing and Noise key schedule match the recorded findings")
	} else {
		fmt.Println("interpretation: the first diverging layer is reported above; record it as a finding")
	}
}

// Result is deliberately small so it can be pasted into a finding.
type Result struct {
	Outcome outcome
	Detail  string
}

func probe(ctx context.Context, endpoint string, timeout time.Duration, sendPayload bool) (Result, error) {
	return probeWithRoot(ctx, endpoint, timeout, sendPayload, waRootPub)
}

// probeWithRoot is probe with an injectable root key, so tests can run against
// a synthetic certificate chain while production pins the recorded constant.
func probeWithRoot(ctx context.Context, endpoint string, timeout time.Duration, sendPayload bool, rootPub []byte) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &transport.WebSocketDialer{HandshakeTimeoutOverride: timeout}
	fr, err := dialer.Dial(ctx, transport.Endpoint{
		URL:              endpoint,
		HandshakeTimeout: timeout,
		ExtraHeaders:     transport.DefaultEndpoint().ExtraHeaders,
	})
	if err != nil {
		return Result{Outcome: outcomeDialFailed, Detail: err.Error()}, err
	}
	defer func() { _ = fr.Close() }()

	// A fresh noise key pair stands in for the device identity: the probe only
	// needs a valid msg1/msg2 exchange, and nothing is persisted.
	noiseKey, err := noise.GenerateKeyPair()
	if err != nil {
		return Result{Outcome: outcomeUnknown, Detail: err.Error()}, err
	}

	// -payload sends a structurally complete registration payload with fresh
	// keys, which is what the server needs before it answers (PF-068).
	var payload []byte
	if sendPayload {
		built, buildErr := buildRegistrationPayload()
		if buildErr != nil {
			return Result{Outcome: outcomeUnknown, Detail: buildErr.Error()}, buildErr
		}
		payload = built
	}

	sc, err := noise.DoClientHandshake(ctx, fr, noiseKey, rootPub, payload)
	if err != nil {
		if ctx.Err() != nil {
			return Result{Outcome: outcomeTimeout, Detail: ctx.Err().Error()}, nil
		}
		return Result{Outcome: outcomeServerRejected, Detail: err.Error()}, nil
	}
	defer func() { _ = sc.Close() }()

	// Read whatever the server answers. With an incomplete payload it closes
	// the socket without a stanza (PF-068); with a complete one it speaks.
	reply, replyErr := sc.ReadFrame(ctx)
	if replyErr != nil {
		return Result{
			Outcome: outcomeHandshakeCompleted,
			Detail: fmt.Sprintf("cipher suite %s established, then %v",
				sc.CipherSuiteName(), replyErr),
		}, nil
	}
	return Result{
		Outcome: outcomeHandshakeCompleted,
		Detail: fmt.Sprintf("cipher suite %s established; server answered %d bytes (first %x)",
			sc.CipherSuiteName(), len(reply), reply[:minInt(16, len(reply))]),
	}, nil
}

// buildRegistrationPayload builds a complete registration ClientPayload with
// fresh key material. No token table is involved: this is protobuf inside the
// Noise msg3 payload, not the binary node format.
func buildRegistrationPayload() ([]byte, error) {
	identity, err := noise.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	signed, err := noise.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	var registrationID [4]byte
	if _, err := rand.Read(registrationID[:]); err != nil {
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
			RegistrationID:        binary.BigEndian.Uint32(registrationID[:]),
			IdentityKey:           identity.Pub[:],
			SignedPreKeyID:        1,
			SignedPreKey:          signed.Pub[:],
			SignedPreKeySignature: make([]byte, 64),
		},
		DeviceProps: auth.DeviceProps{
			OS:           probeOSName,
			Version:      auth.Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849},
			PlatformType: protobuf.DeviceProps_UNKNOWN,
		},
	})
}

// minInt avoids shadowing the builtin min, which the linter flags.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
