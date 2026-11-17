package main

import (
	"context"
	"fmt"
	gosignal "os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/internal/waref"
	"github.com/angga0x3/whatscore/protocol/auth"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
	"github.com/angga0x3/whatscore/protocol/transport"
)

// sendConfig is one attempt to deliver a message: text, or one media file.
type sendConfig struct {
	Endpoint string
	CredPath string
	DictPath string
	To       string
	Text     string
	// FilePath turns the send into a media send: the file is encrypted,
	// uploaded, and the message protobuf carries its CDN location.
	FilePath string
	MimeType string
	Caption  string
	// UploadOnly stops after the media upload, before anything is sent. It
	// exists so the CDN half of PF-092 can be proven without putting a
	// message on anyone's phone.
	UploadOnly bool
	Timeout    time.Duration
	KeyPath    string
	MediaDir   string
	// AutoRead marks every decrypted inbound message as read — the blue
	// ticks on the sender's phone. Off by default: reading is a choice.
	AutoRead bool
}

// runSend logs in with stored credentials and sends one text message.
//
// Sending needs three things beyond a login: this device's prekeys published to
// the server, the peer's bundle fetched back, and a Signal session built from
// them. Each is a separate server round trip, and each can fail on its own, so
// the steps are reported as they happen rather than as one opaque result.
func runSend(cfg sendConfig) error {
	record, err := loadCredentialRecord(cfg.CredPath)
	if err != nil {
		return err
	}
	login, err := parseLoginIdentity(record)
	if err != nil {
		return err
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

	sc, err := dialLogin(ctx, cfg.Endpoint, record, login)
	if err != nil {
		return err
	}
	defer func() { _ = sc.Close() }()

	d := newDispatcher(sc, codec)
	d.holeCodec = wabinary.NewCodec(holeFilled(dict))
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		d.run(ctx)
	}()
	defer func() {
		d.shutdown()
		<-loopDone
	}()
	if err := awaitSuccessVerdict(ctx, d); err != nil {
		return err
	}

	// Prekeys are not uploaded here. Pairing published a working set, and the
	// server accepts one upload per device: a repeat is answered with silence
	// or an immediate close, which would end the connection this send needs.
	// The keys are managed by -listen, which owns the persistent key file.

	// 2. Resolve the destination and restore what this device already knows.
	//    A session the listener bootstrapped is the one this send must
	//    continue: re-initiating would spend another one-time prekey and
	//    orphan the chain the peer is already answering on.
	peerJID, err := stanza.ParseJID(cfg.To)
	if err != nil {
		return fmt.Errorf("to %q: %w", cfg.To, err)
	}
	sessionsPath := sessionsPathFor(cfg.KeyPath)
	sessions, err := loadSessionsFile(sessionsPath)
	if err != nil {
		return err
	}

	// 3. Encrypt and send.
	identityPair := signal.KeyPair{Private: record.IdentityPriv, Public: record.IdentityPub}
	sender, err := messaging.NewSender(frameWriter{sc}, messaging.WithCodec(codec))
	if err != nil {
		return err
	}
	sender.SetIdentityPair(identityPair)
	blob, err := deviceIdentityBytes(record)
	if err != nil {
		return fmt.Errorf("paired device identity: %w", err)
	}
	sender.SetDeviceIdentity(blob)
	sender.SetPreKeyBundleSource(directBundles{d})
	if n, err := sessions.installSender(sender); err != nil {
		return err
	} else if n > 0 {
		fmt.Printf("sessions: %d restored from %s\n", n, sessionsPath)
	}

	// The message itself: a text conversation, or one uploaded attachment.
	inner, msgType, err := buildOutgoing(ctx, d, cfg)
	if err != nil {
		return err
	}
	if cfg.UploadOnly {
		fmt.Println("upload-only: nothing was sent")
		return nil
	}
	// Group destinations take the sender-key path: one skmsg for the group
	// content, the SKDM pairwise to every member device, phash for the
	// fanout. The sender key is ephemeral (v1).
	if peerJID.Server == "g.us" {
		id, devices, groupErr := sendGroupText(ctx, d, sc, codec, record, peerJID.String(), cfg.Text)
		if groupErr != nil {
			return fmt.Errorf("group send: %w", groupErr)
		}
		fmt.Printf("\nSENT (group): id=%s to=%s, SKDM to %d devices\n", id, peerJID.String(), len(devices))
		return awaitAck(ctx, d, id, 20*time.Second)
	}

	// The id is minted here, not inside the sender, because the own-device
	// copy below must carry the same one: one logical message, two
	// ciphertexts. A second id would make the phone show the send twice.
	id, err := randomID()
	if err != nil {
		return err
	}
	id, deviceSessions, err := sender.SendDirect(ctx, directDevices{d}, messaging.DirectMessage{
		To: peerJID.String(), ID: id, Type: msgType, Message: inner,
		OwnJID: record.JID, OwnLID: record.LID, RegistrationID: record.RegistrationID,
		Persist: func(_ context.Context, peer string, session *messaging.PeerSession) error {
			return sessions.persist(sessionsPath, peer, session)
		},
	})
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	fmt.Printf("\nSENT: id=%s to=%s (%d device ciphertexts, one stanza)\n", id, peerJID.String(), len(deviceSessions))

	// Writing the frame only proves the bytes left. The server answers with an
	// ack, an error, or silence, and only the first two mean anything.
	return awaitAck(ctx, d, id, 20*time.Second)
}

// awaitAck waits for the server's acknowledgement of a message id.
func awaitAck(ctx context.Context, d *dispatcher, id string, timeout time.Duration) error {
	verdict := make(chan string, 4)
	d.mu.Lock()
	previous := d.onNode
	d.onNode = func(ctx context.Context, node *wabinary.Node) {
		switch {
		case node.Tag == "ack" && node.Attrs["id"] == id:
			// An ack names more than its class: error/code/phash say whether
			// the server accepted the message or just the stanza. Dropping
			// them made a refusal look like success.
			summary := "class=" + node.Attrs["class"]
			for _, key := range []string{"error", "code", "reason", "phash", "t"} {
				if value := node.Attrs[key]; value != "" {
					summary += " " + key + "=" + value
				}
			}
			select {
			case verdict <- summary:
			default:
			}
			return
		case node.Tag == "iq" && node.Attrs["type"] == "error":
			select {
			case verdict <- "ERROR: " + describeError(node):
			default:
			}
			return
		case node.Tag == "receipt" && (node.Attrs["id"] == id || nodeHasChildID(node, id)):
			select {
			case verdict <- "RECEIPT type=" + node.Attrs["type"]:
			default:
			}
			return
		}
		if previous != nil {
			previous(ctx, node)
		}
	}
	d.mu.Unlock()

	select {
	case class := <-verdict:
		if len(class) > 6 && class[:6] == "ERROR:" {
			return fmt.Errorf("server rejected the message: %s", class[7:])
		}
		if strings.Contains(class, " error=") || strings.Contains(class, " code=") {
			return fmt.Errorf("server refused the message: %s", class)
		}
		fmt.Printf("ACK: the server accepted the message (%s)\n", class)
		return nil
	case <-time.After(timeout):
		fmt.Printf("no ack for %s within %s (the message may still be delivered)\n", id, timeout)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fetchPreKeyBundle asks the server for a peer's keys through the dispatcher.
func fetchPreKeyBundle(ctx context.Context, d *dispatcher, jid string) (*signal.PreKeyBundle, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	reply, err := d.request(ctx, &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to": serverJID, "type": "get", "xmlns": "encrypt", "id": id,
		},
		Children: []wabinary.Node{{
			Tag: "key",
			Children: []wabinary.Node{{
				Tag:   "user",
				Attrs: wabinary.Attrs{"jid": jid, "reason": "identity"},
			}},
		}},
	}, 20*time.Second)
	if err != nil {
		return nil, err
	}
	return parsePreKeyResponse(reply, jid)
}

// frameWriter adapts a secure connection to the sender's one-method interface.
type frameWriter struct {
	sc noise.SecureConn
}

func (w frameWriter) WriteFrame(ctx context.Context, frame []byte) error {
	return w.sc.WriteFrame(ctx, frame)
}

// loginIdentity is the parsed form of the stored JID, or an error naming the
// field that is wrong.
type loginIdentity struct {
	Username string
	Device   uint32
}

func parseLoginIdentity(record *credentialRecord) (loginIdentity, error) {
	jid, err := stanza.ParseJID(record.JID)
	if err != nil {
		return loginIdentity{}, fmt.Errorf("parse jid %q: %w", record.JID, err)
	}
	if jid.User == "" {
		return loginIdentity{}, fmt.Errorf("credential jid %q has no user", record.JID)
	}
	return loginIdentity{Username: jid.User, Device: uint32(jid.Device)}, nil
}

// dialLogin performs the handshake for a paired device.
func dialLogin(ctx context.Context, endpointURL string, record *credentialRecord, login loginIdentity) (noise.SecureConn, error) {
	username, err := strconv.ParseUint(login.Username, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("jid user %q is not a number: %w", login.Username, err)
	}
	payload, err := auth.BuildLoginPayload(auth.LoginInput{
		Version:       loginVersion,
		UserAgent:     loginUserAgent,
		WebInfo:       auth.WebInfo{SubPlatform: protobuf.ClientPayload_WebInfo_WEB_BROWSER},
		ConnectType:   protobuf.ClientPayload_WIFI_UNKNOWN,
		ConnectReason: protobuf.ClientPayload_USER_ACTIVATED,
		Username:      username,
		Device:        login.Device,
	})
	if err != nil {
		return nil, fmt.Errorf("build login payload: %w", err)
	}
	dialer := &transport.WebSocketDialer{HandshakeTimeoutOverride: 20 * time.Second}
	endpoint := transport.DefaultEndpoint()
	if endpointURL != "" {
		endpoint.URL = endpointURL
	}
	fr, err := dialer.Dial(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	sc, err := noise.DoClientHandshake(ctx, fr, noise.KeyPair{Priv: record.NoisePriv, Pub: record.NoisePub}, waref.RootPublicKey(), payload)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return sc, nil
}

// preKeyBatch is how many one-time prekeys to publish per send. The reference
// publishes 812 on first upload; a probe only needs enough for one session.
const preKeyBatch = 20

// uploadPreKeysVia sends a key set through the shared read loop.
func uploadPreKeysVia(ctx context.Context, d *dispatcher, record *credentialRecord, keys []signal.PreKey, signed signal.SignedPreKey) error {
	node, err := buildPreKeyUpload(record, keys, signed)
	if err != nil {
		return err
	}
	_, err = d.request(ctx, node, 45*time.Second)
	return err
}

// buildPreKeyUpload assembles the encrypt/iq set node (PF-082).
func buildPreKeyUpload(record *credentialRecord, keys []signal.PreKey, signed signal.SignedPreKey) (*wabinary.Node, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	list := make([]wabinary.Node, 0, len(keys))
	for _, key := range keys {
		var idBytes [4]byte
		idBytes[0] = byte(key.ID >> 24)
		idBytes[1] = byte(key.ID >> 16)
		idBytes[2] = byte(key.ID >> 8)
		idBytes[3] = byte(key.ID)
		list = append(list, wabinary.Node{
			Tag: "key",
			Children: []wabinary.Node{
				{Tag: "id", Bytes: idBytes[1:]},
				{Tag: "value", Bytes: key.Pair.Public[:]},
			},
		})
	}
	var signedID [4]byte
	signedID[0] = byte(signed.ID >> 24)
	signedID[1] = byte(signed.ID >> 16)
	signedID[2] = byte(signed.ID >> 8)
	signedID[3] = byte(signed.ID)
	var registration [4]byte
	registration[0] = byte(record.RegistrationID >> 24)
	registration[1] = byte(record.RegistrationID >> 16)
	registration[2] = byte(record.RegistrationID >> 8)
	registration[3] = byte(record.RegistrationID)

	return &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"to": serverJID, "type": "set", "xmlns": "encrypt", "id": id,
		},
		Children: []wabinary.Node{
			{Tag: "registration", Bytes: registration[:]},
			{Tag: "type", Bytes: []byte{0x05}},
			{Tag: "identity", Bytes: record.IdentityPub[:]},
			{Tag: "list", Children: list},
			{Tag: "skey", Children: []wabinary.Node{
				{Tag: "id", Bytes: signedID[1:]},
				{Tag: "value", Bytes: signed.Pair.Public[:]},
				{Tag: "signature", Bytes: signed.Signature},
			}},
		},
	}, nil
}

// nodeHasChildID reports whether a batched receipt lists this id.
func nodeHasChildID(node *wabinary.Node, id string) bool {
	for i := range node.Children {
		if node.Children[i].Attrs["id"] == id {
			return true
		}
	}
	return false
}

// buildOutgoing produces the protobuf Message a send carries and the stanza
// class it travels under. Text is one conversation field; a file is one
// uploaded attachment whose digests and key came from the envelope.
func buildOutgoing(ctx context.Context, d *dispatcher, cfg sendConfig) (*protobuf.Message, string, error) {
	if cfg.FilePath != "" {
		message, err := buildMediaPayload(ctx, d, cfg)
		if err != nil {
			return nil, "", err
		}
		return message, stanza.MessageTypeMedia, nil
	}
	if cfg.Text == "" {
		return nil, "", fmt.Errorf("send needs -text or -file")
	}
	return &protobuf.Message{Conversation: proto.String(cfg.Text)}, stanza.MessageTypeText, nil
}
