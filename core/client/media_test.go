package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/core/media"
	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// mediaRig is one connected client with an established peer session plus the
// recipient's half of that session, so a sent descriptor can be decrypted the
// way bob would. No sleeps: writes are buffered by fakeConn and read directly.
type mediaRig struct {
	client  *Client
	conn    *fakeConn
	store   *memorySessions
	bob     *signal.State
	aliceID [32]byte
	bobID   [32]byte
	peer    string
}

func newMediaRig(t *testing.T) *mediaRig {
	t.Helper()
	conn := newFakeConn()
	bus := events.NewBus()
	store := &memorySessions{records: make(map[string]*PeerRecord)}
	c, err := New("session-1", WithDialer(&fakeDialer{conn: conn}), WithBus(bus), WithSessionStore(store))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}

	alice, bob, aliceID, bobID := encryptedPair(t)
	peer := "628123@s.whatsapp.net"
	store.records[peer] = &PeerRecord{PeerIdentity: bobID, State: alice}
	c.SetSignalIdentity(aliceID)

	return &mediaRig{client: c, conn: conn, store: store, bob: bob, aliceID: aliceID, bobID: bobID, peer: peer}
}

// descriptor reads the next written frame, decrypts it as bob, and returns the
// descriptor plaintext.
func (r *mediaRig) descriptor(t *testing.T) []byte {
	t.Helper()
	frame := <-r.conn.writes
	node, err := binary.NewCodec(nil).Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	// ParseEncryptedText reads the inbound shape, which stamps "from"; the
	// wire here is outbound, so the round trip adds a sender for it.
	node.Attrs["from"] = "100000000000000@s.whatsapp.net"
	envelope, err := stanza.ParseEncryptedText(node)
	if err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	if envelope.Carrier != stanza.CarrierMsg {
		t.Fatalf("carrier = %q, want %q", envelope.Carrier, stanza.CarrierMsg)
	}
	plaintext, err := r.bob.Decrypt(envelope.Ciphertext, r.aliceID, r.bobID)
	if err != nil {
		t.Fatalf("decrypt descriptor: %v", err)
	}
	return plaintext
}

// sendAndDecrypt sends media and returns the result plus the descriptor bob
// received.
func (r *mediaRig) sendAndDecrypt(t *testing.T, kind MediaKind, name string, payload []byte) (MediaResult, []byte) {
	t.Helper()
	result, err := r.client.SendMedia(context.Background(), r.peer, kind, name, payload)
	if err != nil {
		t.Fatalf("SendMedia: %v", err)
	}
	return result, r.descriptor(t)
}

// syntheticMedia builds deterministic filler bytes without fixtures.
func syntheticMedia(size int, seed byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i*7) ^ seed
	}
	return out
}

func TestSendMediaImageRoundTrip(t *testing.T) {
	rig := newMediaRig(t)
	payload := syntheticMedia(3_000, 0x21)

	result, descriptor := rig.sendAndDecrypt(t, MediaKindImage, "photo.jpg", payload)
	if result.ID == "" {
		t.Fatal("empty message id")
	}
	if result.Kind != MediaKindImage || result.FileName != "photo.jpg" {
		t.Fatalf("result = %#v", result)
	}
	if result.MimeType != "image/jpeg" {
		t.Fatalf("MimeType = %q, want image/jpeg", result.MimeType)
	}
	if result.Size != len(payload) {
		t.Fatalf("Size = %d, want %d", result.Size, len(payload))
	}
	if result.MediaKey == "" {
		t.Fatal("result has no media key")
	}
	if len(result.SHA256) != 64 || len(result.EncSHA256) != 64 {
		t.Fatalf("digests = %q / %q", result.SHA256, result.EncSHA256)
	}
	if !rig.store.saved() {
		t.Fatal("ratchet state was not persisted")
	}

	// The descriptor is the documented JSON shape.
	var wire map[string]any
	if err := json.Unmarshal(descriptor, &wire); err != nil {
		t.Fatalf("descriptor json: %v", err)
	}
	for _, field := range []string{"media_id", "file_name", "media_type", "size",
		"sha256", "enc_sha256", "media_key", "direct_path", "url"} {
		if _, ok := wire[field]; !ok {
			t.Fatalf("descriptor has no %q field: %s", field, descriptor)
		}
	}
	if wire["media_id"] != mediaIDPlaceholder || wire["direct_path"] != "" || wire["url"] != "" {
		t.Fatalf("descriptor transport fields = %#v", wire)
	}
	if wire["media_type"] != "WhatsApp Image Keys" {
		t.Fatalf("media_type = %v", wire["media_type"])
	}
	if wire["file_name"] != "photo.jpg" || wire["size"] != float64(len(payload)) {
		t.Fatalf("descriptor = %#v", wire)
	}

	received, plaintext, err := rig.client.ReceiveMedia(context.Background(), rig.peer, descriptor)
	if err != nil {
		t.Fatalf("ReceiveMedia: %v", err)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatal("round-tripped payload differs")
	}
	if received.Kind != MediaKindImage || received.FileName != "photo.jpg" ||
		received.MimeType != "image/jpeg" || received.Size != len(payload) {
		t.Fatalf("received = %#v", received)
	}
	if received.SHA256 != result.SHA256 || received.EncSHA256 != result.EncSHA256 {
		t.Fatalf("digests changed in transit: %#v vs %#v", received, result)
	}
	if received.MediaKey != result.MediaKey {
		t.Fatal("media key changed in transit")
	}
}

func TestSendMediaDocumentRoundTrip(t *testing.T) {
	rig := newMediaRig(t)
	payload := syntheticMedia(97, 0x5a)

	result, descriptor := rig.sendAndDecrypt(t, MediaKindDocument, "report.pdf", payload)
	if result.MimeType != "application/pdf" {
		t.Fatalf("MimeType = %q, want application/pdf", result.MimeType)
	}
	received, plaintext, err := rig.client.ReceiveMedia(context.Background(), rig.peer, descriptor)
	if err != nil {
		t.Fatalf("ReceiveMedia: %v", err)
	}
	if !bytes.Equal(plaintext, payload) || received.Kind != MediaKindDocument {
		t.Fatalf("received = %#v", received)
	}
}

func TestSendMediaEmptyPayload(t *testing.T) {
	rig := newMediaRig(t)

	result, descriptor := rig.sendAndDecrypt(t, MediaKindImage, "empty.png", nil)
	if result.Size != 0 {
		t.Fatalf("Size = %d, want 0", result.Size)
	}
	received, plaintext, err := rig.client.ReceiveMedia(context.Background(), rig.peer, descriptor)
	if err != nil {
		t.Fatalf("ReceiveMedia: %v", err)
	}
	if len(plaintext) != 0 || received.Size != 0 {
		t.Fatalf("empty payload round-tripped as %d bytes", len(plaintext))
	}
	if received.SHA256 != result.SHA256 {
		t.Fatal("digest of empty payload changed")
	}
}

func TestSendMediaOneMiBRoundTrip(t *testing.T) {
	rig := newMediaRig(t)
	payload := syntheticMedia(1<<20, 0xc3)

	result, descriptor := rig.sendAndDecrypt(t, MediaKindDocument, "blob.bin", payload)
	if result.Size != 1<<20 {
		t.Fatalf("Size = %d", result.Size)
	}
	received, plaintext, err := rig.client.ReceiveMedia(context.Background(), rig.peer, descriptor)
	if err != nil {
		t.Fatalf("ReceiveMedia: %v", err)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatal("1 MiB payload round-trip mismatch")
	}
	if received.Size != 1<<20 || received.FileName != "blob.bin" {
		t.Fatalf("received = %#v", received)
	}
}

func TestSendMediaUnknownKind(t *testing.T) {
	rig := newMediaRig(t)
	_, err := rig.client.SendMedia(context.Background(), rig.peer, MediaKind("video"), "clip.mp4", []byte("x"))
	if !errors.Is(err, ErrUnknownMediaKind) {
		t.Fatalf("want ErrUnknownMediaKind, got %v", err)
	}
}

func TestSendMediaPayloadTooLarge(t *testing.T) {
	rig := newMediaRig(t)
	payload := make([]byte, media.MaxMediaSize+1)
	_, err := rig.client.SendMedia(context.Background(), rig.peer, MediaKindDocument, "huge.bin", payload)
	if !errors.Is(err, ErrMediaTooLarge) {
		t.Fatalf("want ErrMediaTooLarge, got %v", err)
	}
	if !errors.Is(err, media.ErrPayloadTooLarge) {
		t.Fatalf("error should wrap core/media's sentinel: %v", err)
	}
}

func TestSendMediaInvalidFileName(t *testing.T) {
	rig := newMediaRig(t)
	for _, name := range []string{"", "   "} {
		if _, err := rig.client.SendMedia(context.Background(), rig.peer, MediaKindImage, name, []byte("x")); !errors.Is(err, ErrInvalidMediaDescriptor) {
			t.Fatalf("name %q: want ErrInvalidMediaDescriptor, got %v", name, err)
		}
	}
	longName := strings.Repeat("f", maxMediaFileNameBytes+1)
	if _, err := rig.client.SendMedia(context.Background(), rig.peer, MediaKindImage, longName, []byte("x")); !errors.Is(err, ErrInvalidMediaDescriptor) {
		t.Fatalf("long name: want ErrInvalidMediaDescriptor, got %v", err)
	}
}

func TestSendMediaRequiresSession(t *testing.T) {
	bus := events.NewBus()
	c, err := New("session-1", WithDialer(&fakeDialer{conn: newFakeConn()}), WithBus(bus))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	_, err = c.SendMedia(context.Background(), "628123@s.whatsapp.net", MediaKindImage, "a.jpg", []byte("x"))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestReceiveMediaInvalidDescriptor(t *testing.T) {
	rig := newMediaRig(t)
	cases := []struct {
		name string
		raw  string
	}{
		{"not json", `{"file_name":`},
		{"unknown media type", `{"media_type":"WhatsApp Video Keys","file_name":"a.mp4","size":0}`},
		{"missing media type", `{"file_name":"a.bin","size":0}`},
		{"negative size", `{"media_type":"WhatsApp Image Keys","file_name":"a.jpg","size":-1}`},
		{"empty file name", `{"media_type":"WhatsApp Image Keys","file_name":"  ","size":0}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := rig.client.ReceiveMedia(context.Background(), rig.peer, []byte(tc.raw))
			if !errors.Is(err, ErrInvalidMediaDescriptor) {
				t.Fatalf("want ErrInvalidMediaDescriptor, got %v", err)
			}
			if !errors.Is(err, media.ErrInvalidDescriptor) {
				t.Fatalf("error should wrap core/media's sentinel: %v", err)
			}
		})
	}
}

func TestReceiveMediaDescriptorTooLarge(t *testing.T) {
	rig := newMediaRig(t)
	raw, err := json.Marshal(mediaDescriptorJSON{
		MediaID:   mediaIDPlaceholder,
		FileName:  "big.bin",
		MediaType: "WhatsApp Document Keys",
		Size:      media.MaxMediaSize + 1,
		SHA256:    strings.Repeat("0", 64),
		EncSHA256: strings.Repeat("0", 64),
		MediaKey:  base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rig.client.ReceiveMedia(context.Background(), rig.peer, raw); !errors.Is(err, ErrMediaTooLarge) {
		t.Fatalf("want ErrMediaTooLarge, got %v", err)
	}
}

func TestReceiveMediaMalformedKeyOrDigest(t *testing.T) {
	rig := newMediaRig(t)
	_, descriptor := rig.sendAndDecrypt(t, MediaKindImage, "photo.jpg", syntheticMedia(32, 0x01))

	var wire mediaDescriptorJSON
	if err := json.Unmarshal(descriptor, &wire); err != nil {
		t.Fatal(err)
	}

	t.Run("short key", func(t *testing.T) {
		bad := wire
		bad.MediaKey = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
		raw, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := rig.client.ReceiveMedia(context.Background(), rig.peer, raw); !errors.Is(err, ErrInvalidMediaDescriptor) {
			t.Fatalf("want ErrInvalidMediaDescriptor, got %v", err)
		}
	})

	t.Run("bad hex digest", func(t *testing.T) {
		bad := wire
		bad.SHA256 = "not-hex"
		raw, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := rig.client.ReceiveMedia(context.Background(), rig.peer, raw); !errors.Is(err, ErrInvalidMediaDescriptor) {
			t.Fatalf("want ErrInvalidMediaDescriptor, got %v", err)
		}
	})

	t.Run("payload not base64", func(t *testing.T) {
		bad := wire
		bad.Payload = "!!!!"
		raw, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := rig.client.ReceiveMedia(context.Background(), rig.peer, raw); !errors.Is(err, ErrInvalidMediaDescriptor) {
			t.Fatalf("want ErrInvalidMediaDescriptor, got %v", err)
		}
	})
}

func TestReceiveMediaHashMismatch(t *testing.T) {
	rig := newMediaRig(t)
	_, descriptor := rig.sendAndDecrypt(t, MediaKindDocument, "doc.pdf", syntheticMedia(500, 0x77))

	var wire mediaDescriptorJSON
	if err := json.Unmarshal(descriptor, &wire); err != nil {
		t.Fatal(err)
	}

	t.Run("plaintext digest", func(t *testing.T) {
		bad := wire
		bad.SHA256 = strings.Repeat("0", 64)
		raw, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = rig.client.ReceiveMedia(context.Background(), rig.peer, raw)
		if !errors.Is(err, ErrMediaHashMismatch) {
			t.Fatalf("want ErrMediaHashMismatch, got %v", err)
		}
		if !errors.Is(err, media.ErrHashMismatch) {
			t.Fatalf("error should wrap core/media's sentinel: %v", err)
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		bad := wire
		blob, err := base64.StdEncoding.DecodeString(bad.Payload)
		if err != nil {
			t.Fatal(err)
		}
		blob[0] ^= 0xff
		bad.Payload = base64.StdEncoding.EncodeToString(blob)
		raw, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := rig.client.ReceiveMedia(context.Background(), rig.peer, raw); !errors.Is(err, ErrMediaHashMismatch) {
			t.Fatalf("want ErrMediaHashMismatch, got %v", err)
		}
	})
}

func TestReceiveMediaRejectsEmptyFrom(t *testing.T) {
	rig := newMediaRig(t)
	if _, _, err := rig.client.ReceiveMedia(context.Background(), "", []byte("{}")); err == nil {
		t.Fatal("empty from should fail")
	}
}

func TestMediaResultStringRedactsKey(t *testing.T) {
	result := MediaResult{
		ID:       "MSG1",
		Kind:     MediaKindImage,
		FileName: "photo.jpg",
		Size:     3,
		MediaKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32)),
	}
	if strings.Contains(result.String(), result.MediaKey) {
		t.Fatalf("String leaked the media key: %s", result.String())
	}
	if !strings.Contains(result.String(), "[REDACTED]") {
		t.Fatalf("String = %s", result.String())
	}
}

// saved reports whether any peer record was persisted.
func (m *memorySessions) saved() bool { return len(m.records) > 0 }

// Ensure the media path reuses the Signal carrier: a descriptor send also
// advances the stored ratchet, exactly like a text send.
func TestSendMediaAdvancesRatchet(t *testing.T) {
	rig := newMediaRig(t)
	before, err := rig.store.records[rig.peer].State.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.client.SendMedia(context.Background(), rig.peer,
		MediaKindImage, "photo.jpg", []byte("x")); err != nil {
		t.Fatalf("SendMedia: %v", err)
	}
	<-rig.conn.writes
	after, err := rig.store.records[rig.peer].State.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("media send did not advance the ratchet")
	}
}
