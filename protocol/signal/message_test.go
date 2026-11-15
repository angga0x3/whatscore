package signal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func testMessageKeys() MessageKeys {
	var keys MessageKeys
	for i := range keys.CipherKey {
		keys.CipherKey[i] = 0xAA
		keys.MACKey[i] = 0xBB
	}
	for i := range keys.IV {
		keys.IV[i] = 0xCC
	}
	return keys
}

func testHeader() Header {
	var header Header
	for i := range header.RatchetKey {
		header.RatchetKey[i] = 0xDD
	}
	header.MessageNumber = 5
	header.PreviousChainLength = 2
	return header
}

func testIdentities() (sender, receiver [32]byte) {
	for i := range sender {
		sender[i] = 0x11
		receiver[i] = 0x22
	}
	return sender, receiver
}

func TestEncryptDecryptMessage(t *testing.T) {
	keys := testMessageKeys()
	header := testHeader()
	sender, receiver := testIdentities()
	plaintext := []byte("halo signal")

	wire, err := EncryptMessage(keys, header, plaintext, sender, receiver)
	if err != nil {
		t.Fatal(err)
	}
	message, err := ParseMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if message.Version != Version || message.Header != header || message.Ciphertext == nil || len(message.MAC) != MACSize {
		t.Fatalf("parsed = %#v", message)
	}
	got, err := DecryptMessage(wire, keys, sender, receiver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestMessageRejectsTampering(t *testing.T) {
	keys := testMessageKeys()
	header := testHeader()
	sender, receiver := testIdentities()
	wire, err := EncryptMessage(keys, header, []byte("payload"), sender, receiver)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		mutate func([]byte) []byte
		want   error
	}{
		"version": {func(b []byte) []byte { b[0] = 0x32; return b }, ErrInvalidMessage},
		"body":    {func(b []byte) []byte { b[len(b)-MACSize-1] ^= 0x01; return b }, ErrBadMAC},
		"mac":     {func(b []byte) []byte { b[len(b)-1] ^= 0x01; return b }, ErrBadMAC},
		"short":   {func(b []byte) []byte { return b[:5] }, ErrInvalidMessage},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := tc.mutate(append([]byte(nil), wire...))
			if _, err := DecryptMessage(tampered, keys, sender, receiver); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}

	if _, err := DecryptMessage(wire, keys, receiver, sender); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("swapped identities: %v", err)
	}
	other := keys
	other.MACKey[0] ^= 0x01
	if _, err := DecryptMessage(wire, other, sender, receiver); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("wrong mac key: %v", err)
	}
}

func TestMessageVectors(t *testing.T) {
	raw, err := os.ReadFile("../../tests/fixtures/signal_message_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vector struct {
		CipherKey        string `json:"cipher_key"`
		MACKey           string `json:"mac_key"`
		IV               string `json:"iv"`
		RatchetKey       string `json:"ratchet_key"`
		SenderIdentity   string `json:"sender_identity"`
		ReceiverIdentity string `json:"receiver_identity"`
		Counter          uint32 `json:"counter"`
		PreviousCounter  uint32 `json:"previous_counter"`
		Plaintext        string `json:"plaintext"`
		Ciphertext       string `json:"ciphertext"`
		Wire             string `json:"wire"`
		PreKey           struct {
			RegistrationID uint32 `json:"registration_id"`
			PreKeyID       uint32 `json:"pre_key_id"`
			SignedPreKeyID uint32 `json:"signed_pre_key_id"`
			BaseKey        string `json:"base_key"`
			IdentityKey    string `json:"identity_key"`
			Message        string `json:"message"`
		} `json:"prekey"`
		PreKeyWire string `json:"prekey_wire"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}

	keys := MessageKeys{
		CipherKey: decodeHex(t, vector.CipherKey),
		MACKey:    decodeHex(t, vector.MACKey),
		IV:        decodeHex16(t, vector.IV),
	}
	header := Header{
		RatchetKey:          decodeHex(t, vector.RatchetKey),
		MessageNumber:       vector.Counter,
		PreviousChainLength: vector.PreviousCounter,
	}
	sender := decodeHex(t, vector.SenderIdentity)
	receiver := decodeHex(t, vector.ReceiverIdentity)
	plaintext, err := hex.DecodeString(vector.Plaintext)
	if err != nil {
		t.Fatal(err)
	}

	wire, err := EncryptMessage(keys, header, plaintext, sender, receiver)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(wire); got != vector.Wire {
		t.Fatalf("wire mismatch\n got %s\nwant %s", got, vector.Wire)
	}
	got, err := DecryptMessage(wire, keys, sender, receiver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q", got)
	}

	preKeyMessage, err := hex.DecodeString(vector.PreKey.Message)
	if err != nil {
		t.Fatal(err)
	}
	preKeyWire, err := BuildPreKeyMessage(PreKeyMessage{
		RegistrationID: vector.PreKey.RegistrationID,
		PreKeyID:       vector.PreKey.PreKeyID,
		SignedPreKeyID: vector.PreKey.SignedPreKeyID,
		BaseKey:        decodeHex(t, vector.PreKey.BaseKey),
		IdentityKey:    decodeHex(t, vector.PreKey.IdentityKey),
		Message:        preKeyMessage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(preKeyWire); got != vector.PreKeyWire {
		t.Fatalf("prekey wire mismatch\n got %s\nwant %s", got, vector.PreKeyWire)
	}
}

func TestStateEncryptDecrypt(t *testing.T) {
	c := newConversation(t)
	sender, receiver := testIdentities()

	var wires [][]byte
	var plaintexts [][]byte
	for i := 0; i < 3; i++ {
		plaintext := []byte{byte('a' + i)}
		wire, err := c.alice.Encrypt(plaintext, sender, receiver)
		if err != nil {
			t.Fatal(err)
		}
		wires = append(wires, wire)
		plaintexts = append(plaintexts, plaintext)
	}
	for _, index := range []int{2, 0, 1} {
		got, err := c.bob.Decrypt(wires[index], sender, receiver)
		if err != nil {
			t.Fatalf("decrypt %d: %v", index, err)
		}
		if !bytes.Equal(got, plaintexts[index]) {
			t.Fatalf("message %d = %q", index, got)
		}
	}

	wire, err := c.bob.Encrypt([]byte("reply"), receiver, sender)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.alice.Decrypt(wire, receiver, sender)
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	if string(got) != "reply" {
		t.Fatalf("reply = %q", got)
	}
}
