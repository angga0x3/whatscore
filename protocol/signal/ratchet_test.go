package signal

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type ratchetVector struct {
	RootKey   string `json:"root_key"`
	AlicePriv string `json:"alice_ratchet_priv"`
	AlicePub  string `json:"alice_ratchet_pub"`
	BobPriv   string `json:"bob_ratchet_priv"`
	BobPub    string `json:"bob_ratchet_pub"`
	Shared    string `json:"shared_secret"`
	NextRoot  string `json:"next_root_key"`
	Chain     string `json:"chain_key"`
	Steps     []struct {
		Index      uint32 `json:"index"`
		MessageKey string `json:"message_key"`
		NextChain  string `json:"next_chain"`
		CipherKey  string `json:"cipher_key"`
		MACKey     string `json:"mac_key"`
		IV         string `json:"iv"`
	} `json:"steps"`
}

func TestRatchetVectors(t *testing.T) {
	raw, err := os.ReadFile("../../tests/fixtures/signal_ratchet_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vector ratchetVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}

	root := RootKey(decodeHex(t, vector.RootKey))
	alicePriv := decodeHex(t, vector.AlicePriv)
	bobPriv := decodeHex(t, vector.BobPriv)
	bobPub := decodeHex(t, vector.BobPub)
	alicePub := decodeHex(t, vector.AlicePub)

	if got, err := dh(alicePriv, bobPub); err != nil || got != decodeHex(t, vector.Shared) {
		t.Fatalf("shared secret = %x, %v", got, err)
	}

	next, chain, err := root.CreateChain(alicePriv, bobPub)
	if err != nil {
		t.Fatal(err)
	}
	if [32]byte(next) != decodeHex(t, vector.NextRoot) || [32]byte(chain) != decodeHex(t, vector.Chain) {
		t.Fatalf("alice ratchet = %x/%x", next, chain)
	}

	mirrorNext, mirrorChain, err := root.CreateChain(bobPriv, alicePub)
	if err != nil {
		t.Fatal(err)
	}
	if mirrorNext != next || mirrorChain != chain {
		t.Fatal("ratchet sides disagree")
	}

	for _, step := range vector.Steps {
		messageKey := chain.MessageKey()
		if messageKey != decodeHex(t, step.MessageKey) {
			t.Fatalf("step %d message key = %x", step.Index, messageKey)
		}
		keys, err := DeriveMessageKeys(messageKey, step.Index)
		if err != nil {
			t.Fatal(err)
		}
		if keys.CipherKey != decodeHex(t, step.CipherKey) || keys.MACKey != decodeHex(t, step.MACKey) || keys.IV != decodeHex16(t, step.IV) {
			t.Fatalf("step %d keys = %#v", step.Index, keys)
		}
		chain = chain.Next()
		if [32]byte(chain) != decodeHex(t, step.NextChain) {
			t.Fatalf("step %d chain = %x", step.Index, chain)
		}
	}
}

func TestRatchetRejectsInvalidDH(t *testing.T) {
	root := RootKey{}
	var zero [32]byte
	if _, _, err := root.CreateChain(zero, zero); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("want ErrInvalidKey, got %v", err)
	}
}

func decodeHex16(t *testing.T, value string) [16]byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 16 {
		t.Fatalf("bad iv %q: %v", value, err)
	}
	var out [16]byte
	copy(out[:], raw)
	return out
}
