package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func testKey(t *testing.T) *Key {
	t.Helper()
	raw := bytes.Repeat([]byte{0x42}, KeySize)
	key, err := NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestParseKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0x11}, KeySize)
	padded := base64.StdEncoding.EncodeToString(raw)

	for name, encoded := range map[string]string{
		"padded":   padded,
		"unpadded": base64.RawStdEncoding.EncodeToString(raw),
		"spaces":   "  " + padded + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			key, err := ParseKey(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for i, b := range key.material {
				if b != raw[i] {
					t.Fatalf("key byte %d = %x", i, b)
				}
			}
		})
	}

	for name, encoded := range map[string]string{
		"empty":      "",
		"not base64": "!!!",
		"short":      base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"long":       base64.StdEncoding.EncodeToString(make([]byte, 33)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKey(encoded); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("want ErrInvalidKey, got %v", err)
			}
		})
	}
}

func TestSealOpen(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("session credentials")
	aad := []byte("session/42")
	sealed, err := key.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0] != Version || len(sealed) != HeaderSize+len(plaintext)+TagSize {
		t.Fatalf("unexpected envelope shape: %d bytes, version %d", len(sealed), sealed[0])
	}
	got, err := key.Open(sealed, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestSealEmptyAndLarge(t *testing.T) {
	key := testKey(t)
	for _, plaintext := range [][]byte{{}, bytes.Repeat([]byte{0xAB}, 1<<20)} {
		sealed, err := key.Seal(plaintext, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := key.Open(sealed, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip mismatch for %d bytes", len(plaintext))
		}
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	key := testKey(t)
	first, err := key.Seal([]byte("same"), nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := key.Seal([]byte("same"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[1:HeaderSize], second[1:HeaderSize]) {
		t.Fatal("nonce repeated")
	}
	if bytes.Equal(first, second) {
		t.Fatal("ciphertext repeated")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	key := testKey(t)
	sealed, err := key.Seal([]byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		mutate func([]byte) []byte
		want   error
	}{
		"version": {func(b []byte) []byte { b[0] = 0xFF; return b }, ErrInvalidEnvelope},
		"nonce":   {func(b []byte) []byte { b[1] ^= 0x01; return b }, ErrDecryptFailed},
		"payload": {func(b []byte) []byte { b[HeaderSize] ^= 0x01; return b }, ErrDecryptFailed},
		"tag":     {func(b []byte) []byte { b[len(b)-1] ^= 0x01; return b }, ErrDecryptFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := tc.mutate(append([]byte(nil), sealed...))
			if _, err := key.Open(tampered, []byte("aad")); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}

	if _, err := key.Open(sealed, []byte("other")); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("wrong aad: %v", err)
	}
	other, err := NewKey(bytes.Repeat([]byte{0x43}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(sealed, []byte("aad")); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("wrong key: %v", err)
	}
	for _, short := range [][]byte{nil, {Version}, {Version, 0x00}} {
		if _, err := key.Open(short, nil); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("short envelope %d: %v", len(short), err)
		}
	}
}

func TestClear(t *testing.T) {
	key := testKey(t)
	sealed, err := key.Seal([]byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	key.Clear()
	if _, err := key.Open(sealed, nil); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("open after clear: %v", err)
	}
	key.Clear()
}

func TestKeysAreIndependent(t *testing.T) {
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	first, err := NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xFF
	second, err := NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := first.Seal([]byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Open(sealed, nil); !errors.Is(err, ErrDecryptFailed) {
		t.Fatal("different keys must not decrypt each other")
	}
}
