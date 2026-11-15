package cbc

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 16)
	for _, size := range []int{0, 1, 15, 16, 17, 1 << 10} {
		plaintext := bytes.Repeat([]byte{0xAB}, size)
		sealed, err := Encrypt(key, iv, plaintext)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(sealed)%16 != 0 || len(sealed) < size+1 {
			t.Fatalf("size %d: envelope length %d", size, len(sealed))
		}
		got, err := Decrypt(key, iv, sealed)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d mismatch", size)
		}
	}
}

func TestTamperAndBounds(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 16)
	sealed, err := Encrypt(key, iv, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x02
	if _, err := Decrypt(key, iv, tampered); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("tampered: %v", err)
	}
	for _, bad := range [][]byte{nil, sealed[:len(sealed)-1]} {
		if _, err := Decrypt(key, iv, bad); !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("length %d: %v", len(bad), err)
		}
	}
	if _, err := Encrypt(key[:16], iv, []byte("x")); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("short key: %v", err)
	}
	if _, err := Encrypt(key, iv[:8], []byte("x")); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("short iv: %v", err)
	}
}
