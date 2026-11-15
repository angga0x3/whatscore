package media

import (
	"bytes"
	"testing"
)

func benchKeys(b *testing.B) Keys {
	b.Helper()
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	keys, err := DeriveKeys(key, TypeImage, 0)
	if err != nil {
		b.Fatal(err)
	}
	return keys
}

func BenchmarkEncrypt1MiB(b *testing.B) {
	keys := benchKeys(b)
	plaintext := bytes.Repeat([]byte{0xA5}, 1<<20)
	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Encrypt(plaintext, keys); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt1MiB(b *testing.B) {
	keys := benchKeys(b)
	plaintext := bytes.Repeat([]byte{0xA5}, 1<<20)
	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Decrypt(blob, keys); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptStream1MiB(b *testing.B) {
	keys := benchKeys(b)
	plaintext := bytes.Repeat([]byte{0xA5}, 1<<20)
	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptStream(discard{}, bytes.NewReader(plaintext), keys); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveKeys(b *testing.B) {
	var key [32]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DeriveKeys(key, TypeDocument, 0); err != nil {
			b.Fatal(err)
		}
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
