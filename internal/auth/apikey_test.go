package auth

import (
	"bytes"
	"testing"
)

func TestGenerateKeyShape(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	if !bytes.HasPrefix([]byte(key), []byte(KeyPrefix)) {
		t.Errorf("key %q does not start with prefix %q", key, KeyPrefix)
	}
	// 32 bytes -> 43 base64url characters + prefix.
	if want := len(KeyPrefix) + 43; len(key) != want {
		t.Errorf("key length = %d, want %d", len(key), want)
	}
}

func TestGenerateKeyIsRandom(t *testing.T) {
	first, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	second, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	if first == second {
		t.Fatal("two generated keys are identical")
	}
}

func TestHashAndVerifyKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	hash := HashKey(key)
	if len(hash) != 32 {
		t.Errorf("hash length = %d, want 32 (SHA-256)", len(hash))
	}

	if !VerifyKey(key, hash) {
		t.Error("VerifyKey(correct key, hash) = false, want true")
	}

	wrong, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	if VerifyKey(wrong, hash) {
		t.Error("VerifyKey(wrong key, hash) = true, want false")
	}
}

func TestHashKeyIsDeterministic(t *testing.T) {
	a := HashKey("wc_live_test")
	b := HashKey("wc_live_test")
	if !bytes.Equal(a, b) {
		t.Error("HashKey is not deterministic for the same input")
	}
}

func TestSplitKey(t *testing.T) {
	prefix, ok := SplitKey("wc_live_abc123")
	if !ok || prefix != KeyPrefix {
		t.Errorf("SplitKey = (%q, %v), want (%q, true)", prefix, ok, KeyPrefix)
	}

	if _, ok := SplitKey("garbage"); ok {
		t.Error("SplitKey(garbage) ok = true, want false")
	}
	if _, ok := SplitKey(KeyPrefix); ok {
		t.Error("SplitKey(prefix only) ok = true, want false")
	}
}
