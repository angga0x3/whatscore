package waref

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestRootPublicKeyIsPinned guards the one invariant every caller depends on:
// the pinned root is 32 bytes and matches the value recorded in PF-009. The
// probe and cmd/whatscore both take it from here, so a change to this constant
// is a protocol decision, never a local tweak.
func TestRootPublicKeyIsPinned(t *testing.T) {
	root := RootPublicKey()
	if len(root) != 32 {
		t.Fatalf("root public key is %d bytes, want 32", len(root))
	}
	if got := hex.EncodeToString(root); got != RootPubHex {
		t.Fatalf("decoded root %s does not match the pinned hex", got)
	}
	if got := hex.EncodeToString(root); got != "142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b" {
		t.Fatalf("root public key %s does not match the recorded finding", got)
	}
}

// TestRootPublicKeyReturnsACopy proves callers cannot mutate the pinned value
// for the rest of the process: core/engine keeps the slice it is given.
func TestRootPublicKeyReturnsACopy(t *testing.T) {
	first := RootPublicKey()
	first[0] ^= 0xff
	if bytes.Equal(first, RootPublicKey()) {
		t.Fatal("RootPublicKey shares its backing array between callers")
	}
}
