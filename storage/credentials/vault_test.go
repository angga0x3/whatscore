package credentials

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/angga0x3/whatscore/storage/envelope"
)

func newVault(t *testing.T) (*Vault, *MemoryBackend) {
	t.Helper()
	key, err := envelope.NewKey(bytes.Repeat([]byte{0x42}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	backend := NewMemoryBackend()
	vault, err := NewVault(backend, key)
	if err != nil {
		t.Fatal(err)
	}
	return vault, backend
}

func TestVaultRoundTrip(t *testing.T) {
	ctx := context.Background()
	vault, backend := newVault(t)
	plaintext := []byte(`{"noise":"synthetic","identity":"synthetic"}`)

	if err := vault.Put(ctx, "device/1", plaintext); err != nil {
		t.Fatal(err)
	}
	stored, err := backend.Get(ctx, "device/1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, plaintext) {
		t.Fatal("backend holds plaintext")
	}
	got, err := vault.Get(ctx, "device/1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q", got)
	}

	if err := vault.Delete(ctx, "device/1"); err != nil {
		t.Fatal(err)
	}
	if err := vault.Delete(ctx, "device/1"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if _, err := vault.Get(ctx, "device/1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestVaultBindsRecordKey(t *testing.T) {
	ctx := context.Background()
	vault, backend := newVault(t)
	if err := vault.Put(ctx, "device/1", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	sealed, err := backend.Get(ctx, "device/1")
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Put(ctx, "device/2", sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Get(ctx, "device/2"); !errors.Is(err, envelope.ErrDecryptFailed) {
		t.Fatalf("copied record must not open: %v", err)
	}
}

func TestVaultValidation(t *testing.T) {
	ctx := context.Background()
	vault, _ := newVault(t)

	if _, err := NewVault(nil, nil); err == nil {
		t.Fatal("nil backend and key must fail")
	}
	if _, err := NewVault(NewMemoryBackend(), nil); err == nil {
		t.Fatal("nil key must fail")
	}
	if err := vault.Put(ctx, "", []byte("x")); err == nil {
		t.Fatal("empty key must fail")
	}
	if _, err := vault.Get(ctx, ""); err == nil {
		t.Fatal("empty key must fail")
	}
	if err := vault.Put(ctx, strings.Repeat("k", 513), []byte("x")); err == nil {
		t.Fatal("oversized key must fail")
	}
	if _, err := vault.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestVaultConcurrent(t *testing.T) {
	ctx := context.Background()
	vault, _ := newVault(t)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("device/%d", i)
			want := []byte(fmt.Sprintf("secret-%d", i))
			if err := vault.Put(ctx, key, want); err != nil {
				t.Errorf("put %s: %v", key, err)
				return
			}
			got, err := vault.Get(ctx, key)
			if err != nil {
				t.Errorf("get %s: %v", key, err)
				return
			}
			if !bytes.Equal(got, want) {
				t.Errorf("get %s = %q", key, got)
			}
		}(i)
	}
	wg.Wait()
}

func TestVaultIndependentKeys(t *testing.T) {
	ctx := context.Background()
	vault, backend := newVault(t)
	otherKey, err := envelope.NewKey(bytes.Repeat([]byte{0x43}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewVault(backend, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Put(ctx, "device/1", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Get(ctx, "device/1"); !errors.Is(err, envelope.ErrDecryptFailed) {
		t.Fatalf("other key must not open: %v", err)
	}
}
