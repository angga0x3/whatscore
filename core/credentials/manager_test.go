package credentials

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/angga0x3/whatscore/protocol/protobuf"
	storecreds "github.com/angga0x3/whatscore/storage/credentials"
	"github.com/angga0x3/whatscore/storage/envelope"
)

func testRecord() *Record {
	r := &Record{RegistrationID: 4242}
	for i := 0; i < 32; i++ {
		r.NoisePrivateKey[i] = byte(i)
		r.NoisePublicKey[i] = byte(i + 1)
		r.IdentityPrivateKey[i] = byte(i + 2)
		r.IdentityPublicKey[i] = byte(i + 3)
		r.AdvSecret[i] = byte(i + 4)
	}
	return r
}

func withIdentity(r *Record) *Record {
	r.Identity = &DeviceIdentity{
		RawID:            7,
		Timestamp:        1234567890,
		KeyIndex:         2,
		AccountType:      protobuf.ADVEncryptionType_HOSTED,
		DeviceType:       protobuf.ADVEncryptionType_E2EE,
		Details:          []byte("details"),
		AccountKey:       bytes.Repeat([]byte{0x11}, 32),
		AccountSignature: bytes.Repeat([]byte{0x22}, 64),
		DeviceSignature:  bytes.Repeat([]byte{0x33}, 64),
	}
	return r
}

func TestRecordRoundTrip(t *testing.T) {
	for name, want := range map[string]*Record{
		"keys only":   testRecord(),
		"identity":    withIdentity(testRecord()),
		"empty blobs": withIdentity(testRecord()),
	} {
		if name == "empty blobs" {
			want.Identity.Details = nil
			want.Identity.AccountKey = nil
			want.Identity.AccountSignature = nil
			want.Identity.DeviceSignature = nil
		}
		raw, err := want.Marshal()
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		got, err := Unmarshal(raw)
		if err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: round trip mismatch\n got %#v\nwant %#v", name, got, want)
		}
	}
}

func TestMarshalRejectsOversizedField(t *testing.T) {
	r := withIdentity(testRecord())
	r.Identity.Details = make([]byte, MaxIdentityField+1)
	if _, err := r.Marshal(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("want ErrInvalidRecord, got %v", err)
	}
}

func TestUnmarshalErrors(t *testing.T) {
	valid, err := withIdentity(testRecord()).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	keysOnly, err := testRecord().Marshal()
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(f func([]byte) []byte) []byte { return f(append([]byte(nil), valid...)) }

	cases := map[string][]byte{
		"empty":            nil,
		"short":            valid[:MinRecordSize-1],
		"bad version":      mutate(func(b []byte) []byte { b[0] = 0xFF; return b }),
		"unknown flags":    mutate(func(b []byte) []byte { b[1] = 0x80; return b }),
		"truncated":        valid[:len(valid)-1],
		"trailing bytes":   append(append([]byte(nil), valid...), 0x00),
		"truncated header": mutate(func(b []byte) []byte { return b[:MinRecordSize+1] }),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Unmarshal(raw); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("want ErrInvalidRecord, got %v", err)
			}
		})
	}
	if _, err := Unmarshal(keysOnly); err != nil {
		t.Fatalf("keys-only record rejected: %v", err)
	}
}

func TestClear(t *testing.T) {
	r := withIdentity(testRecord())
	r.Clear()
	if r.NoisePrivateKey != [32]byte{} || r.IdentityPrivateKey != [32]byte{} || r.AdvSecret != [32]byte{} {
		t.Fatal("key material not cleared")
	}
	for name, blob := range map[string][]byte{
		"details": r.Identity.Details, "account key": r.Identity.AccountKey,
		"account sig": r.Identity.AccountSignature, "device sig": r.Identity.DeviceSignature,
	} {
		if len(blob) != 0 && !bytes.Equal(blob, make([]byte, len(blob))) {
			t.Fatalf("%s not cleared", name)
		}
	}
}

type fakeStore struct {
	records map[string][]byte
	err     error
}

func newFakeStore() *fakeStore { return &fakeStore{records: make(map[string][]byte)} }

func (f *fakeStore) Put(_ context.Context, key string, blob []byte) error {
	if f.err != nil {
		return f.err
	}
	f.records[key] = append([]byte(nil), blob...)
	return nil
}

func (f *fakeStore) Get(_ context.Context, key string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	blob, ok := f.records[key]
	if !ok {
		return nil, fmt.Errorf("missing %s", key)
	}
	return append([]byte(nil), blob...), nil
}

func (f *fakeStore) Delete(_ context.Context, key string) error {
	if f.err != nil {
		return f.err
	}
	delete(f.records, key)
	return nil
}

func TestManagerSaveLoadDelete(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	manager, err := NewManager(store)
	if err != nil {
		t.Fatal(err)
	}
	want := withIdentity(testRecord())

	if err := manager.Save(ctx, "session-1", want); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.records["sessions/session-1/credentials"]; !ok {
		t.Fatalf("unexpected keys: %v", store.records)
	}
	got, err := manager.Load(ctx, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded record mismatch:\n got %#v\nwant %#v", got, want)
	}
	if err := manager.Delete(ctx, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Load(ctx, "session-1"); err == nil {
		t.Fatal("deleted record still loads")
	}
}

func TestManagerValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := NewManager(nil); err == nil {
		t.Fatal("nil store must fail")
	}
	manager, err := NewManager(newFakeStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Save(ctx, "ok", nil); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("nil record: %v", err)
	}
	for _, id := range []string{"", strings.Repeat("a", 129), "has/slash", "has space"} {
		if err := manager.Save(ctx, id, testRecord()); !errors.Is(err, ErrInvalidSessionID) {
			t.Fatalf("save %q: %v", id, err)
		}
		if _, err := manager.Load(ctx, id); !errors.Is(err, ErrInvalidSessionID) {
			t.Fatalf("load %q: %v", id, err)
		}
		if err := manager.Delete(ctx, id); !errors.Is(err, ErrInvalidSessionID) {
			t.Fatalf("delete %q: %v", id, err)
		}
	}
}

func TestManagerStoreErrors(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("backend down")
	manager, err := NewManager(&fakeStore{records: map[string][]byte{}, err: sentinel})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Save(ctx, "s", testRecord()); !errors.Is(err, sentinel) {
		t.Fatalf("save: %v", err)
	}
	if _, err := manager.Load(ctx, "s"); !errors.Is(err, sentinel) {
		t.Fatalf("load: %v", err)
	}
	if err := manager.Delete(ctx, "s"); !errors.Is(err, sentinel) {
		t.Fatalf("delete: %v", err)
	}
}

func TestManagerWithVault(t *testing.T) {
	ctx := context.Background()
	key, err := envelope.NewKey(bytes.Repeat([]byte{0x42}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	backend := storecreds.NewMemoryBackend()
	vault, err := storecreds.NewVault(backend, key)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(vault)
	if err != nil {
		t.Fatal(err)
	}
	want := withIdentity(testRecord())
	if err := manager.Save(ctx, "vaulted", want); err != nil {
		t.Fatal(err)
	}
	raw, err := backend.Get(ctx, "sessions/vaulted/credentials")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, want.NoisePrivateKey[:]) || bytes.Contains(raw, want.AdvSecret[:]) {
		t.Fatal("backend holds plaintext key material")
	}
	got, err := manager.Load(ctx, "vaulted")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("vault round trip mismatch")
	}
}
