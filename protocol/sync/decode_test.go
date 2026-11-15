package sync

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/internal/cbc"
	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// fixtureKeys returns a deterministic key set and the key data it came from.
func fixtureKeys(t *testing.T) Keys {
	t.Helper()
	keys, err := ExpandKeys(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// buildMutation produces a wire-consistent mutation for the index and action.
func buildMutation(t *testing.T, keys Keys, keyID []byte, operation, index string, action []byte, version int32) PatchMutation {
	t.Helper()
	plaintext, err := proto.Marshal(&protobuf.SyncActionData{
		Index:   []byte(index),
		Value:   &protobuf.SyncActionValue{Raw: action},
		Version: proto.Int32(version),
	})
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{0x01}, ValueIVSize)
	ciphertext, err := cbc.Encrypt(keys.ValueEncryption[:], iv, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	value := append(append([]byte(nil), iv...), ciphertext...)
	operationName := OperationSet
	opByte := byte(0x01)
	if operation == OperationRemove {
		opByte = 0x02
	}
	mac := hmac.New(sha512.New, keys.ValueMAC[:])
	mac.Write([]byte{opByte})
	mac.Write(keyID)
	mac.Write(value)
	mac.Write([]byte{0, 0, 0, 0, 0, 0, 0, byte(len(keyID) + 1)})
	indexMAC := hmac.New(sha256.New, keys.Index[:])
	indexMAC.Write([]byte(index))
	return PatchMutation{
		Operation: operationName,
		KeyID:     keyID,
		IndexMAC:  indexMAC.Sum(nil),
		Value:     value,
		ValueMAC:  mac.Sum(nil)[:ValueMACSize],
	}
}

func TestExpandKeys(t *testing.T) {
	keys := fixtureKeys(t)
	seen := map[[KeySize]byte]string{}
	for name, key := range map[string][KeySize]byte{
		"index": keys.Index, "value encryption": keys.ValueEncryption,
		"value mac": keys.ValueMAC, "snapshot mac": keys.SnapshotMAC, "patch mac": keys.PatchMAC,
	} {
		if other, dup := seen[key]; dup {
			t.Fatalf("%s equals %s", name, other)
		}
		seen[key] = name
	}
	if _, err := ExpandKeys(nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("empty key data: %v", err)
	}
	again := fixtureKeys(t)
	if keys != again {
		t.Fatal("expansion is not deterministic")
	}
}

func TestDecodeMutation(t *testing.T) {
	keys := fixtureKeys(t)
	keyID := []byte{1, 2, 3}
	mutation := buildMutation(t, keys, keyID, OperationSet, `["setting_pushName"]`, []byte("action-bytes"), 12)

	decoded, err := DecodeMutation(mutation, keys)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Operation != OperationSet || decoded.KeyID != string(keyID) {
		t.Fatalf("decoded = %#v", decoded)
	}
	if decoded.Index != `["setting_pushName"]` || decoded.Version != 12 {
		t.Fatalf("action metadata = %#v", decoded)
	}
	if !bytes.Equal(decoded.Action, []byte("action-bytes")) {
		t.Fatalf("action = %q", decoded.Action)
	}
	if !bytes.Equal(decoded.ValueMAC, mutation.ValueMAC) || !bytes.Equal(decoded.IndexMAC, mutation.IndexMAC) {
		t.Fatal("MACs not carried through")
	}
}

func TestDecodeMutationRemoveWithoutValue(t *testing.T) {
	keys := fixtureKeys(t)
	mutation := PatchMutation{
		Operation: OperationRemove,
		KeyID:     []byte{1},
		IndexMAC:  bytes.Repeat([]byte{0x09}, 32),
	}
	decoded, err := DecodeMutation(mutation, keys)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Index != "" || decoded.Action != nil {
		t.Fatalf("decoded = %#v", decoded)
	}
	if !bytes.Equal(decoded.IndexMAC, mutation.IndexMAC) {
		t.Fatal("index MAC not carried through")
	}

	mutation.Operation = OperationSet
	if _, err := DecodeMutation(mutation, keys); !errors.Is(err, ErrInvalidMutation) {
		t.Fatalf("SET without value: %v", err)
	}
}

func TestDecodeMutationRejects(t *testing.T) {
	keys := fixtureKeys(t)
	keyID := []byte{1, 2, 3}
	valid := buildMutation(t, keys, keyID, OperationSet, `["x"]`, []byte("a"), 1)

	tamperedValue := cloneMutation(valid)
	tamperedValue.Value[len(tamperedValue.Value)-1] ^= 0x01

	tamperedIndexMAC := cloneMutation(valid)
	tamperedIndexMAC.IndexMAC[0] ^= 0x01

	otherKeys := fixtureKeys(t)
	otherKeys.ValueMAC[0] ^= 0x01

	cases := map[string]struct {
		mutation PatchMutation
		keys     Keys
		want     error
	}{
		"tampered value":     {tamperedValue, keys, ErrBadMAC},
		"tampered index mac": {tamperedIndexMAC, keys, ErrBadMAC},
		"wrong value key":    {valid, otherKeys, ErrBadMAC},
		"short value":        {PatchMutation{Operation: OperationSet, KeyID: keyID, IndexMAC: valid.IndexMAC, Value: []byte{1}, ValueMAC: signValue(t, keys, keyID, OperationSet, []byte{1})}, keys, ErrInvalidMutation},
		"bad ciphertext":     {PatchMutation{Operation: OperationSet, KeyID: keyID, IndexMAC: valid.IndexMAC, Value: append(append([]byte(nil), bytes.Repeat([]byte{0x02}, ValueIVSize)...), 1), ValueMAC: valid.ValueMAC}, keys, ErrBadMAC},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeMutation(tc.mutation, tc.keys); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// signValue computes a valid value MAC for arbitrary value bytes, so tests can
// reach failures that happen after authentication.
func signValue(t *testing.T, keys Keys, keyID []byte, operation string, value []byte) []byte {
	t.Helper()
	opByte := byte(0x01)
	if operation == OperationRemove {
		opByte = 0x02
	}
	mac := hmac.New(sha512.New, keys.ValueMAC[:])
	mac.Write([]byte{opByte})
	mac.Write(keyID)
	mac.Write(value)
	var length [8]byte
	length[7] = byte(len(keyID) + 1)
	mac.Write(length[:])
	return mac.Sum(nil)[:ValueMACSize]
}

func cloneMutation(m PatchMutation) PatchMutation {
	return PatchMutation{
		Operation: m.Operation,
		KeyID:     append([]byte(nil), m.KeyID...),
		IndexMAC:  append([]byte(nil), m.IndexMAC...),
		Value:     append([]byte(nil), m.Value...),
		ValueMAC:  append([]byte(nil), m.ValueMAC...),
	}
}
