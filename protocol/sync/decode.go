package sync

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/internal/cbc"
	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// KeySize is the size of each expanded app-state key.
const KeySize = 32

// KeysInfo is the HKDF info string for app-state key expansion (PF-075).
const KeysInfo = "WhatsApp Mutation Keys"

// ExpandedSize is the total expansion length: five 32-byte keys.
const ExpandedSize = 5 * KeySize

var (
	// ErrInvalidKey is returned for unusable app-state key material.
	ErrInvalidKey = errors.New("sync: invalid key")
	// ErrInvalidMutation is returned for a mutation that cannot be decoded.
	ErrInvalidMutation = errors.New("sync: invalid mutation")
)

// Keys are the five keys derived from one app-state sync key (PF-075).
type Keys struct {
	Index           [KeySize]byte
	ValueEncryption [KeySize]byte
	ValueMAC        [KeySize]byte
	SnapshotMAC     [KeySize]byte
	PatchMAC        [KeySize]byte
}

// ExpandKeys derives the key set:
//
//	HKDF-SHA256(ikm=keyData, salt=nil, info="WhatsApp Mutation Keys", L=160)
//
// with index, value-encryption, value-MAC, snapshot-MAC and patch-MAC keys in
// that order.
func ExpandKeys(keyData []byte) (Keys, error) {
	if len(keyData) == 0 {
		return Keys{}, fmt.Errorf("%w: empty key data", ErrInvalidKey)
	}
	raw, err := hkdf.Key(sha256.New, keyData, nil, KeysInfo, ExpandedSize)
	if err != nil {
		return Keys{}, fmt.Errorf("%w: hkdf: %w", ErrInvalidKey, err)
	}
	var keys Keys
	copy(keys.Index[:], raw[0:KeySize])
	copy(keys.ValueEncryption[:], raw[KeySize:2*KeySize])
	copy(keys.ValueMAC[:], raw[2*KeySize:3*KeySize])
	copy(keys.SnapshotMAC[:], raw[3*KeySize:4*KeySize])
	copy(keys.PatchMAC[:], raw[4*KeySize:5*KeySize])
	return keys, nil
}

// indexMAC computes HMAC-SHA256(indexKey, indexJSON) (PF-076).
func indexMAC(keys Keys, index string) ([]byte, error) {
	if index == "" {
		return nil, fmt.Errorf("%w: empty index", ErrInvalidMutation)
	}
	mac := hmac.New(sha256.New, keys.Index[:])
	mac.Write([]byte(index))
	return mac.Sum(nil), nil
}

// Decoded is one decrypted mutation (PF-076).
type Decoded struct {
	Operation string
	KeyID     string
	IndexMAC  []byte
	ValueMAC  []byte
	// Index is the JSON index string echoed inside the decrypted value.
	Index string
	// Action is the raw SyncActionValue bytes; interpretation is the caller's.
	Action []byte
	// Version is the per-mutation action version.
	Version int32
}

// DecodeMutation verifies the value MAC, decrypts the blob, and verifies the
// index MAC against the decrypted index (PF-076).
//
// A REMOVE with no value is returned undecoded: it carries no ciphertext to
// verify, so only its index MAC is meaningful.
func DecodeMutation(mutation PatchMutation, keys Keys) (*Decoded, error) {
	decoded := &Decoded{
		Operation: mutation.Operation,
		KeyID:     string(mutation.KeyID),
		IndexMAC:  append([]byte(nil), mutation.IndexMAC...),
		ValueMAC:  append([]byte(nil), mutation.ValueMAC...),
	}
	if len(mutation.Value) == 0 {
		if mutation.Operation != OperationRemove {
			return nil, fmt.Errorf("%w: %s mutation without a value", ErrInvalidMutation, mutation.Operation)
		}
		return decoded, nil
	}
	if err := VerifyValueMAC(string(mutation.ValueMAC), string(keys.ValueMAC[:]), mutation.Operation, string(mutation.KeyID), mutation.Value); err != nil {
		return nil, err
	}

	if len(mutation.Value) < ValueIVSize {
		return nil, fmt.Errorf("%w: value is %d bytes", ErrInvalidMutation, len(mutation.Value))
	}
	plaintext, err := cbc.Decrypt(keys.ValueEncryption[:], mutation.Value[:ValueIVSize], mutation.Value[ValueIVSize:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMutation, err)
	}

	var action protobuf.SyncActionData
	if err := proto.Unmarshal(plaintext, &action); err != nil {
		return nil, fmt.Errorf("%w: action: %w", ErrInvalidMutation, err)
	}
	decoded.Index = string(action.GetIndex())
	decoded.Version = action.GetVersion()
	if value := action.GetValue(); value != nil {
		decoded.Action = value.GetRaw()
	}

	expected, err := indexMAC(keys, decoded.Index)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(expected, mutation.IndexMAC) {
		return nil, fmt.Errorf("%w: index MAC mismatch", ErrBadMAC)
	}
	return decoded, nil
}
