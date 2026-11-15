// Package credentials persists the engine's device credentials through an
// encrypting store. The record encoding is versioned and opaque to the store;
// the store only sees ciphertext.
package credentials

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// Record layout and limits.
const (
	recordVersion = 1
	flagIdentity  = 1
	keyPrefix     = "sessions/"
	keySuffix     = "/credentials"

	// Record limits; identity fields are protobuf blobs, not media.
	MaxIdentityField = 1 << 16
	MinRecordSize    = 2 + 32*5 + 4
)

var (
	// ErrInvalidRecord is returned for malformed or truncated records.
	ErrInvalidRecord = errors.New("core/credentials: invalid record")
	// ErrInvalidSessionID is returned for an unusable session key.
	ErrInvalidSessionID = errors.New("core/credentials: invalid session id")
)

// Record is one device's credential material. Private keys are only ever
// written encrypted; call Clear when the record is no longer needed.
type Record struct {
	NoisePrivateKey    [32]byte
	NoisePublicKey     [32]byte
	IdentityPrivateKey [32]byte
	IdentityPublicKey  [32]byte
	AdvSecret          [32]byte
	RegistrationID     uint32

	// Identity is optional; it is present after a successful pairing.
	Identity *DeviceIdentity
}

// DeviceIdentity is the verified companion identity from pair-success.
type DeviceIdentity struct {
	RawID            uint32
	Timestamp        uint64
	KeyIndex         uint32
	AccountType      protobuf.ADVEncryptionType
	DeviceType       protobuf.ADVEncryptionType
	Details          []byte
	AccountKey       []byte
	AccountSignature []byte
	DeviceSignature  []byte
}

// Clear zeroes the record's key material and identity blobs.
func (r *Record) Clear() {
	for i := range r.NoisePrivateKey {
		r.NoisePrivateKey[i] = 0
	}
	for i := range r.IdentityPrivateKey {
		r.IdentityPrivateKey[i] = 0
	}
	for i := range r.AdvSecret {
		r.AdvSecret[i] = 0
	}
	if r.Identity != nil {
		clear(r.Identity.Details)
		clear(r.Identity.AccountKey)
		clear(r.Identity.AccountSignature)
		clear(r.Identity.DeviceSignature)
	}
}

// Marshal encodes the record. The format is versioned and little-endian for
// integers; byte fields are length-prefixed with uint16.
func (r *Record) Marshal() ([]byte, error) {
	if r.Identity != nil {
		if len(r.Identity.Details) > MaxIdentityField || len(r.Identity.AccountKey) > MaxIdentityField ||
			len(r.Identity.AccountSignature) > MaxIdentityField || len(r.Identity.DeviceSignature) > MaxIdentityField {
			return nil, fmt.Errorf("%w: identity field exceeds %d bytes", ErrInvalidRecord, MaxIdentityField)
		}
	}
	flags := byte(0)
	if r.Identity != nil {
		flags = flagIdentity
	}
	out := make([]byte, 0, MinRecordSize+256)
	out = append(out, recordVersion, flags)
	out = append(out, r.NoisePrivateKey[:]...)
	out = append(out, r.NoisePublicKey[:]...)
	out = append(out, r.IdentityPrivateKey[:]...)
	out = append(out, r.IdentityPublicKey[:]...)
	out = append(out, r.AdvSecret[:]...)
	out = binary.BigEndian.AppendUint32(out, r.RegistrationID)

	if r.Identity != nil {
		id := r.Identity
		out = binary.BigEndian.AppendUint32(out, id.RawID)
		out = binary.BigEndian.AppendUint64(out, id.Timestamp)
		out = binary.BigEndian.AppendUint32(out, id.KeyIndex)
		out = binary.BigEndian.AppendUint32(out, uint32(id.AccountType))
		out = binary.BigEndian.AppendUint32(out, uint32(id.DeviceType))
		for _, field := range [][]byte{id.Details, id.AccountKey, id.AccountSignature, id.DeviceSignature} {
			out = binary.BigEndian.AppendUint16(out, uint16(len(field)))
			out = append(out, field...)
		}
	}
	return out, nil
}

// Unmarshal decodes a record produced by Marshal.
func Unmarshal(raw []byte) (*Record, error) {
	if len(raw) < MinRecordSize {
		return nil, fmt.Errorf("%w: %d bytes, need at least %d", ErrInvalidRecord, len(raw), MinRecordSize)
	}
	if raw[0] != recordVersion {
		return nil, fmt.Errorf("%w: version %d", ErrInvalidRecord, raw[0])
	}
	if flags := raw[1]; flags&^flagIdentity != 0 {
		return nil, fmt.Errorf("%w: unknown flags %#x", ErrInvalidRecord, flags)
	}

	r := &Record{}
	offset := 2
	copy(r.NoisePrivateKey[:], raw[offset:offset+32])
	offset += 32
	copy(r.NoisePublicKey[:], raw[offset:offset+32])
	offset += 32
	copy(r.IdentityPrivateKey[:], raw[offset:offset+32])
	offset += 32
	copy(r.IdentityPublicKey[:], raw[offset:offset+32])
	offset += 32
	copy(r.AdvSecret[:], raw[offset:offset+32])
	offset += 32
	r.RegistrationID = binary.BigEndian.Uint32(raw[offset : offset+4])
	offset += 4

	if raw[1]&flagIdentity == 0 {
		if offset != len(raw) {
			return nil, fmt.Errorf("%w: %d trailing bytes", ErrInvalidRecord, len(raw)-offset)
		}
		return r, nil
	}

	if offset+4+8+4+4+4 > len(raw) {
		return nil, fmt.Errorf("%w: truncated identity header", ErrInvalidRecord)
	}
	r.Identity = &DeviceIdentity{}
	r.Identity.RawID = binary.BigEndian.Uint32(raw[offset : offset+4])
	offset += 4
	r.Identity.Timestamp = binary.BigEndian.Uint64(raw[offset : offset+8])
	offset += 8
	r.Identity.KeyIndex = binary.BigEndian.Uint32(raw[offset : offset+4])
	offset += 4
	r.Identity.AccountType = protobuf.ADVEncryptionType(binary.BigEndian.Uint32(raw[offset : offset+4]))
	offset += 4
	r.Identity.DeviceType = protobuf.ADVEncryptionType(binary.BigEndian.Uint32(raw[offset : offset+4]))
	offset += 4

	fields := []*[]byte{&r.Identity.Details, &r.Identity.AccountKey, &r.Identity.AccountSignature, &r.Identity.DeviceSignature}
	for _, dst := range fields {
		if offset+2 > len(raw) {
			return nil, fmt.Errorf("%w: truncated field length", ErrInvalidRecord)
		}
		length := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
		offset += 2
		if offset+length > len(raw) {
			return nil, fmt.Errorf("%w: field of %d bytes exceeds input", ErrInvalidRecord, length)
		}
		*dst = append([]byte(nil), raw[offset:offset+length]...)
		offset += length
	}
	if offset != len(raw) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrInvalidRecord, len(raw)-offset)
	}
	return r, nil
}

// Store persists opaque records. *storage/credentials.Vault satisfies it.
type Store interface {
	Put(ctx context.Context, key string, blob []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

// Manager maps a session id to an encrypted credential record.
type Manager struct {
	store Store
}

// NewManager wires a store.
func NewManager(store Store) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("core/credentials: nil store")
	}
	return &Manager{store: store}, nil
}

// Save encodes and stores the record for sessionID.
func (m *Manager) Save(ctx context.Context, sessionID string, record *Record) error {
	if record == nil {
		return fmt.Errorf("%w: nil record", ErrInvalidRecord)
	}
	key, err := recordKey(sessionID)
	if err != nil {
		return err
	}
	raw, err := record.Marshal()
	if err != nil {
		return err
	}
	if err := m.store.Put(ctx, key, raw); err != nil {
		return fmt.Errorf("core/credentials: save %q: %w", sessionID, err)
	}
	return nil
}

// Load reads and decodes the record for sessionID.
func (m *Manager) Load(ctx context.Context, sessionID string) (*Record, error) {
	key, err := recordKey(sessionID)
	if err != nil {
		return nil, err
	}
	raw, err := m.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	return Unmarshal(raw)
}

// Delete removes the record for sessionID.
func (m *Manager) Delete(ctx context.Context, sessionID string) error {
	key, err := recordKey(sessionID)
	if err != nil {
		return err
	}
	if err := m.store.Delete(ctx, key); err != nil {
		return fmt.Errorf("core/credentials: delete %q: %w", sessionID, err)
	}
	return nil
}

func recordKey(sessionID string) (string, error) {
	if sessionID == "" || len(sessionID) > 128 {
		return "", fmt.Errorf("%w: %q", ErrInvalidSessionID, sessionID)
	}
	for i := 0; i < len(sessionID); i++ {
		c := sessionID[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return "", fmt.Errorf("%w: %q contains %q", ErrInvalidSessionID, sessionID, c)
	}
	return keyPrefix + sessionID + keySuffix, nil
}
