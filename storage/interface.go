// Package storage defines the persistence contracts shared by the
// application core and its backends. The SDK default backend is SQLite
// (storage/sqlite, pure Go — Phase 3); the REST server uses PostgreSQL
// (storage/postgres). Backends implement these interfaces; nothing outside
// this package knows which backend is active.
//
// The interface set mirrors Signal protocol state so the signal package
// (Phase 4) can be implemented against libsignal-protocol semantics without
// binding to its Rust/CGo implementation. Record blobs are opaque here;
// their marshalling belongs to the crypto layer.
//
// Status: contract skeleton (backends land in Phase 3).
package storage

import "context"

// Store is the aggregate persistence interface for one device identity.
// Implementations must be safe for concurrent use.
type Store interface {
	Device() DeviceStore
	Identities() IdentityStore
	Sessions() SessionStore
	PreKeys() PreKeyStore
	SignedPreKeys() SignedPreKeyStore
	SenderKeys() SenderKeyStore
	AppState() AppStateStore
}

// DeviceStore persists this device's registration and identity material.
type DeviceStore interface {
	Save(ctx context.Context, record []byte) error
	Load(ctx context.Context) ([]byte, error)
	Clear(ctx context.Context) error
}

// IdentityStore manages remote identity keys and trust decisions. The
// address is a Signal address (JID + device id).
type IdentityStore interface {
	SaveIdentity(ctx context.Context, address string, key []byte) error
	IsTrusted(ctx context.Context, address string, key []byte) (bool, error)
	DeleteIdentity(ctx context.Context, address string) error
}

// SessionStore persists Signal session records per remote address.
type SessionStore interface {
	StoreSession(ctx context.Context, address string, record []byte) error
	LoadSession(ctx context.Context, address string) ([]byte, error)
	HasSession(ctx context.Context, address string) (bool, error)
	DeleteSession(ctx context.Context, address string) error
}

// PreKeyStore manages one-time prekeys.
type PreKeyStore interface {
	StorePreKey(ctx context.Context, id uint32, record []byte) error
	LoadPreKey(ctx context.Context, id uint32) ([]byte, error)
	DeletePreKey(ctx context.Context, id uint32) error
	CountPreKeys(ctx context.Context) (int, error)
}

// SignedPreKeyStore manages signed prekeys.
type SignedPreKeyStore interface {
	StoreSignedPreKey(ctx context.Context, id uint32, record []byte) error
	LoadSignedPreKey(ctx context.Context, id uint32) ([]byte, error)
	DeleteSignedPreKey(ctx context.Context, id uint32) error
}

// SenderKeyStore persists group sender-key records.
type SenderKeyStore interface {
	StoreSenderKey(ctx context.Context, group, sender string, record []byte) error
	LoadSenderKey(ctx context.Context, group, sender string) ([]byte, error)
}

// AppStateStore persists WhatsApp app-state sync blobs per collection.
type AppStateStore interface {
	SaveState(ctx context.Context, collection string, version uint32, blob []byte) error
	LoadState(ctx context.Context, collection string) (version uint32, blob []byte, err error)
}
