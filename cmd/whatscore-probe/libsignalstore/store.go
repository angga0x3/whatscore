package libsignalstore

// In-memory stores implementing go.mau.fi/libsignal's 5 store interfaces.
// The persistence is handled by the caller (sessions file, vault) — these
// stores just hold state in memory for libsignal's session builder and
// cipher to use.

import (
	"context"
	"fmt"
	"sync"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/groups/state/record"
	groupstore "go.mau.fi/libsignal/groups/state/store"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/state/store"
)

// SignalProtocolStore implements all 5 libsignal store interfaces in memory.
type SignalProtocolStore struct {
	mu sync.RWMutex

	// Identity
	identityPair     *identity.KeyPair
	registrationID   uint32
	remoteIdentities map[string]*identity.Key

	// Sessions
	sessions map[string]*record.Session

	// PreKeys
	preKeys      map[uint32]*record.PreKey
	nextPreKeyID uint32

	// Signed PreKeys
	signedPreKeys map[uint32]*record.SignedPreKeyRecord

	// Sender Keys
	senderKeys map[string]*record.SenderKey
}

func New(identityPair *identity.KeyPair, registrationID uint32) *SignalProtocolStore {
	return &SignalProtocolStore{
		identityPair:     identityPair,
		registrationID:   registrationID,
		remoteIdentities: make(map[string]*identity.Key),
		sessions:         make(map[string]*record.Session),
		preKeys:          make(map[uint32]*record.PreKey),
		nextPreKeyID:     1,
		signedPreKeys:    make(map[uint32]*record.SignedPreKeyRecord),
		senderKeys:       make(map[string]*record.SenderKey),
	}
}

func addrKey(addr *protocol.SignalAddress) string {
	return fmt.Sprintf("%s:%d", addr.Name(), addr.DeviceID())
}

// --- IdentityKeyStore ---

func (s *SignalProtocolStore) GetIdentityKeyPair() *identity.KeyPair {
	return s.identityPair
}

func (s *SignalProtocolStore) GetLocalRegistrationID() uint32 {
	return s.registrationID
}

func (s *SignalProtocolStore) SaveIdentity(ctx context.Context, address *protocol.SignalAddress, key *identity.Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteIdentities[addrKey(address)] = key
	return nil
}

func (s *SignalProtocolStore) IsTrustedIdentity(ctx context.Context, address *protocol.SignalAddress, key *identity.Key) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	existing, ok := s.remoteIdentities[addrKey(address)]
	if !ok {
		return true, nil // trust on first use
	}
	return existing.String() == key.String(), nil
}

// --- SessionStore ---

func (s *SignalProtocolStore) LoadSession(ctx context.Context, address *protocol.SignalAddress) (*record.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[addrKey(address)]
	if !ok {
		return record.NewSession(nil, nil), nil
	}
	return session, nil
}

func (s *SignalProtocolStore) GetSubDeviceSessions(ctx context.Context, name string) ([]uint32, error) {
	return nil, nil
}

func (s *SignalProtocolStore) StoreSession(ctx context.Context, address *protocol.SignalAddress, rec *record.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[addrKey(address)] = rec
	return nil
}

func (s *SignalProtocolStore) ContainsSession(ctx context.Context, address *protocol.SignalAddress) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.sessions[addrKey(address)]
	return ok, nil
}

func (s *SignalProtocolStore) DeleteSession(ctx context.Context, address *protocol.SignalAddress) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, addrKey(address))
	return nil
}

func (s *SignalProtocolStore) DeleteAllSessions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]*record.Session)
	return nil
}

// --- PreKeyStore ---

func (s *SignalProtocolStore) LoadPreKey(ctx context.Context, preKeyID uint32) (*record.PreKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.preKeys[preKeyID]
	if !ok {
		return nil, fmt.Errorf("prekey %d not found", preKeyID)
	}
	return rec, nil
}

func (s *SignalProtocolStore) StorePreKey(ctx context.Context, preKeyID uint32, rec *record.PreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preKeys[preKeyID] = rec
	return nil
}

func (s *SignalProtocolStore) ContainsPreKey(ctx context.Context, preKeyID uint32) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.preKeys[preKeyID]
	return ok, nil
}

func (s *SignalProtocolStore) RemovePreKey(ctx context.Context, preKeyID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.preKeys, preKeyID)
	return nil
}

// --- SignedPreKeyStore ---

func (s *SignalProtocolStore) LoadSignedPreKey(ctx context.Context, signedPreKeyID uint32) (*record.SignedPreKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.signedPreKeys[signedPreKeyID]
	if !ok {
		return nil, fmt.Errorf("signed prekey %d not found", signedPreKeyID)
	}
	return rec, nil
}

func (s *SignalProtocolStore) LoadSignedPreKeys(ctx context.Context) ([]*record.SignedPreKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*record.SignedPreKeyRecord, 0, len(s.signedPreKeys))
	for _, rec := range s.signedPreKeys {
		out = append(out, rec)
	}
	return out, nil
}

func (s *SignalProtocolStore) StoreSignedPreKey(ctx context.Context, signedPreKeyID uint32, rec *record.SignedPreKeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signedPreKeys[signedPreKeyID] = rec
	return nil
}

func (s *SignalProtocolStore) ContainsSignedPreKey(ctx context.Context, signedPreKeyID uint32) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.signedPreKeys[signedPreKeyID]
	return ok, nil
}

func (s *SignalProtocolStore) RemoveSignedPreKey(ctx context.Context, signedPreKeyID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.signedPreKeys, signedPreKeyID)
	return nil
}

// --- SenderKeyStore ---

func (s *SignalProtocolStore) StoreSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName, keyRecord *record.SenderKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.senderKeys[senderKeyName.String()] = keyRecord
	return nil
}

func (s *SignalProtocolStore) LoadSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName) (*record.SenderKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.senderKeys[senderKeyName.String()]
	if !ok {
		return record.NewSenderKey(nil, nil), nil
	}
	return rec, nil
}

var _ store.SenderKey = (*SignalProtocolStore)(nil)
