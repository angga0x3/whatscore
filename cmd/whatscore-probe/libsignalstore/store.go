package libsignalstore

// In-memory stores implementing go.mau.fi/libsignal's 5 store interfaces.
// The persistence is handled by the caller (sessions file, vault) — these
// stores just hold state in memory for libsignal's session builder and
// cipher to use.

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	grouprecord "go.mau.fi/libsignal/groups/state/record"
	groupstore "go.mau.fi/libsignal/groups/state/store"
	"go.mau.fi/libsignal/keys/identity"
	lprotocol "go.mau.fi/libsignal/protocol"
	lrecord "go.mau.fi/libsignal/state/record"
	lstore "go.mau.fi/libsignal/state/store"
)

// SignalProtocolStore implements all 5 libsignal store interfaces in memory.
type SignalProtocolStore struct {
	mu               sync.RWMutex
	identityPair     *identity.KeyPair
	registrationID   uint32
	remoteIdentities map[string]*identity.Key
	sessions         map[string]*lrecord.Session
	preKeys          map[uint32]*lrecord.PreKey
	signedPreKeys    map[uint32]*lrecord.SignedPreKey
	senderKeys       map[string]*grouprecord.SenderKey
}

func New(identityPair *identity.KeyPair, registrationID uint32) *SignalProtocolStore {
	return &SignalProtocolStore{
		identityPair:     identityPair,
		registrationID:   registrationID,
		remoteIdentities: make(map[string]*identity.Key),
		sessions:         make(map[string]*lrecord.Session),
		preKeys:          make(map[uint32]*lrecord.PreKey),
		signedPreKeys:    make(map[uint32]*lrecord.SignedPreKey),
		senderKeys:       make(map[string]*grouprecord.SenderKey),
	}
}

func addrKey(addr *lprotocol.SignalAddress) string {
	return fmt.Sprintf("%s:%d", addr.Name(), addr.DeviceID())
}

// --- IdentityKeyStore ---

func (s *SignalProtocolStore) GetIdentityKeyPair() *identity.KeyPair {
	return s.identityPair
}

func (s *SignalProtocolStore) GetLocalRegistrationID() uint32 {
	return s.registrationID
}

func (s *SignalProtocolStore) SaveIdentity(ctx context.Context, address *lprotocol.SignalAddress, key *identity.Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteIdentities[addrKey(address)] = key
	return nil
}

func (s *SignalProtocolStore) IsTrustedIdentity(ctx context.Context, address *lprotocol.SignalAddress, key *identity.Key) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	existing, ok := s.remoteIdentities[addrKey(address)]
	if !ok {
		return true, nil // trust on first use
	}
	return bytes.Equal(existing.Serialize(), key.Serialize()), nil
}

// --- SessionStore ---

func (s *SignalProtocolStore) LoadSession(ctx context.Context, address *lprotocol.SignalAddress) (*lrecord.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[addrKey(address)]
	if !ok {
		return lrecord.NewSession(nil, nil), nil
	}
	return session, nil
}

func (s *SignalProtocolStore) GetSubDeviceSessions(ctx context.Context, name string) ([]uint32, error) {
	return nil, nil
}

func (s *SignalProtocolStore) StoreSession(ctx context.Context, address *lprotocol.SignalAddress, rec *lrecord.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[addrKey(address)] = rec
	return nil
}

func (s *SignalProtocolStore) ContainsSession(ctx context.Context, address *lprotocol.SignalAddress) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.sessions[addrKey(address)]
	return ok, nil
}

func (s *SignalProtocolStore) DeleteSession(ctx context.Context, address *lprotocol.SignalAddress) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, addrKey(address))
	return nil
}

func (s *SignalProtocolStore) DeleteAllSessions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]*lrecord.Session)
	return nil
}

// --- PreKeyStore ---

func (s *SignalProtocolStore) LoadPreKey(ctx context.Context, preKeyID uint32) (*lrecord.PreKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.preKeys[preKeyID]
	if !ok {
		return nil, fmt.Errorf("prekey %d not found", preKeyID)
	}
	return rec, nil
}

func (s *SignalProtocolStore) StorePreKey(ctx context.Context, preKeyID uint32, rec *lrecord.PreKey) error {
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

func (s *SignalProtocolStore) LoadSignedPreKey(ctx context.Context, signedPreKeyID uint32) (*lrecord.SignedPreKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.signedPreKeys[signedPreKeyID]
	if !ok {
		return nil, fmt.Errorf("signed prekey %d not found", signedPreKeyID)
	}
	return rec, nil
}

func (s *SignalProtocolStore) LoadSignedPreKeys(ctx context.Context) ([]*lrecord.SignedPreKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*lrecord.SignedPreKey, 0, len(s.signedPreKeys))
	for _, rec := range s.signedPreKeys {
		out = append(out, rec)
	}
	return out, nil
}

func (s *SignalProtocolStore) StoreSignedPreKey(ctx context.Context, signedPreKeyID uint32, rec *lrecord.SignedPreKey) error {
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

func (s *SignalProtocolStore) StoreSenderKey(ctx context.Context, senderKeyName *lprotocol.SenderKeyName, keyRecord *grouprecord.SenderKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.senderKeys[senderKeyName.GroupID()+"|"+senderKeyName.Sender().String()] = keyRecord
	return nil
}

func (s *SignalProtocolStore) LoadSenderKey(ctx context.Context, senderKeyName *lprotocol.SenderKeyName) (*grouprecord.SenderKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.senderKeys[senderKeyName.GroupID()+"|"+senderKeyName.Sender().String()]
	if !ok {
		return grouprecord.NewSenderKey(nil, nil), nil
	}
	return rec, nil
}

// Compile-time checks that all 5 interfaces are implemented.
var (
	_ lstore.IdentityKey   = (*SignalProtocolStore)(nil)
	_ lstore.Session       = (*SignalProtocolStore)(nil)
	_ lstore.PreKey        = (*SignalProtocolStore)(nil)
	_ lstore.SignedPreKey  = (*SignalProtocolStore)(nil)
	_ groupstore.SenderKey = (*SignalProtocolStore)(nil)
)
