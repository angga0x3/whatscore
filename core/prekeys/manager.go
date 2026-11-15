// Package prekeys owns this device's signed and one-time prekeys: generation
// behind an injected signer, encrypted persistence, rotation, and one-time
// consumption for inbound session bootstrap.
package prekeys

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/angga0x3/whatscore/protocol/signal"
)

const (
	recordVersion = 1
	maxOneTime    = 256
	keyPrefix     = "sessions/"
	keySuffix     = "/prekeys"
)

var (
	// ErrInvalidConfig is returned for unusable construction arguments.
	ErrInvalidConfig = errors.New("core/prekeys: invalid config")
	// ErrNotFound is returned when a prekey is absent.
	ErrNotFound = errors.New("core/prekeys: prekey not found")
	// ErrInvalidRecord is returned for malformed stored state.
	ErrInvalidRecord = errors.New("core/prekeys: invalid record")
)

// Store persists opaque records. *storage/credentials.Vault satisfies it.
type Store interface {
	Put(ctx context.Context, key string, blob []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

// Config controls generation and rotation.
type Config struct {
	// SignedPreKeyID is the id of the generated signed prekey.
	SignedPreKeyID uint32
	// OneTimeCount is how many one-time prekeys to generate up front.
	OneTimeCount int
	// FirstOneTimeID is the id of the first one-time prekey; later ones
	// increment from it.
	FirstOneTimeID uint32
	// RotateAfter triggers signed-prekey rotation when the stored key is
	// older than this. Zero disables time-based rotation.
	RotateAfter time.Duration
	// Now is injectable for tests.
	Now func() time.Time
	// NotFound reports whether a store error means "record absent". It is
	// supplied by the caller so this package never string-matches a backend
	// error; nil means only this package's ErrNotFound counts.
	NotFound func(error) bool
}

// Manager holds one device's prekeys behind an encrypted store. It is safe for
// concurrent use and implements core/messaging.PreKeySource.
type Manager struct {
	store    Store
	session  string
	identity signal.KeyPair
	signer   signal.Signer
	cfg      Config

	mu         sync.Mutex
	state      *state
	isNotFound func(error) bool
}

// state is the persisted prekey material. Identity keys live in the device
// credential record, so only prekeys are stored here.
type state struct {
	signed    signal.SignedPreKey
	signedAt  time.Time
	oneTime   []signal.PreKey
	nextOneID uint32
}

// New loads the stored prekeys, generating them when absent.
func New(ctx context.Context, store Store, sessionID string, identity signal.KeyPair, signer signal.Signer, cfg Config) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, fmt.Errorf("%w: nil signer", ErrInvalidConfig)
	}
	if cfg.OneTimeCount < 0 || cfg.OneTimeCount > maxOneTime {
		return nil, fmt.Errorf("%w: one-time count %d outside 0..%d", ErrInvalidConfig, cfg.OneTimeCount, maxOneTime)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	m := &Manager{store: store, session: sessionID, identity: identity, signer: signer, cfg: cfg, isNotFound: cfg.NotFound}
	raw, err := store.Get(ctx, m.key())
	switch {
	case err == nil:
		parsed, parseErr := unmarshal(raw)
		if parseErr != nil {
			return nil, parseErr
		}
		m.state = parsed
	case m.notFound(err):
		// No stored state yet: generate below.
	default:
		return nil, fmt.Errorf("core/prekeys: load: %w", err)
	}

	if m.state == nil {
		if err := m.rotateLocked(); err != nil {
			return nil, err
		}
		if err := m.persist(ctx); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// NeedRotation reports whether the signed prekey is older than RotateAfter.
func (m *Manager) NeedRotation() bool {
	if m.cfg.RotateAfter <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Now().Sub(m.state.signedAt) >= m.cfg.RotateAfter
}

// Rotate generates a fresh signed prekey and replenishes the one-time pool.
func (m *Manager) Rotate(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.rotateLocked(); err != nil {
		return err
	}
	return m.persist(ctx)
}

func (m *Manager) rotateLocked() error {
	signed, err := signal.GenerateSignedPreKey(m.cfg.SignedPreKeyID, m.signer)
	if err != nil {
		return fmt.Errorf("core/prekeys: signed prekey: %w", err)
	}
	m.state = &state{signed: signed, signedAt: m.cfg.Now()}
	for i := 0; i < m.cfg.OneTimeCount; i++ {
		id := m.cfg.FirstOneTimeID + uint32(i)
		prekey, err := signal.GeneratePreKey(id)
		if err != nil {
			return fmt.Errorf("core/prekeys: one-time prekey: %w", err)
		}
		m.state.oneTime = append(m.state.oneTime, prekey)
	}
	m.state.nextOneID = m.cfg.FirstOneTimeID + uint32(m.cfg.OneTimeCount)
	return nil
}

// Identity returns this device's identity key pair.
func (m *Manager) Identity() signal.KeyPair { return m.identity }

// SignedPreKey returns the signed prekey with the given id.
func (m *Manager) SignedPreKey(id uint32) (*signal.SignedPreKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.signed.ID != id {
		return nil, fmt.Errorf("%w: signed prekey %d", ErrNotFound, id)
	}
	signed := m.state.signed
	return &signed, nil
}

// OneTimePreKey returns the one-time prekey with the given id.
func (m *Manager) OneTimePreKey(id uint32) (*signal.PreKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.state.oneTime {
		if m.state.oneTime[i].ID == id {
			prekey := m.state.oneTime[i]
			return &prekey, nil
		}
	}
	return nil, fmt.Errorf("%w: one-time prekey %d", ErrNotFound, id)
}

// ConsumeOneTimePreKey removes a one-time prekey after successful bootstrap and
// persists the removal, so a replay cannot reuse it.
func (m *Manager) ConsumeOneTimePreKey(ctx context.Context, id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.state.oneTime {
		if m.state.oneTime[i].ID != id {
			continue
		}
		m.state.oneTime = append(m.state.oneTime[:i], m.state.oneTime[i+1:]...)
		return m.persist(ctx)
	}
	return fmt.Errorf("%w: one-time prekey %d", ErrNotFound, id)
}

// Replenish generates extra one-time prekeys up to target.
func (m *Manager) Replenish(ctx context.Context, target int) error {
	if target < 0 || target > maxOneTime {
		return fmt.Errorf("%w: target %d outside 0..%d", ErrInvalidConfig, target, maxOneTime)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(m.state.oneTime) < target {
		prekey, err := signal.GeneratePreKey(m.state.nextOneID)
		if err != nil {
			return fmt.Errorf("core/prekeys: one-time prekey: %w", err)
		}
		m.state.nextOneID++
		m.state.oneTime = append(m.state.oneTime, prekey)
	}
	return m.persist(ctx)
}

// Bundle returns a publishable bundle for peer consumption, optionally with a
// one-time prekey.
func (m *Manager) Bundle(includeOneTime bool) signal.PreKeyBundle {
	m.mu.Lock()
	defer m.mu.Unlock()
	bundle := signal.PreKeyBundle{
		IdentityKey:           m.identity.Public,
		SignedPreKeyID:        m.state.signed.ID,
		SignedPreKey:          m.state.signed.Pair.Public,
		SignedPreKeySignature: append([]byte(nil), m.state.signed.Signature...),
	}
	if includeOneTime && len(m.state.oneTime) > 0 {
		bundle.OneTimePreKeyID = m.state.oneTime[0].ID
		public := m.state.oneTime[0].Pair.Public
		bundle.OneTimePreKey = &public
	}
	return bundle
}

// OneTimeCount returns how many one-time prekeys remain.
func (m *Manager) OneTimeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.state.oneTime)
}

func (m *Manager) persist(ctx context.Context) error {
	if err := m.store.Put(ctx, m.key(), marshal(m.state)); err != nil {
		return fmt.Errorf("core/prekeys: persist: %w", err)
	}
	return nil
}

func (m *Manager) key() string { return keyPrefix + m.session + keySuffix }

func marshal(s *state) []byte {
	out := []byte{recordVersion}
	out = binary.BigEndian.AppendUint32(out, s.signed.ID)
	out = binary.BigEndian.AppendUint64(out, uint64(s.signedAt.Unix()))
	out = append(out, s.signed.Pair.Private[:]...)
	out = append(out, s.signed.Pair.Public[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(s.signed.Signature)))
	out = append(out, s.signed.Signature...)
	out = binary.BigEndian.AppendUint32(out, s.nextOneID)
	out = binary.BigEndian.AppendUint16(out, uint16(len(s.oneTime)))
	for _, prekey := range s.oneTime {
		out = binary.BigEndian.AppendUint32(out, prekey.ID)
		out = append(out, prekey.Pair.Private[:]...)
		out = append(out, prekey.Pair.Public[:]...)
	}
	return out
}

func unmarshal(raw []byte) (*state, error) {
	if len(raw) < 1 || raw[0] != recordVersion {
		return nil, fmt.Errorf("%w: version", ErrInvalidRecord)
	}
	reader := sliceReader{raw: raw[1:]}
	s := &state{}
	s.signed.ID = reader.uint32()
	s.signedAt = time.Unix(int64(reader.uint64()), 0).UTC()
	copy(s.signed.Pair.Private[:], reader.bytes(signal.KeySize))
	copy(s.signed.Pair.Public[:], reader.bytes(signal.KeySize))
	s.signed.Signature = reader.prefixed(signal.SignatureSize)
	s.nextOneID = reader.uint32()
	count := int(reader.uint16())
	if count > maxOneTime {
		return nil, fmt.Errorf("%w: %d one-time prekeys", ErrInvalidRecord, count)
	}
	for i := 0; i < count; i++ {
		var prekey signal.PreKey
		prekey.ID = reader.uint32()
		copy(prekey.Pair.Private[:], reader.bytes(signal.KeySize))
		copy(prekey.Pair.Public[:], reader.bytes(signal.KeySize))
		s.oneTime = append(s.oneTime, prekey)
	}
	if reader.err != nil || len(reader.raw) != 0 {
		return nil, fmt.Errorf("%w: truncated or trailing bytes", ErrInvalidRecord)
	}
	return s, nil
}

type sliceReader struct {
	raw []byte
	err error
}

func (r *sliceReader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.raw) < n {
		r.err = errors.New("short read")
		return nil
	}
	out := r.raw[:n]
	r.raw = r.raw[n:]
	return out
}

func (r *sliceReader) uint16() uint16 {
	raw := r.bytes(2)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint16(raw)
}

func (r *sliceReader) uint32() uint32 {
	raw := r.bytes(4)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint32(raw)
}

func (r *sliceReader) uint64() uint64 {
	raw := r.bytes(8)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

// prefixed reads a uint16 length followed by that many bytes.
func (r *sliceReader) prefixed(limit int) []byte {
	length := int(r.uint16())
	if r.err != nil {
		return nil
	}
	if length > limit {
		r.err = fmt.Errorf("field of %d bytes exceeds %d", length, limit)
		return nil
	}
	return r.bytes(length)
}

// notFound reports whether a store error means "no record yet". The store's own
// sentinel is supplied through WithNotFound so this package never string-matches
// or imports a backend.
func (m *Manager) notFound(err error) bool {
	if errors.Is(err, ErrNotFound) {
		return true
	}
	return m.isNotFound != nil && m.isNotFound(err)
}

// validateSessionID keeps the storage key unambiguous.
func validateSessionID(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("%w: empty session id", ErrInvalidConfig)
	}
	if len(sessionID) > 128 {
		return fmt.Errorf("%w: session id longer than 128 bytes", ErrInvalidConfig)
	}
	for i := 0; i < len(sessionID); i++ {
		c := sessionID[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return fmt.Errorf("%w: session id contains %q", ErrInvalidConfig, c)
	}
	return nil
}

// OneTimePreKeys returns a snapshot of the current one-time pool, for the
// upload node the server path builds. The pool can be large; callers should
// upload only the ids they have not pushed before.
func (m *Manager) OneTimePreKeys() []signal.PreKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]signal.PreKey, len(m.state.oneTime))
	copy(out, m.state.oneTime)
	return out
}
