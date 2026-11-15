package signalsession

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/angga0x3/whatscore/protocol/signal"
)

const recordVersion = 1

// ErrInvalidRecord is returned for malformed stored records.
var ErrInvalidRecord = errors.New("core/signalsession: invalid record")

// Record is one peer's ratchet state plus the identity key it belongs to.
// The peer identity is needed for every SignalMessage MAC, so it travels
// with the state.
type Record struct {
	PeerIdentity [signal.KeySize]byte
	State        *signal.State
}

// MarshalBinary encodes the record deterministically.
func (r *Record) MarshalBinary() ([]byte, error) {
	if r == nil || r.State == nil {
		return nil, fmt.Errorf("%w: nil state", ErrInvalidRecord)
	}
	state, err := r.State.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+signal.KeySize+len(state))
	out = append(out, recordVersion)
	out = append(out, r.PeerIdentity[:]...)
	out = append(out, state...)
	return out, nil
}

// ParseRecord decodes a stored record.
func ParseRecord(raw []byte) (*Record, error) {
	if len(raw) < 1+signal.KeySize {
		return nil, fmt.Errorf("%w: %d bytes", ErrInvalidRecord, len(raw))
	}
	if raw[0] != recordVersion {
		return nil, fmt.Errorf("%w: version %d", ErrInvalidRecord, raw[0])
	}
	record := &Record{}
	copy(record.PeerIdentity[:], raw[1:1+signal.KeySize])
	state, err := signal.ParseState(raw[1+signal.KeySize:])
	if err != nil {
		return nil, err
	}
	record.State = state
	return record, nil
}

// SaveRecord encodes and stores the record for peer.
func (m *Manager) SaveRecord(ctx context.Context, peer string, record *Record) error {
	key, err := m.key(peer)
	if err != nil {
		return err
	}
	raw, err := record.MarshalBinary()
	if err != nil {
		return fmt.Errorf("core/signalsession: encode %q: %w", peer, err)
	}
	if err := m.store.Put(ctx, key, raw); err != nil {
		return fmt.Errorf("core/signalsession: save %q: %w", peer, err)
	}
	return nil
}

// LoadRecord reads and decodes the record for peer.
func (m *Manager) LoadRecord(ctx context.Context, peer string) (*Record, error) {
	key, err := m.key(peer)
	if err != nil {
		return nil, err
	}
	raw, err := m.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	record, err := ParseRecord(raw)
	if err != nil {
		return nil, fmt.Errorf("core/signalsession: decode %q: %w", peer, err)
	}
	return record, nil
}

func (m *Manager) key(peer string) (string, error) {
	if err := validateToken(peer, "peer", 256); err != nil {
		return "", err
	}
	return "sessions/" + m.sessionID + "/signal/" + peer, nil
}

func validateToken(value, field string, limit int) error {
	if value == "" {
		return fmt.Errorf("%w: empty %s", ErrInvalidAddress, field)
	}
	if len(value) > limit {
		return fmt.Errorf("%w: %s longer than %d bytes", ErrInvalidAddress, field, limit)
	}
	if strings.ContainsAny(value, " \t\r\n/") {
		return fmt.Errorf("%w: %s contains a separator or whitespace", ErrInvalidAddress, field)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return fmt.Errorf("%w: %s contains non-printable bytes", ErrInvalidAddress, field)
		}
	}
	return nil
}
