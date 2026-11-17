package signal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// Serialization bounds and layout.
const (
	stateVersion        = 2
	MaxSerializedChains = 64
	maxStateBytes       = 256 << 10
	stateHeaderSize     = 1 + 4*KeySize + 4 + 4 + 2 + 2
)

// ErrInvalidState is returned for malformed serialized ratchet state.
var ErrInvalidState = errors.New("signal: invalid state")

// MarshalBinary encodes the ratchet state deterministically. Map entries are
// sorted, so the same state always produces the same bytes.
func (s *State) MarshalBinary() ([]byte, error) {
	if len(s.receiverChains) > MaxSerializedChains {
		return nil, fmt.Errorf("%w: %d receiver chains", ErrInvalidState, len(s.receiverChains))
	}
	if len(s.skipped) > MaxSkippedKeys {
		return nil, fmt.Errorf("%w: %d skipped keys", ErrInvalidState, len(s.skipped))
	}

	size := stateHeaderSize +
		len(s.receiverChains)*(2*KeySize+4) + len(s.skipped)*(KeySize+4+MessageKeysSize)
	out := make([]byte, 0, size)
	out = append(out, stateVersion)
	out = append(out, s.root[:]...)
	out = append(out, s.senderRatchet.Private[:]...)
	out = append(out, s.senderRatchet.Public[:]...)
	out = append(out, s.senderChain[:]...)
	out = binary.BigEndian.AppendUint32(out, s.senderIndex)
	out = binary.BigEndian.AppendUint32(out, s.previousChainLength)

	ratchets := make([][KeySize]byte, 0, len(s.receiverChains))
	for ratchet := range s.receiverChains {
		ratchets = append(ratchets, ratchet)
	}
	slices.SortFunc(ratchets, func(a, b [KeySize]byte) int { return bytes.Compare(a[:], b[:]) })
	out = binary.BigEndian.AppendUint16(out, uint16(len(ratchets)))
	for _, ratchet := range ratchets {
		chain := s.receiverChains[ratchet]
		out = append(out, ratchet[:]...)
		out = append(out, chain.chain[:]...)
		out = binary.BigEndian.AppendUint32(out, chain.index)
	}

	skipped := make([]skippedKey, 0, len(s.skipped))
	for key := range s.skipped {
		skipped = append(skipped, key)
	}
	slices.SortFunc(skipped, func(a, b skippedKey) int {
		if c := bytes.Compare(a.ratchet[:], b.ratchet[:]); c != 0 {
			return c
		}
		switch {
		case a.index < b.index:
			return -1
		case a.index > b.index:
			return 1
		default:
			return 0
		}
	})
	out = binary.BigEndian.AppendUint16(out, uint16(len(skipped)))
	for _, key := range skipped {
		keys := s.skipped[key]
		out = append(out, key.ratchet[:]...)
		out = binary.BigEndian.AppendUint32(out, key.index)
		out = append(out, keys.CipherKey[:]...)
		out = append(out, keys.MACKey[:]...)
		out = append(out, keys.IV[:]...)
	}
	if s.pendingPreKey == nil {
		out = append(out, 0)
	} else {
		p := s.pendingPreKey
		out = append(out, 1)
		out = binary.BigEndian.AppendUint32(out, p.RegistrationID)
		out = binary.BigEndian.AppendUint32(out, p.SignedPreKeyID)
		out = binary.BigEndian.AppendUint32(out, p.PreKeyID)
		out = append(out, p.BaseKey[:]...)
	}
	if s.bootstrapBase == nil {
		out = append(out, 0)
	} else {
		out = append(out, 1)
		out = append(out, s.bootstrapBase[:]...)
	}
	return out, nil
}

// UnmarshalBinary replaces the state with the serialized one.
func (s *State) UnmarshalBinary(raw []byte) error {
	if len(raw) > maxStateBytes {
		return fmt.Errorf("%w: %d bytes exceeds limit", ErrInvalidState, len(raw))
	}
	if len(raw) < stateHeaderSize {
		return fmt.Errorf("%w: %d bytes", ErrInvalidState, len(raw))
	}
	if raw[0] != 1 && raw[0] != stateVersion {
		return fmt.Errorf("%w: version %d", ErrInvalidState, raw[0])
	}
	reader := stateReader{raw: raw[1:]}

	var next State
	next.root = RootKey(reader.key())
	next.senderRatchet.Private = reader.key()
	next.senderRatchet.Public = reader.key()
	next.senderChain = ChainKey(reader.key())
	next.senderIndex = reader.uint32()
	next.previousChainLength = reader.uint32()

	chainCount := reader.uint16()
	if chainCount > MaxSerializedChains {
		return fmt.Errorf("%w: %d receiver chains", ErrInvalidState, chainCount)
	}
	next.receiverChains = make(map[[KeySize]byte]*receiverChain, chainCount)
	for i := 0; i < int(chainCount); i++ {
		ratchet := reader.key()
		chain := &receiverChain{chain: ChainKey(reader.key()), index: reader.uint32()}
		if _, exists := next.receiverChains[ratchet]; exists {
			return fmt.Errorf("%w: duplicate receiver chain", ErrInvalidState)
		}
		next.receiverChains[ratchet] = chain
	}

	skippedCount := reader.uint16()
	if skippedCount > MaxSkippedKeys {
		return fmt.Errorf("%w: %d skipped keys", ErrInvalidState, skippedCount)
	}
	next.skipped = make(map[skippedKey]MessageKeys, skippedCount)
	for i := 0; i < int(skippedCount); i++ {
		key := skippedKey{ratchet: reader.key(), index: reader.uint32()}
		keys := MessageKeys{
			CipherKey: reader.key(),
			MACKey:    reader.key(),
			Index:     key.index,
		}
		copy(keys.IV[:], reader.bytes(16))
		if _, exists := next.skipped[key]; exists {
			return fmt.Errorf("%w: duplicate skipped key", ErrInvalidState)
		}
		next.skipped[key] = keys
	}
	if raw[0] >= 2 {
		flag := reader.bytes(1)
		if reader.err != nil {
			return fmt.Errorf("%w: missing pending prekey flag", ErrInvalidState)
		}
		switch flag[0] {
		case 0:
		case 1:
			next.pendingPreKey = &PendingPreKey{
				RegistrationID: reader.uint32(), SignedPreKeyID: reader.uint32(),
				PreKeyID: reader.uint32(), BaseKey: reader.key(),
			}
		default:
			return fmt.Errorf("%w: invalid pending prekey flag", ErrInvalidState)
		}
		flag = reader.bytes(1)
		if reader.err != nil {
			return fmt.Errorf("%w: missing bootstrap flag", ErrInvalidState)
		}
		switch flag[0] {
		case 0:
		case 1:
			base := reader.key()
			next.bootstrapBase = &base
		default:
			return fmt.Errorf("%w: invalid bootstrap flag", ErrInvalidState)
		}
	}
	if reader.err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidState, reader.err)
	}
	if len(reader.raw) != 0 {
		return fmt.Errorf("%w: %d trailing bytes", ErrInvalidState, len(reader.raw))
	}

	*s = next
	return nil
}

// ParseState decodes a state from raw bytes.
func ParseState(raw []byte) (*State, error) {
	state := &State{}
	if err := state.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return state, nil
}

// Clear zeroes the state's key material.
func (s *State) Clear() {
	s.pendingPreKey = nil
	s.bootstrapBase = nil
	s.root = RootKey{}
	s.senderRatchet = KeyPair{}
	s.senderChain = ChainKey{}
	for _, chain := range s.receiverChains {
		chain.chain = ChainKey{}
		chain.index = 0
	}
	zero := MessageKeys{}
	for key := range s.skipped {
		s.skipped[key] = zero
		delete(s.skipped, key)
	}
}

type stateReader struct {
	raw []byte
	err error
}

func (r *stateReader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.raw) < n {
		r.err = ErrInvalidState
		return nil
	}
	out := r.raw[:n]
	r.raw = r.raw[n:]
	return out
}

func (r *stateReader) key() [KeySize]byte {
	var out [KeySize]byte
	copy(out[:], r.bytes(KeySize))
	return out
}

func (r *stateReader) uint16() uint16 {
	raw := r.bytes(2)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint16(raw)
}

func (r *stateReader) uint32() uint32 {
	raw := r.bytes(4)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint32(raw)
}
