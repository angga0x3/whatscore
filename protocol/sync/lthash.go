package sync

import (
	"crypto/hkdf"
	"crypto/sha256"
	binenc "encoding/binary"
	"errors"
	"fmt"
)

// LTHash constants (PF-077).
const (
	// LTHashSize is the size of the additive patch-integrity accumulator.
	LTHashSize = 128
	// LTHashInfo is the HKDF info string of the per-value-MAC expansion.
	LTHashInfo = "WhatsApp Patch Integrity"
)

// ErrInvalidLTHash is returned when an accumulator update cannot be applied.
var ErrInvalidLTHash = errors.New("sync: invalid LTHash state")

// Hash is the 128-byte additive app-state integrity accumulator (PF-077).
//
// The zero value is the empty state, which is what a collection starts at
// before its snapshot or first patch. It is a sum of per-value-MAC elements
// over GF(2^16)^64: each element is derived with HKDF-SHA256 and folded in as
// 64 independent 16-bit little-endian lanes, so every mutation is reversible
// and the order of additions does not matter. Snapshot and patch MACs sign the
// serialized 128 bytes (PF-078), which is why the lane endianness is part of
// the wire contract rather than an implementation choice.
type Hash [LTHashSize]byte

// SubtractThenAdd folds remove then add into h (PF-077). remove carries the
// previous value MAC of each index a mutation overwrites or deletes; add
// carries the value MAC of each SET. A REMOVE whose index has no known
// previous value contributes to neither list, which is how the references
// treat it.
//
// Every element must be a ValueMACSize value MAC: the trailing 32 bytes of a
// record's value blob, or the stored MAC of a previous SET. The subtraction
// runs first and both directions wrap modulo 2^16 per lane, so subtracting an
// element exactly undoes adding it.
func (h *Hash) SubtractThenAdd(remove, add [][]byte) error {
	if h == nil {
		return fmt.Errorf("%w: nil accumulator", ErrInvalidLTHash)
	}
	// Subtract first: an element present in both lists must end up added.
	for _, mac := range remove {
		if err := h.fold(mac, true); err != nil {
			return err
		}
	}
	for _, mac := range add {
		if err := h.fold(mac, false); err != nil {
			return err
		}
	}
	return nil
}

// fold adds or subtracts one expanded element.
func (h *Hash) fold(mac []byte, subtract bool) error {
	element, err := expandElement(mac)
	if err != nil {
		return err
	}
	for i := 0; i < LTHashSize; i += 2 {
		x := binenc.LittleEndian.Uint16(h[i : i+2])
		y := binenc.LittleEndian.Uint16(element[i : i+2])
		var sum uint16
		if subtract {
			sum = x - y
		} else {
			sum = x + y
		}
		binenc.LittleEndian.PutUint16(h[i:i+2], sum)
	}
	return nil
}

// expandElement derives one accumulator element from a value MAC:
//
//	HKDF-SHA256(ikm=mac, salt=nil, info="WhatsApp Patch Integrity", L=128)
//
// i.e. RFC 5869 extract with a zero-filled salt followed by four expand rounds
// of 32 bytes each (T1 ‖ T2 ‖ T3 ‖ T4). The result is returned by value so the
// per-element fold touches no heap beyond the HKDF output itself.
func expandElement(mac []byte) ([LTHashSize]byte, error) {
	var element [LTHashSize]byte
	if len(mac) != ValueMACSize {
		return element, fmt.Errorf("%w: element of %d bytes, want %d",
			ErrInvalidLTHash, len(mac), ValueMACSize)
	}
	okm, err := hkdf.Key(sha256.New, mac, nil, LTHashInfo, LTHashSize)
	if err != nil {
		return element, fmt.Errorf("%w: hkdf: %w", ErrInvalidLTHash, err)
	}
	copy(element[:], okm)
	return element, nil
}
