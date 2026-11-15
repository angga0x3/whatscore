package sync

import (
	"crypto/hmac"
	"crypto/sha256"
	binenc "encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// EnvelopeMACSize is the length of a snapshot MAC and of a patch MAC: both
// are full HMAC-SHA256 tags, not truncations (PF-078).
const EnvelopeMACSize = 32

// ErrBadEnvelopeMAC means a snapshot or patch MAC did not verify, or the
// material supplied to build one was unusable.
var ErrBadEnvelopeMAC = errors.New("sync: bad envelope MAC")

// SnapshotMAC computes the MAC a snapshot (or a patch's snapshotMAC field)
// must carry (PF-078):
//
//	HMAC-SHA256(snapshotMACKey, hash ‖ uint64be(version) ‖ collectionName)
//
// hash is the 128-byte LTHash after the snapshot's records (or, for a patch
// check, after the patch's mutations) have been folded in, version is the
// resulting collection version and collection is the `<collection name=…>`
// attribute, e.g. "critical_block". The comparison itself is the caller's:
// use VerifySnapshotMAC to get a constant-time check.
func SnapshotMAC(keys Keys, hash Hash, version uint64, collection string) []byte {
	mac := hmac.New(sha256.New, keys.SnapshotMAC[:])
	mac.Write(hash[:])
	writeVersion(mac, version)
	mac.Write([]byte(collection))
	return mac.Sum(nil)
}

// PatchMAC computes the MAC a patch must carry (PF-078):
//
//	HMAC-SHA256(patchMACKey, snapshotMAC ‖ valueMAC₁…valueMACₙ ‖ uint64be(version) ‖ collectionName)
//
// snapshotMAC is the patch's own `snapshotMAC` field — the MAC of the state
// the patch produces, not the state it starts from — and valueMACs are the
// trailing 32-byte value MACs of the patch's mutations **in wire order**,
// REMOVE mutations included whenever they carry a payload. Use ValueMACs to
// collect them from a decoded patch. Duplicating, dropping or reordering an
// entry changes the MAC.
func PatchMAC(keys Keys, snapshotMAC []byte, valueMACs [][]byte, version uint64, collection string) []byte {
	mac := hmac.New(sha256.New, keys.PatchMAC[:])
	mac.Write(snapshotMAC)
	for _, valueMAC := range valueMACs {
		mac.Write(valueMAC)
	}
	writeVersion(mac, version)
	mac.Write([]byte(collection))
	return mac.Sum(nil)
}

// VerifySnapshotMAC recomputes SnapshotMAC and compares it in constant time
// with expected, the `mac` field of a `SyncdSnapshot` or the `snapshotMAC`
// field of a `SyncdPatch`.
func VerifySnapshotMAC(keys Keys, hash Hash, version uint64, collection string, expected []byte) error {
	if len(expected) != EnvelopeMACSize {
		return fmt.Errorf("%w: snapshot MAC of %d bytes, want %d",
			ErrBadEnvelopeMAC, len(expected), EnvelopeMACSize)
	}
	if !hmac.Equal(SnapshotMAC(keys, hash, version, collection), expected) {
		return fmt.Errorf("%w: snapshot MAC mismatch", ErrBadEnvelopeMAC)
	}
	return nil
}

// VerifyPatchMAC recomputes PatchMAC and compares it in constant time with
// expected, the `patchMAC` field of a `SyncdPatch`.
func VerifyPatchMAC(keys Keys, snapshotMAC []byte, valueMACs [][]byte, version uint64, collection string, expected []byte) error {
	if len(expected) != EnvelopeMACSize {
		return fmt.Errorf("%w: patch MAC of %d bytes, want %d",
			ErrBadEnvelopeMAC, len(expected), EnvelopeMACSize)
	}
	if !hmac.Equal(PatchMAC(keys, snapshotMAC, valueMACs, version, collection), expected) {
		return fmt.Errorf("%w: patch MAC mismatch", ErrBadEnvelopeMAC)
	}
	return nil
}

// ValueMACs returns the value MACs PatchMAC expects for a decoded patch, in
// wire order. A mutation whose record carried no value blob (a REMOVE without
// a payload) contributes nothing, matching both references: whatsmeow takes
// the trailing 32 bytes of every present blob and whatsapp-rust skips the
// mutation when the blob is absent.
func ValueMACs(mutations []PatchMutation) [][]byte {
	valueMACs := make([][]byte, 0, len(mutations))
	for i := range mutations {
		if mutations[i].ValueMAC == nil {
			continue
		}
		valueMACs = append(valueMACs, mutations[i].ValueMAC)
	}
	return valueMACs
}

// writeVersion writes the version as eight big-endian bytes. The references
// disagree above 2³²−1: whatsmeow writes a full uint64, while Baileys'
// to64BitNetworkOrder *and* WA Web write a uint32 into the low four bytes of an
// eight-byte buffer, so versions ≥2³² collide (whatsapp-rust reproduces the
// truncation deliberately while logging a warning). The protocol is not known
// to produce such a version; WhatsCore follows whatsmeow's full uint64 and the
// 2⁴⁰ vectors pin that choice instead of leaving it implicit.
func writeVersion(mac hash.Hash, version uint64) {
	var buf [8]byte
	binenc.BigEndian.PutUint64(buf[:], version)
	mac.Write(buf[:])
}
