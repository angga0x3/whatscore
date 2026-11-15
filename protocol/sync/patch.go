// Package sync decodes encrypted application-state patches.
//
// The multi-device protocol ships app state as `<sync>` stanzas: a
// `<collection name=...>` carries `<patch>` children whose byte content is a
// serialized `SyncdPatch` protobuf (docs/protocol/sync.md, PF-070..PF-074).
// ParsePatches turns that stanza into Patch values, and VerifyValueMAC
// authenticates one mutation record against an expanded app-state key.
//
// The package is key-free and network-free on purpose: key expansion
// (HKDF-SHA256 over "WhatsApp Mutation Keys"), AES-256-CBC decryption of the
// record payload, snapshot blob downloads and the LTHash bookkeeping stay with
// the caller. Parsing never verifies a MAC, so callers must run VerifyValueMAC
// before acting on a mutation.
package sync

import (
	"crypto/hmac"
	"crypto/sha512"
	binenc "encoding/binary"
	"errors"
	"fmt"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// Value framing constants (PF-072, PF-073).
const (
	// ValueMACSize is the truncated HMAC-SHA512 value MAC length.
	ValueMACSize = 32
	// ValueIVSize is the AES-256-CBC IV prefix of a value blob.
	ValueIVSize = 16
	// MinValueSize is the smallest value blob a reference decoder accepts:
	// IV plus value MAC. Ciphertext block alignment is a decryption-time
	// invariant and is not checked here.
	MinValueSize = ValueIVSize + ValueMACSize
	// ValueMACKeySize is the expanded value-MAC key length.
	ValueMACKeySize = 32
)

// Decode limits.
const (
	// MaxPatchBytes bounds one `<patch>` element's protobuf content.
	MaxPatchBytes = binary.MaxNodeBytes
	// MaxMutations bounds the mutations of a single patch.
	MaxMutations = 1 << 16
)

// Mutation operations (PF-071). The wire enum is SET=0, REMOVE=1.
const (
	OperationSet    = "SET"
	OperationRemove = "REMOVE"
)

// Stanza names of the app-state patch list (PF-070).
const (
	tagSync       = "sync"
	tagCollection = "collection"
	tagPatches    = "patches"
	tagPatch      = "patch"

	attrName = "name"
	attrType = "type"

	collectionTypeError = "error"
)

// SyncdPatch and SyncdMutation field numbers (PF-071).
const (
	fieldPatchVersion     = 1
	fieldPatchMutations   = 2
	fieldPatchExternal    = 3
	fieldPatchSnapshotMAC = 4
	fieldPatchMAC         = 5
	fieldPatchKeyID       = 6

	fieldMutationOperation = 1
	fieldMutationRecord    = 2

	fieldRecordIndex = 1
	fieldRecordValue = 2
	fieldRecordKeyID = 3

	// fieldBlob is the single byte field of SyncdIndex, SyncdValue, KeyId and
	// SyncdVersion (PF-071).
	fieldBlob = 1
)

// Protobuf wire types understood by the decoder.
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5

	maxFieldNumber = 1<<29 - 1
	maxVarintBytes = 10
)

var (
	// ErrInvalidPatch means the stanza or the patch protobuf is malformed.
	ErrInvalidPatch = errors.New("sync: invalid patch")
	// ErrBadMAC means a value MAC did not verify: wrong MAC, key, key id,
	// operation or value.
	ErrBadMAC = errors.New("sync: bad value MAC")
)

// Patch is one `SyncdPatch` (PF-071).
type Patch struct {
	// Collection is the `name` attribute of the enclosing `<collection>`.
	Collection string
	// Version is `SyncdPatch.version.version`, ascending across a patch list.
	Version uint64
	// SnapshotMAC and PatchMAC are the envelope MACs, carried verbatim and not
	// verified by this package (PF-074).
	SnapshotMAC []byte
	PatchMAC    []byte
	// KeyID is the patch-level key id; mutations may carry their own.
	KeyID []byte
	// Mutations holds the records in wire order.
	Mutations []PatchMutation
	// ExternalMutations reports that the mutation list lives in a separately
	// downloaded `SyncdMutations` blob; ParsePatches never downloads it and
	// the caller must fetch it before applying the patch.
	ExternalMutations bool
}

// PatchMutation is one `SyncdMutation` record (PF-071, PF-072).
type PatchMutation struct {
	// Operation is OperationSet or OperationRemove.
	Operation string
	// KeyID is the app-state key id the record was encrypted with.
	KeyID []byte
	// IndexMAC is `record.index.blob`: HMAC-SHA256 over the JSON index.
	IndexMAC []byte
	// Value is the authenticated payload `iv ‖ ciphertext` with the trailing
	// value MAC stripped. A REMOVE may carry no payload at all.
	Value []byte
	// ValueMAC is the trailing ValueMACSize bytes of `record.value.blob`, nil
	// when the mutation carries no payload.
	ValueMAC []byte
}

// ParsePatches decodes an app-state patch list. It accepts a `<sync>` node
// (every `<collection>` child is parsed) or a single `<collection>` node.
// Patch contents, mutation order and versions are preserved as received; a
// patch that names external mutations is reported through
// Patch.ExternalMutations rather than followed.
//
// Returned byte slices are copies and stay valid after the wire buffer is
// reused. Errors wrap ErrInvalidPatch.
func ParsePatches(node *binary.Node) ([]Patch, error) {
	if node == nil {
		return nil, fmt.Errorf("%w: nil node", ErrInvalidPatch)
	}
	switch node.Tag {
	case tagSync:
		patches := make([]Patch, 0, len(node.Children))
		collections := 0
		for i := range node.Children {
			if node.Children[i].Tag != tagCollection {
				continue
			}
			collections++
			parsed, err := parseCollection(&node.Children[i])
			if err != nil {
				return nil, err
			}
			patches = append(patches, parsed...)
		}
		if collections == 0 {
			return nil, fmt.Errorf("%w: sync node without collection", ErrInvalidPatch)
		}
		return patches, nil
	case tagCollection:
		return parseCollection(node)
	default:
		return nil, fmt.Errorf("%w: unexpected node %q, want %q or %q", ErrInvalidPatch, node.Tag, tagSync, tagCollection)
	}
}

// parseCollection decodes one `<collection>`. The patches sit either in a
// `<patches>` child or directly under the collection (PF-070).
func parseCollection(collection *binary.Node) ([]Patch, error) {
	name := collection.Attrs[attrName]
	if name == "" {
		return nil, fmt.Errorf("%w: collection without a %q attribute", ErrInvalidPatch, attrName)
	}
	if collection.Attrs[attrType] == collectionTypeError {
		return nil, fmt.Errorf("%w: collection %q reported a server error", ErrInvalidPatch, name)
	}

	container := collection
	for i := range collection.Children {
		if collection.Children[i].Tag == tagPatches {
			container = &collection.Children[i]
			break
		}
	}

	patches := make([]Patch, 0, len(container.Children))
	for i := range container.Children {
		child := &container.Children[i]
		if child.Tag != tagPatch {
			continue // a <snapshot> reference or an unrelated sibling
		}
		if child.Bytes == nil {
			continue // no content: not a patch we can decode
		}
		patch, err := parseSyncdPatch(child.Bytes)
		if err != nil {
			return nil, fmt.Errorf("sync: patch %d of collection %q: %w", len(patches)+1, name, err)
		}
		patch.Collection = name
		patches = append(patches, patch)
	}
	return patches, nil
}

// parseSyncdPatch decodes the SyncdPatch protobuf (PF-071).
func parseSyncdPatch(data []byte) (Patch, error) {
	if len(data) == 0 {
		return Patch{}, fmt.Errorf("%w: empty patch content", ErrInvalidPatch)
	}
	if len(data) > MaxPatchBytes {
		return Patch{}, fmt.Errorf("%w: patch of %d bytes exceeds %d", ErrInvalidPatch, len(data), MaxPatchBytes)
	}

	var patch Patch
	r := &pbReader{buf: data}
	for !r.done() {
		field, typ, err := r.readTag()
		if err != nil {
			return Patch{}, err
		}
		switch field {
		case fieldPatchVersion:
			raw, err := r.readMessage(field, typ)
			if err != nil {
				return Patch{}, err
			}
			if patch.Version, err = parseSyncdVersion(raw); err != nil {
				return Patch{}, err
			}
		case fieldPatchMutations:
			raw, err := r.readMessage(field, typ)
			if err != nil {
				return Patch{}, err
			}
			mutation, err := parseSyncdMutation(raw)
			if err != nil {
				return Patch{}, err
			}
			if len(patch.Mutations) >= MaxMutations {
				return Patch{}, fmt.Errorf("%w: patch with more than %d mutations", ErrInvalidPatch, MaxMutations)
			}
			patch.Mutations = append(patch.Mutations, mutation)
		case fieldPatchExternal:
			if _, err := r.readMessage(field, typ); err != nil {
				return Patch{}, err
			}
			// Field presence alone means the mutation list is external, even
			// when the reference message carries no fields.
			patch.ExternalMutations = true
		case fieldPatchSnapshotMAC:
			raw, err := r.readMessage(field, typ)
			if err != nil {
				return Patch{}, err
			}
			patch.SnapshotMAC = clone(raw)
		case fieldPatchMAC:
			raw, err := r.readMessage(field, typ)
			if err != nil {
				return Patch{}, err
			}
			patch.PatchMAC = clone(raw)
		case fieldPatchKeyID:
			raw, err := r.readMessage(field, typ)
			if err != nil {
				return Patch{}, err
			}
			if patch.KeyID, err = parseBytesField1(raw); err != nil {
				return Patch{}, err
			}
		default:
			// exitCode, deviceIndex, clientDebugData and future fields.
			if err := r.skip(typ); err != nil {
				return Patch{}, err
			}
		}
	}
	return patch, nil
}

// parseSyncdMutation decodes one SyncdMutation (PF-071, PF-072).
func parseSyncdMutation(data []byte) (PatchMutation, error) {
	// An absent operation defaults to SET: the proto2 enum default is 0.
	mutation := PatchMutation{Operation: OperationSet}
	var record []byte
	haveRecord := false

	r := &pbReader{buf: data}
	for !r.done() {
		field, typ, err := r.readTag()
		if err != nil {
			return PatchMutation{}, err
		}
		switch field {
		case fieldMutationOperation:
			if typ != wireVarint {
				return PatchMutation{}, wrongWireType(field, typ)
			}
			raw, err := r.readVarint()
			if err != nil {
				return PatchMutation{}, err
			}
			if mutation.Operation, err = operationName(raw); err != nil {
				return PatchMutation{}, err
			}
		case fieldMutationRecord:
			if typ != wireBytes {
				return PatchMutation{}, wrongWireType(field, typ)
			}
			if record, err = r.readBytes(); err != nil {
				return PatchMutation{}, err
			}
			haveRecord = true
		default:
			if err := r.skip(typ); err != nil {
				return PatchMutation{}, err
			}
		}
	}
	if !haveRecord {
		return PatchMutation{}, fmt.Errorf("%w: mutation without a record", ErrInvalidPatch)
	}

	index, value, keyID, err := parseSyncdRecord(record)
	if err != nil {
		return PatchMutation{}, err
	}
	if len(index) == 0 {
		return PatchMutation{}, fmt.Errorf("%w: record without an index MAC", ErrInvalidPatch)
	}
	if len(keyID) == 0 {
		return PatchMutation{}, fmt.Errorf("%w: record without a key id", ErrInvalidPatch)
	}

	mutation.IndexMAC = index
	mutation.KeyID = keyID
	switch mutation.Operation {
	case OperationSet:
		if len(value) < MinValueSize {
			return PatchMutation{}, fmt.Errorf("%w: SET value of %d bytes, want at least %d",
				ErrInvalidPatch, len(value), MinValueSize)
		}
	case OperationRemove:
		// A REMOVE is identified by its index MAC, so an absent payload is
		// tolerated; a non-empty payload must have the normal framing.
		if len(value) > 0 && len(value) < MinValueSize {
			return PatchMutation{}, fmt.Errorf("%w: REMOVE value of %d bytes, want 0 or at least %d",
				ErrInvalidPatch, len(value), MinValueSize)
		}
	}
	if len(value) > 0 {
		mutation.Value = clone(value[:len(value)-ValueMACSize])
		mutation.ValueMAC = clone(value[len(value)-ValueMACSize:])
	}
	return mutation, nil
}

// parseSyncdRecord splits a SyncdRecord into index MAC, value blob and key id.
func parseSyncdRecord(data []byte) (index, value, keyID []byte, err error) {
	r := &pbReader{buf: data}
	for !r.done() {
		field, typ, err := r.readTag()
		if err != nil {
			return nil, nil, nil, err
		}
		switch field {
		case fieldRecordIndex, fieldRecordValue, fieldRecordKeyID:
			raw, err := r.readMessage(field, typ)
			if err != nil {
				return nil, nil, nil, err
			}
			switch field {
			case fieldRecordIndex:
				index, err = parseBytesField1(raw)
			case fieldRecordValue:
				value, err = parseBytesField1(raw)
			default:
				keyID, err = parseBytesField1(raw)
			}
			if err != nil {
				return nil, nil, nil, err
			}
		default:
			if err := r.skip(typ); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	return index, value, keyID, nil
}

// parseSyncdVersion reads `SyncdVersion{version=1}` (PF-071).
func parseSyncdVersion(data []byte) (uint64, error) {
	var version uint64
	r := &pbReader{buf: data}
	for !r.done() {
		field, typ, err := r.readTag()
		if err != nil {
			return 0, err
		}
		if field != fieldBlob {
			if err := r.skip(typ); err != nil {
				return 0, err
			}
			continue
		}
		if typ != wireVarint {
			return 0, wrongWireType(field, typ)
		}
		if version, err = r.readVarint(); err != nil {
			return 0, err
		}
	}
	return version, nil
}

// parseBytesField1 reads the single byte field 1 of a wrapper message
// (SyncdIndex, SyncdValue, KeyId); a later occurrence replaces an earlier one.
func parseBytesField1(data []byte) ([]byte, error) {
	var value []byte
	r := &pbReader{buf: data}
	for !r.done() {
		field, typ, err := r.readTag()
		if err != nil {
			return nil, err
		}
		if field != fieldBlob {
			if err := r.skip(typ); err != nil {
				return nil, err
			}
			continue
		}
		if typ != wireBytes {
			return nil, wrongWireType(field, typ)
		}
		raw, err := r.readBytes()
		if err != nil {
			return nil, err
		}
		value = clone(raw)
	}
	return value, nil
}

// VerifyValueMAC checks one mutation's value MAC (PF-073):
//
//	HMAC-SHA512(key, opByte ‖ keyID ‖ value ‖ uint64be(len(keyID)+1))[:32]
//
// with opByte 0x01 for SET and 0x02 for REMOVE. mac, key and keyID carry raw
// bytes, not hex or base64. The comparison is constant time.
//
// It returns ErrBadMAC when the MAC, the key length or the key id is unusable
// or the MAC does not match, and ErrInvalidPatch for an unknown operation.
func VerifyValueMAC(mac, key, operation, keyID string, value []byte) error {
	if len(mac) != ValueMACSize {
		return fmt.Errorf("%w: MAC of %d bytes, want %d", ErrBadMAC, len(mac), ValueMACSize)
	}
	if len(key) != ValueMACKeySize {
		return fmt.Errorf("%w: key of %d bytes, want %d", ErrBadMAC, len(key), ValueMACKeySize)
	}
	if keyID == "" {
		return fmt.Errorf("%w: empty key id", ErrBadMAC)
	}
	op, err := operationByte(operation)
	if err != nil {
		return err
	}
	if !hmac.Equal(valueMAC([]byte(key), op, []byte(keyID), value), []byte(mac)) {
		return fmt.Errorf("%w: value MAC mismatch", ErrBadMAC)
	}
	return nil
}

// valueMAC computes the full (already truncated) value MAC.
func valueMAC(key []byte, op byte, keyID, value []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write([]byte{op})
	mac.Write(keyID)
	mac.Write(value)
	var length [8]byte
	binenc.BigEndian.PutUint64(length[:], uint64(len(keyID)+1))
	mac.Write(length[:])
	return mac.Sum(nil)[:ValueMACSize]
}

// operationName maps the wire enum to its operation constant.
func operationName(value uint64) (string, error) {
	switch value {
	case 0:
		return OperationSet, nil
	case 1:
		return OperationRemove, nil
	default:
		return "", fmt.Errorf("%w: unknown operation %d", ErrInvalidPatch, value)
	}
}

// operationByte maps an operation constant to the MAC prefix.
func operationByte(operation string) (byte, error) {
	switch operation {
	case OperationSet:
		return 0x01, nil
	case OperationRemove:
		return 0x02, nil
	default:
		return 0, fmt.Errorf("%w: unknown operation %q", ErrInvalidPatch, operation)
	}
}

func wrongWireType(field, typ int) error {
	return fmt.Errorf("%w: field %d has wire type %d", ErrInvalidPatch, field, typ)
}

func clone(b []byte) []byte {
	return append([]byte(nil), b...)
}

// pbReader is a strict protobuf wire reader for the decoded subset. Groups
// (wire types 3 and 4) and the reserved types 6 and 7 are rejected: WhatsApp
// emits none of them and skipping a group needs nesting bookkeeping that a
// strict decoder should not need.
type pbReader struct {
	buf []byte
}

func (r *pbReader) done() bool {
	return len(r.buf) == 0
}

func (r *pbReader) readVarint() (uint64, error) {
	var value uint64
	for i := 0; i < maxVarintBytes; i++ {
		if len(r.buf) == 0 {
			return 0, fmt.Errorf("%w: truncated varint", ErrInvalidPatch)
		}
		b := r.buf[0]
		r.buf = r.buf[1:]
		if i == maxVarintBytes-1 && b > 1 {
			return 0, fmt.Errorf("%w: varint overflows 64 bits", ErrInvalidPatch)
		}
		value |= uint64(b&0x7f) << (7 * uint(i))
		if b < 0x80 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("%w: varint overflows 64 bits", ErrInvalidPatch)
}

func (r *pbReader) readTag() (field, typ int, err error) {
	key, err := r.readVarint()
	if err != nil {
		return 0, 0, err
	}
	field = int(key >> 3)
	typ = int(key & 7)
	if field < 1 || field > maxFieldNumber {
		return 0, 0, fmt.Errorf("%w: field number %d", ErrInvalidPatch, field)
	}
	return field, typ, nil
}

func (r *pbReader) readBytes() ([]byte, error) {
	length, err := r.readVarint()
	if err != nil {
		return nil, err
	}
	if length > uint64(len(r.buf)) {
		return nil, fmt.Errorf("%w: length %d exceeds %d remaining bytes", ErrInvalidPatch, length, len(r.buf))
	}
	out := r.buf[:length]
	r.buf = r.buf[length:]
	return out, nil
}

// readMessage reads a length-delimited field that must carry typ.
func (r *pbReader) readMessage(field, typ int) ([]byte, error) {
	if typ != wireBytes {
		return nil, wrongWireType(field, typ)
	}
	return r.readBytes()
}

func (r *pbReader) skip(typ int) error {
	switch typ {
	case wireVarint:
		_, err := r.readVarint()
		return err
	case wireFixed64:
		return r.skipN(8)
	case wireBytes:
		_, err := r.readBytes()
		return err
	case wireFixed32:
		return r.skipN(4)
	default:
		return fmt.Errorf("%w: unsupported wire type %d", ErrInvalidPatch, typ)
	}
}

func (r *pbReader) skipN(n int) error {
	if len(r.buf) < n {
		return fmt.Errorf("%w: truncated %d-byte field", ErrInvalidPatch, n)
	}
	r.buf = r.buf[n:]
	return nil
}
