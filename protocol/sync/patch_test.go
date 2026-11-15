package sync

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// Synthetic material only. The value MAC vectors were produced by an
// independent Python implementation (hmac/hashlib, SHA-512 truncated to 32
// bytes) from the PF-073 description; no real account, key or payload is
// involved.
const (
	// testMACKey is bytes 0x00..0x1f.
	testMACKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	// testKeyID is bytes 0x01..0x06.
	testKeyIDHex = "010203040506"
	// testValue is iv (0x10..0x1f) followed by 48 ciphertext bytes (0x20..0x4f).
	testValueHex = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
		"303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"

	// MAC over op=SET, the full testValue.
	testSetMACHex = "108c51790dc5e6ac03af14b4c6a36ff1c6b698501711a38b7c229437a09cc0de"
	// MAC over op=REMOVE with an empty value.
	testRemoveMACHex = "6bbe8b445615b533f82a1a7bec3736c845baf1de0278aa130a7852570787c97a"
	// MAC over op=REMOVE with the full testValue.
	testRemoveValueMACHex = "91b2fb9f52c14abadc9c3c5686893fcbefc91bb1511915c498d4baaa9445fabb"
)

func mustHex(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("vector %s: invalid hex: %v", name, err)
	}
	return b
}

// hexBytes decodes a constant vector in a builder that has no *testing.T.
func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid constant vector: " + err.Error())
	}
	return b
}

// --- synthetic protobuf writer (tests only) -------------------------------

func pbVarint(n uint64) []byte {
	var out []byte
	for n >= 0x80 {
		out = append(out, byte(n)|0x80)
		n >>= 7
	}
	return append(out, byte(n))
}

func pbTag(field, typ int) []byte {
	return pbVarint(uint64(field)<<3 | uint64(typ))
}

func pbUint(field int, value uint64) []byte {
	return append(pbTag(field, 0), pbVarint(value)...)
}

func pbBytes(field int, value []byte) []byte {
	out := pbTag(field, 2)
	out = append(out, pbVarint(uint64(len(value)))...)
	return append(out, value...)
}

func pbConcat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// blob wraps bytes in the single-field wrapper messages (SyncdIndex,
// SyncdValue, KeyId).
func blob(value []byte) []byte {
	return pbBytes(fieldBlob, value)
}

// mutation encodes one SyncdMutation with the given operation value.
func mutation(operation uint64, indexMAC, valueBlob, keyID []byte) []byte {
	record := pbConcat(
		pbBytes(fieldRecordIndex, blob(indexMAC)),
		pbBytes(fieldRecordValue, blob(valueBlob)),
		pbBytes(fieldRecordKeyID, blob(keyID)),
	)
	return pbConcat(pbUint(fieldMutationOperation, operation), pbBytes(fieldMutationRecord, record))
}

// setRecord encodes a SET mutation whose value blob is iv ‖ ciphertext ‖ MAC.
func setRecord(indexMAC, value, keyID []byte) []byte {
	valueBlob := pbConcat(value, valueMACForTest(OperationSet, keyID, value))
	return mutation(0, indexMAC, valueBlob, keyID)
}

// removeRecord encodes a REMOVE mutation; value may be nil.
func removeRecord(indexMAC, value, keyID []byte) []byte {
	valueBlob := value
	if len(value) > 0 {
		valueBlob = pbConcat(value, valueMACForTest(OperationRemove, keyID, value))
	}
	return mutation(1, indexMAC, valueBlob, keyID)
}

// valueMACForTest wraps the package helper for the synthetic builders.
func valueMACForTest(operation string, keyID, value []byte) []byte {
	op, err := operationByte(operation)
	if err != nil {
		panic("invalid test operation: " + err.Error())
	}
	return valueMAC(hexBytes(testMACKeyHex), op, keyID, value)
}

// syncdPatch encodes a SyncdPatch with the given version and mutations.
func syncdPatch(version uint64, mutations [][]byte) []byte {
	parts := [][]byte{
		pbBytes(fieldPatchVersion, pbUint(fieldBlob, version)),
		pbBytes(fieldPatchSnapshotMAC, bytes.Repeat([]byte{0xAA}, 32)),
		pbBytes(fieldPatchMAC, bytes.Repeat([]byte{0xBB}, 32)),
		pbBytes(fieldPatchKeyID, blob(hexBytes(testKeyIDHex))),
	}
	for _, m := range mutations {
		parts = append(parts, pbBytes(fieldPatchMutations, m))
	}
	return pbConcat(parts...)
}

// patchNode builds the stanza shape around already-encoded patch protobufs.
func patchNode(collection string, patches ...[]byte) *binary.Node {
	children := make([]binary.Node, 0, len(patches))
	for _, raw := range patches {
		children = append(children, binary.Node{Tag: "patch", Bytes: raw})
	}
	return &binary.Node{
		Tag:   "sync",
		Attrs: binary.Attrs{"xmlns": "w:sync:app:state"},
		Children: []binary.Node{{
			Tag:      "collection",
			Attrs:    binary.Attrs{"name": collection, "return_snapshot": "false"},
			Children: []binary.Node{{Tag: "patches", Children: children}},
		}},
	}
}

// roundTrip encodes node, decodes it again and parses the patches, so every
// test exercises the real codec instead of a hand-built Node.
func roundTrip(t *testing.T, node *binary.Node) []Patch {
	t.Helper()
	codec := binary.NewCodec(nil)
	frame, err := codec.Encode(node)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := codec.Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	patches, err := ParsePatches(decoded)
	if err != nil {
		t.Fatalf("ParsePatches: %v", err)
	}
	return patches
}

// --- parsing --------------------------------------------------------------

func TestRoundTripPatchList(t *testing.T) {
	keyID := mustHex(t, "key id", testKeyIDHex)
	value := mustHex(t, "value", testValueHex)
	indexMAC := bytes.Repeat([]byte{0x11}, 32)

	node := patchNode("regular_low",
		syncdPatch(7, [][]byte{setRecord(indexMAC, value, keyID)}),
		syncdPatch(8, [][]byte{
			setRecord(indexMAC, value, keyID),
			removeRecord(bytes.Repeat([]byte{0x22}, 32), nil, keyID),
		}),
	)
	patches := roundTrip(t, node)
	if len(patches) != 2 {
		t.Fatalf("got %d patches, want 2", len(patches))
	}

	first := patches[0]
	if first.Collection != "regular_low" || first.Version != 7 {
		t.Fatalf("first patch = %q v%d, want regular_low v7", first.Collection, first.Version)
	}
	if !bytes.Equal(first.KeyID, keyID) {
		t.Fatalf("patch key id = %x, want %x", first.KeyID, keyID)
	}
	if !bytes.Equal(first.SnapshotMAC, bytes.Repeat([]byte{0xAA}, 32)) ||
		!bytes.Equal(first.PatchMAC, bytes.Repeat([]byte{0xBB}, 32)) {
		t.Fatal("patch MACs were not carried verbatim")
	}
	if len(first.Mutations) != 1 {
		t.Fatalf("first patch has %d mutations, want 1", len(first.Mutations))
	}

	set := first.Mutations[0]
	if set.Operation != OperationSet {
		t.Fatalf("operation = %q, want %q", set.Operation, OperationSet)
	}
	if !bytes.Equal(set.IndexMAC, indexMAC) {
		t.Fatalf("index MAC = %x, want %x", set.IndexMAC, indexMAC)
	}
	if !bytes.Equal(set.Value, value) {
		t.Fatalf("value = %x, want %x", set.Value, value)
	}
	if !bytes.Equal(set.ValueMAC, mustHex(t, "set MAC", testSetMACHex)) {
		t.Fatalf("value MAC = %x, want %s", set.ValueMAC, testSetMACHex)
	}
	if !bytes.Equal(set.KeyID, keyID) {
		t.Fatalf("mutation key id = %x, want %x", set.KeyID, keyID)
	}

	second := patches[1]
	if second.Version != 8 || len(second.Mutations) != 2 {
		t.Fatalf("second patch = v%d with %d mutations, want v8 with 2", second.Version, len(second.Mutations))
	}

	remove := second.Mutations[1]
	if remove.Operation != OperationRemove {
		t.Fatalf("operation = %q, want %q", remove.Operation, OperationRemove)
	}
	if remove.Value != nil || remove.ValueMAC != nil {
		t.Fatalf("removal carried a payload: value=%x mac=%x", remove.Value, remove.ValueMAC)
	}
	if !bytes.Equal(remove.IndexMAC, bytes.Repeat([]byte{0x22}, 32)) {
		t.Fatalf("removal index MAC = %x", remove.IndexMAC)
	}
}

func TestParsePatchesPreservesOrder(t *testing.T) {
	keyID := mustHex(t, "key id", testKeyIDHex)
	value := mustHex(t, "value", testValueHex)

	var raw [][]byte
	for version := uint64(1); version <= 5; version++ {
		raw = append(raw, syncdPatch(version, [][]byte{
			setRecord(bytes.Repeat([]byte{byte(version)}, 32), value, keyID),
			setRecord(bytes.Repeat([]byte{byte(version + 0x80)}, 32), value, keyID),
		}))
	}

	patches := roundTrip(t, patchNode("critical_block", raw...))
	if len(patches) != len(raw) {
		t.Fatalf("got %d patches, want %d", len(patches), len(raw))
	}
	for i, patch := range patches {
		if patch.Version != uint64(i+1) {
			t.Fatalf("patch %d has version %d, want %d", i, patch.Version, i+1)
		}
		if len(patch.Mutations) != 2 {
			t.Fatalf("patch %d has %d mutations, want 2", i, len(patch.Mutations))
		}
		if patch.Mutations[0].IndexMAC[0] != byte(i+1) {
			t.Fatalf("patch %d mutation order changed: first index MAC starts %#x", i, patch.Mutations[0].IndexMAC[0])
		}
	}
}

func TestParsePatchesDeterministic(t *testing.T) {
	keyID := mustHex(t, "key id", testKeyIDHex)
	node := patchNode("regular", syncdPatch(3, [][]byte{
		setRecord(bytes.Repeat([]byte{0x33}, 32), mustHex(t, "value", testValueHex), keyID),
	}))

	first := roundTrip(t, node)
	second := roundTrip(t, node)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("decode is not deterministic:\n first=%#v\nsecond=%#v", first, second)
	}
}

func TestParsePatchesCollectionVariants(t *testing.T) {
	keyID := mustHex(t, "key id", testKeyIDHex)
	raw := syncdPatch(4, [][]byte{setRecord(bytes.Repeat([]byte{0x44}, 32), mustHex(t, "value", testValueHex), keyID)})

	t.Run("patches without wrapper", func(t *testing.T) {
		// Some responses put <patch> straight under <collection>.
		node := &binary.Node{
			Tag: "collection",
			Attrs: binary.Attrs{
				"name": "regular_high",
			},
			Children: []binary.Node{{Tag: "patch", Bytes: raw}},
		}
		patches := roundTrip(t, node)
		if len(patches) != 1 || patches[0].Collection != "regular_high" {
			t.Fatalf("got %#v", patches)
		}
	})

	t.Run("snapshot sibling and empty patch", func(t *testing.T) {
		node := &binary.Node{
			Tag:   "sync",
			Attrs: binary.Attrs{},
			Children: []binary.Node{{
				Tag:   "collection",
				Attrs: binary.Attrs{"name": "critical_unblock_low", "has_more_patches": "true"},
				Children: []binary.Node{
					{Tag: "snapshot", Bytes: []byte{0x0a, 0x00}},
					{Tag: "patches", Children: []binary.Node{
						{Tag: "patch", Bytes: raw},
						{Tag: "patch"}, // no content: skipped, not an error
					}},
				},
			}},
		}
		patches := roundTrip(t, node)
		if len(patches) != 1 {
			t.Fatalf("got %d patches, want 1", len(patches))
		}
	})

	t.Run("external mutations", func(t *testing.T) {
		external := pbConcat(
			pbBytes(fieldPatchVersion, pbUint(fieldBlob, 9)),
			pbBytes(fieldPatchExternal, pbBytes(1, []byte("media-key"))),
		)
		patches := roundTrip(t, patchNode("regular_low", external))
		if len(patches) != 1 {
			t.Fatalf("got %d patches, want 1", len(patches))
		}
		if !patches[0].ExternalMutations {
			t.Fatal("external mutation reference not reported")
		}
		if patches[0].Version != 9 {
			t.Fatalf("version = %d, want 9", patches[0].Version)
		}
		if len(patches[0].Mutations) != 0 {
			t.Fatalf("external patch carried %d inline mutations", len(patches[0].Mutations))
		}
	})
}

func TestParsePatchesUnknownFieldsIgnored(t *testing.T) {
	keyID := mustHex(t, "key id", testKeyIDHex)
	value := mustHex(t, "value", testValueHex)
	// deviceIndex (8, varint), clientDebugData (9, bytes) and an unknown
	// field 15 with each skippable wire type.
	raw := pbConcat(
		pbBytes(fieldPatchVersion, pbUint(fieldBlob, 2)),
		pbBytes(fieldPatchMutations, setRecord(bytes.Repeat([]byte{0x55}, 32), value, keyID)),
		pbUint(8, 3),
		pbBytes(9, []byte("debug")),
		pbUint(15, 1),
		pbTag(15, wireFixed64),
		bytes.Repeat([]byte{0xFF}, 8),
		pbTag(15, wireFixed32),
		bytes.Repeat([]byte{0xFF}, 4),
	)
	patches := roundTrip(t, patchNode("regular_low", raw))
	if len(patches) != 1 || len(patches[0].Mutations) != 1 {
		t.Fatalf("got %#v", patches)
	}
}

// --- value MAC ------------------------------------------------------------

func TestVerifyValueMAC(t *testing.T) {
	key := mustHex(t, "mac key", testMACKeyHex)
	keyID := mustHex(t, "key id", testKeyIDHex)
	value := mustHex(t, "value", testValueHex)

	cases := []struct {
		name      string
		mac       string
		operation string
		keyID     string
		value     []byte
		want      error
	}{
		{"set vector", testSetMACHex, OperationSet, testKeyIDHex, value, nil},
		{"remove vector empty value", testRemoveMACHex, OperationRemove, testKeyIDHex, nil, nil},
		{"remove vector with value", testRemoveValueMACHex, OperationRemove, testKeyIDHex, value, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyValueMAC(string(mustHex(t, "mac", tc.mac)), string(key), tc.operation, string(keyID), tc.value)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestVerifyValueMACRejects(t *testing.T) {
	mac := mustHex(t, "mac", testSetMACHex)
	key := mustHex(t, "mac key", testMACKeyHex)
	keyID := mustHex(t, "key id", testKeyIDHex)
	value := mustHex(t, "value", testValueHex)

	tampered := append([]byte(nil), value...)
	tampered[len(tampered)-1] ^= 0x01
	tamperedMAC := append([]byte(nil), mac...)
	tamperedMAC[0] ^= 0x01
	otherKey := append([]byte(nil), key...)
	otherKey[0] ^= 0x01

	cases := []struct {
		name      string
		mac       string
		key       string
		operation string
		keyID     string
		value     []byte
		want      error
	}{
		{"tampered value", string(mac), string(key), OperationSet, string(keyID), tampered, ErrBadMAC},
		{"tampered mac", string(tamperedMAC), string(key), OperationSet, string(keyID), value, ErrBadMAC},
		{"wrong key", string(mac), string(otherKey), OperationSet, string(keyID), value, ErrBadMAC},
		{"wrong key id", string(mac), string(key), OperationSet, string([]byte{0x09, 0x09}), value, ErrBadMAC},
		{"wrong operation", string(mac), string(key), OperationRemove, string(keyID), value, ErrBadMAC},
		{"empty value", string(mac), string(key), OperationSet, string(keyID), nil, ErrBadMAC},
		{"short mac", string(mac[:16]), string(key), OperationSet, string(keyID), value, ErrBadMAC},
		{"long mac", string(append(append([]byte(nil), mac...), 0x00)), string(key), OperationSet, string(keyID), value, ErrBadMAC},
		{"short key", string(mac), string(key[:16]), OperationSet, string(keyID), value, ErrBadMAC},
		{"empty key id", string(mac), string(key), OperationSet, "", value, ErrBadMAC},
		{"unknown operation", string(mac), string(key), "DELETE", string(keyID), value, ErrInvalidPatch},
		{"empty operation", string(mac), string(key), "", string(keyID), value, ErrInvalidPatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyValueMAC(tc.mac, tc.key, tc.operation, tc.keyID, tc.value)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// TestVerifyValueMACMatchesParsedRecord proves the parsed Value/ValueMAC pair
// verifies with the record's own key id and operation, which is the only
// supported decode path.
func TestVerifyValueMACMatchesParsedRecord(t *testing.T) {
	key := mustHex(t, "mac key", testMACKeyHex)
	keyID := mustHex(t, "key id", testKeyIDHex)
	value := mustHex(t, "value", testValueHex)
	node := patchNode("regular_low", syncdPatch(1, [][]byte{
		setRecord(bytes.Repeat([]byte{0x66}, 32), value, keyID),
		removeRecord(bytes.Repeat([]byte{0x67}, 32), value, keyID),
	}))

	patches := roundTrip(t, node)
	mutations := patches[0].Mutations
	for _, mutation := range mutations {
		if err := VerifyValueMAC(string(mutation.ValueMAC), string(key), mutation.Operation, string(mutation.KeyID), mutation.Value); err != nil {
			t.Fatalf("%s record failed verification: %v", mutation.Operation, err)
		}
	}

	// A SET record verified as a REMOVE must fail: the operation is in the MAC.
	if err := VerifyValueMAC(string(mutations[0].ValueMAC), string(key), OperationRemove, string(mutations[0].KeyID), mutations[0].Value); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("SET record verified as REMOVE: %v", err)
	}
}

// --- malformed input ------------------------------------------------------

func TestParsePatchesErrors(t *testing.T) {
	keyID := mustHex(t, "key id", testKeyIDHex)
	value := mustHex(t, "value", testValueHex)

	cases := []struct {
		name string
		node *binary.Node
	}{
		{"nil node", nil},
		{"wrong tag", &binary.Node{Tag: "iq"}},
		{"sync without collection", &binary.Node{Tag: "sync"}},
		{"sync with unrelated child", &binary.Node{Tag: "sync", Children: []binary.Node{{Tag: "patches"}}}},
		{"collection without name", &binary.Node{Tag: "collection"}},
		{"collection server error", &binary.Node{
			Tag:      "collection",
			Attrs:    binary.Attrs{"name": "regular_low", "type": "error"},
			Children: []binary.Node{{Tag: "error", Attrs: binary.Attrs{"code": "409"}}},
		}},
		{"empty patch content", patchNode("regular_low", []byte{})},
		{"truncated tag", patchNode("regular_low", []byte{0x80})},
		{"field number zero", patchNode("regular_low", []byte{0x00})},
		{"truncated length", patchNode("regular_low", []byte{0x0a, 0x05, 0x01})},
		{"group wire type", patchNode("regular_low", []byte{0x0b})},
		{"reserved wire type", patchNode("regular_low", []byte{0x0f})},
		{"varint overflow", patchNode("regular_low", append(pbTag(1, 0),
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F))},
		{"wrong wire type for version", patchNode("regular_low", pbUint(fieldPatchVersion, 1))},
		{"wrong wire type for mutations", patchNode("regular_low", pbUint(fieldPatchMutations, 1))},
		{"mutation missing record", patchNode("regular_low",
			pbConcat(pbBytes(fieldPatchVersion, pbUint(fieldBlob, 1)), pbBytes(fieldPatchMutations, pbUint(1, 0))))},
		{"unknown operation", patchNode("regular_low", syncdPatch(1, [][]byte{
			mutation(2, bytes.Repeat([]byte{0x01}, 32), append(value, valueMACForTest(OperationSet, keyID, value)...), keyID),
		}))},
		{"record without index", patchNode("regular_low", syncdPatch(1, [][]byte{
			pbConcat(pbUint(1, 0), pbBytes(fieldMutationRecord, pbConcat(
				pbBytes(fieldRecordValue, blob(append(value, valueMACForTest(OperationSet, keyID, value)...))),
				pbBytes(fieldRecordKeyID, blob(keyID)),
			))),
		}))},
		{"record without key id", patchNode("regular_low", syncdPatch(1, [][]byte{
			pbConcat(pbUint(1, 0), pbBytes(fieldMutationRecord, pbConcat(
				pbBytes(fieldRecordIndex, blob(bytes.Repeat([]byte{0x01}, 32))),
				pbBytes(fieldRecordValue, blob(append(value, valueMACForTest(OperationSet, keyID, value)...))),
			))),
		}))},
		{"set value too short", patchNode("regular_low", syncdPatch(1, [][]byte{
			mutation(0, bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x00}, MinValueSize-1), keyID),
		}))},
		{"remove value too short", patchNode("regular_low", syncdPatch(1, [][]byte{
			mutation(1, bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x00}, MinValueSize-1), keyID),
		}))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codec := binary.NewCodec(nil)
			node := tc.node
			if node != nil && node.Tag != "" {
				// Round-trip the malformed stanza through the codec so the
				// failure surfaces in ParsePatches, not in the encoder.
				frame, err := codec.Encode(node)
				if err != nil {
					t.Fatalf("encode malformed stanza: %v", err)
				}
				decoded, err := codec.Decode(bytes.NewReader(frame))
				if err != nil {
					t.Fatalf("decode malformed stanza: %v", err)
				}
				node = decoded
			}
			_, err := ParsePatches(node)
			if !errors.Is(err, ErrInvalidPatch) {
				t.Fatalf("want ErrInvalidPatch, got %v", err)
			}
		})
	}

	// A SET blob of exactly MinValueSize bytes is accepted (IV + MAC, no
	// ciphertext); block alignment is a decryption-time check, not a parse one.
	patches := roundTrip(t, patchNode("regular_low", syncdPatch(1, [][]byte{
		mutation(0, bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x00}, MinValueSize), keyID),
	})))
	if len(patches[0].Mutations[0].Value) != ValueIVSize {
		t.Fatalf("value = %d bytes, want %d", len(patches[0].Mutations[0].Value), ValueIVSize)
	}
}

// TestValueMACVectorIsIndependent recomputes the documented vector with the
// stdlib in the test to prove the constant is not merely what the package
// happens to compute.
func TestValueMACVectorIsIndependent(t *testing.T) {
	key := mustHex(t, "mac key", testMACKeyHex)
	keyID := mustHex(t, "key id", testKeyIDHex)
	value := mustHex(t, "value", testValueHex)

	mac := hmac.New(sha512.New, key)
	mac.Write([]byte{0x01})
	mac.Write(keyID)
	mac.Write(value)
	mac.Write([]byte{0, 0, 0, 0, 0, 0, 0, byte(len(keyID) + 1)})
	want := hex.EncodeToString(mac.Sum(nil)[:ValueMACSize])
	if want != testSetMACHex {
		t.Fatalf("vector mismatch: recomputed %s", want)
	}
}
