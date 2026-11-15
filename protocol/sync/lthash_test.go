package sync

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The vectors below were produced in an independent Python 3 implementation
// (hashlib/hmac, RFC 5869 HKDF-SHA256 written from the RFC, little-endian u16
// lanes) that shares no code with this package. The generator prints the same
// hex strings embedded here; only the four input value MACs, the key data and
// the counters are chosen by hand.
const (
	// Input value MACs, 32 bytes each.
	vectorMACa = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vectorMACb = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	vectorMACc = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	vectorMACd = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa55"
	// vectorKeyData is the app-state sync key ExpandKeys is fed.
	vectorKeyData = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

	// Per-element expansions of the four MACs.
	vectorExpandA = "fa29a23a1edb970a8db0b86d1ae94d4461209cbea2dae9dc39ef1ba696d7213042d167b5db383efd034591861867ae2746357ecee3bccd070b1110e0abb6f18c91d687194dd9f7ea2d474f815bed0adb07fd6256915d9bda410982dab7bc7e07f525caf02ef2bc7b9f8d7b70469ab8ada2fc32c2c718728f04d0d340a6a368a2"
	vectorExpandB = "bfdece723742d9dc9dd4eff306eda926fe29c995b04645a390c73e8aa2308f58f5e0281a26a9632ea4ce2a32a40cb0b15c80794b43674e4cb39d9dcac466bc0d3808de524546edf7e21256d28a2778c06fcb37eca3b47f1e54eb828ad8dd7b50ce2f3ea18480f362823b5420f91ad5ddcb91035be7bfc4190a2bbcdc5a5200cb"
	vectorExpandC = "0c4d5720c1af73f1b4cc2f6c354d8b7d4fe118511c697d628734edcb4906450a6374dda742fd63e067ee56bcc6cfda5eac029dd81e322d1db9aa535b47d09a2e87128fc6837128492be4da042c5da68c6627834cf5cfc6b3bc027169781cb7c2051c0a58ff674b9c7e3e68b795e9cd02e0cfd6c31c9954f239df383d3a99c07f"
	vectorExpandD = "46ce76de42ee8fd74cefdd3cc8eb2f775a39f5848f745a4b9fbb24846f18242074003bc99c0b33dea6fbac69d00229459e73b0ae187c6cc8e18befd590bf9041ba9dbd754ca7f6aa4c466d4654f1fe15e9bc9d9da0e34eca3556d4d25b1db5261e660de8c1a0089caf230691570739db73316ea9c165a16da9f844090125dd13"

	// Accumulator states after the documented sequence of folds.
	vectorEmpty     = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	vectorAddA      = "fa29a23a1edb970a8db0b86d1ae94d4461209cbea2dae9dc39ef1ba696d7213042d167b5db383efd034591861867ae2746357ecee3bccd070b1110e0abb6f18c91d687194dd9f7ea2d474f815bed0adb07fd6256915d9bda410982dab7bc7e07f525caf02ef2bc7b9f8d7b70469ab8ada2fc32c2c718728f04d0d340a6a368a2"
	vectorAddAB     = "b90870ad551d70e72a85a76120d6f66a5f4a655452212e80c9b659303808b08837b28fcf01e2a12ba713bbb8bc735ed9a2b5f71926241b54beaeadaa6f1dad9ac9de656c921fe4e20f5aa553e514829b76c8994234121af995f404658f9af957c3550892b272afde21c9cf903fb58d8b6d8e351daed836a90efb8f1d00f6686d"
	vectorAddABC    = "c555c7cd16cde3d8de51d6cd552381e8ae2b7da56e8aabe250eb46fc810ef5929a266c7743df040c0e021175824338384eb894f24456487177590006b6ed47c950f1f43215910c2c3a3e7f5811722828dcef1c8f29e2e0ac51f775ce07b7b01ac87112eab1dafa7a9f073748d49e5a8e4d5e0be1ca718a9b47dac75a3a8f28ed"
	vectorAddABCD   = "0b243dac58bb72b02a41b30a1d0fb05f0865722afdfe052eefa66a80f02619b30e27a740dfea37eab4fdbdde5246617dec2b44a15cd2b43958e5efdb46add70a0a8fb1a8613802d78684ec9e6563263ec5acb92cc9c52e77864d49a162d46541e6d71fd2727b02174e2b3dd92ba69369c08f798a8bd72b09f0d20b643bb40501"
	vectorAddBAC    = "b90870ad551d70e72a85a76120d6f66a5f4a655452212e80c9b659303808b08837b28fcf01e2a12ba713bbb8bc735ed9a2b5f71926241b54beaeadaa6f1dad9ac9de656c921fe4e20f5aa553e514829b76c8994234121af995f404658f9af957c3550892b272afde21c9cf903fb58d8b6d8e351daed836a90efb8f1d00f6686d"
	vectorAddCAB    = "c555c7cd16cde3d8de51d6cd552381e8ae2b7da56e8aabe250eb46fc810ef5929a266c7743df040c0e021175824338384eb894f24456487177590006b6ed47c950f1f43215910c2c3a3e7f5811722828dcef1c8f29e2e0ac51f775ce07b7b01ac87112eab1dafa7a9f073748d49e5a8e4d5e0be1ca718a9b47dac75a3a8f28ed"
	vectorAddDBA    = "ffd6e68b970bffbe7674849ee8c125e2b9835ad9e19588cb68727db4a720d4a8abb2ca989dedd4094d0f67228c76871e4029a7c83ea0871c9f3a9c80ffdc3ddc837c22e2dec6da8d5ba0129a390680b15f8536e0d4f568c3ca4ad837eab7ae7ee1bb157a7313b77ad0ecd52196bcc666e0bfa3c66f3ed716b7f3d326011b4581"
	vectorCancelABC = vectorEmpty
	vectorCancelAB  = vectorEmpty
	vectorSwap      = "521bcdfe039e02c900bc0ca9fd38baf4a91a0dd6abddd7ad26f01150b81e692ad7741871de0896be0dea022696d203a44a764d8736ae99e59a364231d78f2a7041b04c3ccf181ef4772a474b804ea4a24fe420ea95b3147ef158453cd3396ce923821740c00853382d626e48ecf006de5301446dddfef55fe2d77c463bbe9d93"
	vectorSwapDir   = vectorSwap

	// Snapshot MACs over (state, version, collection).
	vectorSnapshotMACEmpty = "1480f7155b9ecdb2151c516d3f0370dd3fe031ec496660a5c3fbfcb9490e2f8e"
	vectorSnapshotMACAB    = "442ff737b8c8a3fecdbee3f585cc225822e72ad36b5d34a5e239c6177915d2d1"
	vectorSnapshotMACABC   = "70b6ee59e79ce65492a80a97fc95ddfd6a41b5eaaa5ec9a5e407d4333f467621"
	vectorSnapshotMACBig   = "478a7a3e11217e0d51dd1a813454ee4d645c77b74760a78ad57a317876742a11"

	// Patch MACs over (snapshotMAC, value MACs, version, collection).
	vectorPatchMACA    = "6d10b6c88a3f11e05413cf486c0aa46e55c03505ec6daca462f30a0f92114e34"
	vectorPatchMACNone = "d0b6ab1504cab0061b022e0cb98cb961dc26ac759e84aa50e931f8761bb482d3"
	vectorPatchMACABC  = "3481a27fdbe9c8b4bf2a8f55d2a4c4df768d2808637bf585f52a50f8e6ab1680"
	vectorPatchMACBig  = "4816fdd1de7c9da82f28685f8d42425ef2b82ac5e4f6692f02d32bc8d21f8cee"
	vectorPatchMACReo  = "464431abb6bf039ea3af6260963d1004da116bc2a25de74e56489609898b3f35"
)

// vectorHash decodes a 128-byte accumulator vector.
func vectorHash(t *testing.T, s string) Hash {
	t.Helper()
	raw := vectorBytes(t, s)
	if len(raw) != LTHashSize {
		t.Fatalf("vector is %d bytes, want %d", len(raw), LTHashSize)
	}
	var h Hash
	copy(h[:], raw)
	return h
}

// vectorBytes decodes a hex vector.
func vectorBytes(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad vector: %v", err)
	}
	return raw
}

// vectorMACs decodes several hex value MACs.
func vectorMACs(t *testing.T, ss ...string) [][]byte {
	t.Helper()
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = vectorBytes(t, s)
	}
	return out
}

// TestExpandElement pins the per-element HKDF-SHA256 expansion.
func TestExpandElement(t *testing.T) {
	cases := []struct {
		name string
		mac  string
		want string
	}{
		{"a", vectorMACa, vectorExpandA},
		{"b", vectorMACb, vectorExpandB},
		{"c", vectorMACc, vectorExpandC},
		{"d", vectorMACd, vectorExpandD},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			element, err := expandElement(vectorBytes(t, tc.mac))
			if err != nil {
				t.Fatal(err)
			}
			if want := vectorBytes(t, tc.want); !bytes.Equal(element[:], want) {
				t.Fatalf("expansion mismatch\n got %x\nwant %x", element[:], want)
			}
		})
	}
}

// TestLTHashStates pins the accumulator after each fold sequence.
func TestLTHashStates(t *testing.T) {
	macA, macB, macC, macD := vectorBytes(t, vectorMACa), vectorBytes(t, vectorMACb),
		vectorBytes(t, vectorMACc), vectorBytes(t, vectorMACd)

	steps := []struct {
		name   string
		remove [][]byte
		add    [][]byte
		want   string
	}{
		{"empty", nil, nil, vectorEmpty},
		{"add a", nil, [][]byte{macA}, vectorAddA},
		{"add ab", nil, [][]byte{macA, macB}, vectorAddAB},
		{"add abc", nil, [][]byte{macA, macB, macC}, vectorAddABC},
		{"add abcd", nil, [][]byte{macA, macB, macC, macD}, vectorAddABCD},
		{"add ba (commutative)", nil, [][]byte{macB, macA}, vectorAddBAC},
		{"add cab (order independent)", nil, [][]byte{macC, macA, macB}, vectorAddCAB},
		{"add dba (order independent)", nil, [][]byte{macD, macB, macA}, vectorAddDBA},
	}
	for _, tc := range steps {
		t.Run(tc.name, func(t *testing.T) {
			var h Hash
			if err := h.SubtractThenAdd(tc.remove, tc.add); err != nil {
				t.Fatal(err)
			}
			if want := vectorHash(t, tc.want); h != want {
				t.Fatalf("state mismatch\n got %x\nwant %x", h[:], want[:])
			}
		})
	}
}

// TestLTHashCancel checks that subtracting what was added restores the state,
// and that subtract-then-add recomputes a different base correctly.
func TestLTHashCancel(t *testing.T) {
	macA, macB, macC, macD := vectorBytes(t, vectorMACa), vectorBytes(t, vectorMACb),
		vectorBytes(t, vectorMACc), vectorBytes(t, vectorMACd)

	t.Run("add then remove returns to empty", func(t *testing.T) {
		var h Hash
		if err := h.SubtractThenAdd(nil, [][]byte{macA, macB, macC}); err != nil {
			t.Fatal(err)
		}
		if err := h.SubtractThenAdd([][]byte{macA, macB, macC}, nil); err != nil {
			t.Fatal(err)
		}
		if want := vectorHash(t, vectorCancelABC); h != want {
			t.Fatalf("state mismatch\n got %x\nwant %x", h[:], want[:])
		}
	})

	t.Run("remove in reverse order returns to empty", func(t *testing.T) {
		var h Hash
		if err := h.SubtractThenAdd(nil, [][]byte{macA, macB}); err != nil {
			t.Fatal(err)
		}
		if err := h.SubtractThenAdd([][]byte{macB, macA}, nil); err != nil {
			t.Fatal(err)
		}
		if want := vectorHash(t, vectorCancelAB); h != want {
			t.Fatalf("state mismatch\n got %x\nwant %x", h[:], want[:])
		}
	})

	t.Run("removal without prior add wraps", func(t *testing.T) {
		var h Hash
		if err := h.SubtractThenAdd([][]byte{macA}, nil); err != nil {
			t.Fatal(err)
		}
		if h == (Hash{}) {
			t.Fatal("subtracting from the empty state left it unchanged")
		}
		if err := h.SubtractThenAdd(nil, [][]byte{macA}); err != nil {
			t.Fatal(err)
		}
		if h != (Hash{}) {
			t.Fatalf("state is %x, want empty after the inverse add", h[:])
		}
	})

	t.Run("remove then add swaps the base", func(t *testing.T) {
		var h Hash
		if err := h.SubtractThenAdd(nil, [][]byte{macA, macB}); err != nil {
			t.Fatal(err)
		}
		if err := h.SubtractThenAdd([][]byte{macA, macB}, [][]byte{macC, macD}); err != nil {
			t.Fatal(err)
		}
		if want := vectorHash(t, vectorSwap); h != want {
			t.Fatalf("state mismatch\n got %x\nwant %x", h[:], want[:])
		}
		var direct Hash
		if err := direct.SubtractThenAdd(nil, [][]byte{macC, macD}); err != nil {
			t.Fatal(err)
		}
		if want := vectorHash(t, vectorSwapDir); direct != want {
			t.Fatalf("direct state mismatch\n got %x\nwant %x", direct[:], want[:])
		}
		if h != direct {
			t.Fatalf("swap base %x differs from direct base %x", h[:], direct[:])
		}
	})

	t.Run("same element in both lists cancels", func(t *testing.T) {
		// Lanes are additive, so an element that is subtracted and added in
		// one call has no net effect on any base. That is the property the
		// caller relies on when a mutation overwrites an index with itself.
		var empty Hash
		if err := empty.SubtractThenAdd([][]byte{macA}, [][]byte{macA}); err != nil {
			t.Fatal(err)
		}
		if empty != (Hash{}) {
			t.Fatalf("state is %x, want empty", empty[:])
		}

		var base Hash
		if err := base.SubtractThenAdd(nil, [][]byte{macA}); err != nil {
			t.Fatal(err)
		}
		if err := base.SubtractThenAdd([][]byte{macA}, [][]byte{macA}); err != nil {
			t.Fatal(err)
		}
		if want := vectorHash(t, vectorAddA); base != want {
			t.Fatalf("state mismatch\n got %x\nwant %x", base[:], want[:])
		}
	})
}

// TestLTHashMalformed covers the element-size and nil-state guards.
func TestLTHashMalformed(t *testing.T) {
	tooShort := bytes.Repeat([]byte{0x01}, ValueMACSize-1)
	tooLong := bytes.Repeat([]byte{0x01}, ValueMACSize+1)

	cases := []struct {
		name   string
		remove [][]byte
		add    [][]byte
		want   string
	}{
		{"short add", nil, [][]byte{tooShort}, "element of 31 bytes"},
		{"long add", nil, [][]byte{tooLong}, "element of 33 bytes"},
		{"empty element", nil, [][]byte{{}}, "element of 0 bytes"},
		{"nil element", nil, [][]byte{nil}, "element of 0 bytes"},
		{"short remove", [][]byte{tooShort}, nil, "element of 31 bytes"},
		{"bad element after good", nil, [][]byte{bytes.Repeat([]byte{0x02}, ValueMACSize), tooLong}, "element of 33 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var h Hash
			err := h.SubtractThenAdd(tc.remove, tc.add)
			if !errors.Is(err, ErrInvalidLTHash) {
				t.Fatalf("error = %v, want ErrInvalidLTHash", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	t.Run("nil accumulator", func(t *testing.T) {
		var h *Hash
		err := h.SubtractThenAdd(nil, [][]byte{bytes.Repeat([]byte{0x01}, ValueMACSize)})
		if !errors.Is(err, ErrInvalidLTHash) {
			t.Fatalf("error = %v, want ErrInvalidLTHash", err)
		}
	})
}

// TestLTHashInPlace checks that the accumulator is modified in place through
// the pointer, as callers holding a HashState field require.
func TestLTHashInPlace(t *testing.T) {
	mac := vectorBytes(t, vectorMACa)
	h := Hash{}
	before := h
	if err := h.SubtractThenAdd(nil, [][]byte{mac}); err != nil {
		t.Fatal(err)
	}
	if h == before {
		t.Fatal("accumulator was not updated in place")
	}
	if want := vectorHash(t, vectorAddA); h != want {
		t.Fatalf("state mismatch\n got %x\nwant %x", h[:], want[:])
	}
}

// envelopeKeys returns the key set the MAC vectors were generated against.
func envelopeKeys(t *testing.T) Keys {
	t.Helper()
	keys, err := ExpandKeys(vectorBytes(t, vectorKeyData))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// TestSnapshotMAC pins the snapshot envelope MAC.
func TestSnapshotMAC(t *testing.T) {
	keys := envelopeKeys(t)
	cases := []struct {
		name       string
		hash       string
		version    uint64
		collection string
		want       string
	}{
		{"empty state version 0", vectorEmpty, 0, "critical_block", vectorSnapshotMACEmpty},
		{"ab version 7", vectorAddAB, 7, "regular", vectorSnapshotMACAB},
		{"abc version 1", vectorAddABC, 1, "critical_unblock_low", vectorSnapshotMACABC},
		{"abcd version above 2^32", vectorAddABCD, 1 << 40, "regular_high", vectorSnapshotMACBig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SnapshotMAC(keys, vectorHash(t, tc.hash), tc.version, tc.collection)
			if want := vectorBytes(t, tc.want); !bytes.Equal(got, want) {
				t.Fatalf("MAC mismatch\n got %x\nwant %x", got, want)
			}
			if err := VerifySnapshotMAC(keys, vectorHash(t, tc.hash), tc.version, tc.collection, vectorBytes(t, tc.want)); err != nil {
				t.Fatalf("VerifySnapshotMAC: %v", err)
			}
		})
	}
}

// TestPatchMAC pins the patch envelope MAC.
func TestPatchMAC(t *testing.T) {
	keys := envelopeKeys(t)
	cases := []struct {
		name       string
		snapshot   string
		valueMACs  []string
		version    uint64
		collection string
		want       string
	}{
		{"two mutations", vectorSnapshotMACEmpty, []string{vectorMACa, vectorMACb}, 1, "critical_block", vectorPatchMACA},
		{"no values", vectorSnapshotMACAB, nil, 2, "regular", vectorPatchMACNone},
		{"three mutations", vectorSnapshotMACABC, []string{vectorMACa, vectorMACb, vectorMACc}, 3, "regular_high", vectorPatchMACABC},
		{"version above 2^32", vectorSnapshotMACBig, []string{vectorMACd}, 1 << 40, "regular_high", vectorPatchMACBig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := vectorBytes(t, tc.snapshot)
			valueMACs := vectorMACs(t, tc.valueMACs...)
			got := PatchMAC(keys, snapshot, valueMACs, tc.version, tc.collection)
			if want := vectorBytes(t, tc.want); !bytes.Equal(got, want) {
				t.Fatalf("MAC mismatch\n got %x\nwant %x", got, want)
			}
			if err := VerifyPatchMAC(keys, snapshot, valueMACs, tc.version, tc.collection, vectorBytes(t, tc.want)); err != nil {
				t.Fatalf("VerifyPatchMAC: %v", err)
			}
		})
	}
}

// TestEnvelopeMACTamper covers the negatives: every input is part of the MAC.
func TestEnvelopeMACTamper(t *testing.T) {
	keys := envelopeKeys(t)
	otherKeys, err := ExpandKeys(bytes.Repeat([]byte{0x5b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	hash := vectorHash(t, vectorAddABC)
	valueMACs := vectorMACs(t, vectorMACa, vectorMACb, vectorMACc)
	snapshot := vectorBytes(t, vectorSnapshotMACABC)
	patch := vectorBytes(t, vectorPatchMACABC)

	t.Run("snapshot", func(t *testing.T) {
		cases := []struct {
			name       string
			keys       Keys
			hash       Hash
			version    uint64
			collection string
			expected   []byte
		}{
			{"wrong key", otherKeys, hash, 3, "regular_high", snapshot},
			{"wrong version", keys, hash, 4, "regular_high", snapshot},
			{"wrong collection", keys, hash, 3, "regular", snapshot},
			{"wrong hash", keys, vectorHash(t, vectorAddAB), 3, "regular_high", snapshot},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := VerifySnapshotMAC(tc.keys, tc.hash, tc.version, tc.collection, tc.expected); !errors.Is(err, ErrBadEnvelopeMAC) {
					t.Fatalf("error = %v, want ErrBadEnvelopeMAC", err)
				}
			})
		}
	})

	t.Run("patch", func(t *testing.T) {
		cases := []struct {
			name       string
			keys       Keys
			snapshot   []byte
			valueMACs  [][]byte
			version    uint64
			collection string
			expected   []byte
		}{
			{"wrong key", otherKeys, snapshot, valueMACs, 3, "regular_high", patch},
			{"wrong snapshot MAC", keys, vectorBytes(t, vectorSnapshotMACEmpty), valueMACs, 3, "regular_high", patch},
			{"dropped value MAC", keys, snapshot, valueMACs[:2], 3, "regular_high", patch},
			{"extra value MAC", keys, snapshot, vectorMACs(t, vectorMACa, vectorMACb, vectorMACc, vectorMACd), 3, "regular_high", patch},
			{"reordered value MACs", keys, snapshot, vectorMACs(t, vectorMACc, vectorMACb, vectorMACa), 3, "regular_high", patch},
			{"wrong version", keys, snapshot, valueMACs, 4, "regular_high", patch},
			{"wrong collection", keys, snapshot, valueMACs, 3, "regular_high2", patch},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := VerifyPatchMAC(tc.keys, tc.snapshot, tc.valueMACs, tc.version, tc.collection, tc.expected); !errors.Is(err, ErrBadEnvelopeMAC) {
					t.Fatalf("error = %v, want ErrBadEnvelopeMAC", err)
				}
			})
		}
	})

	t.Run("reordered patch MAC differs from the vector", func(t *testing.T) {
		got := PatchMAC(keys, snapshot, vectorMACs(t, vectorMACc, vectorMACb, vectorMACa), 3, "regular_high")
		if want := vectorBytes(t, vectorPatchMACReo); !bytes.Equal(got, want) {
			t.Fatalf("MAC mismatch\n got %x\nwant %x", got, want)
		}
	})
}

// TestEnvelopeMACMalformed covers wrong MAC lengths and unusable key material.
func TestEnvelopeMACMalformed(t *testing.T) {
	keys := envelopeKeys(t)
	hash := vectorHash(t, vectorAddABC)
	snapshot := vectorBytes(t, vectorSnapshotMACABC)

	t.Run("snapshot MAC length", func(t *testing.T) {
		cases := []struct {
			name     string
			expected []byte
			want     string
		}{
			{"nil", nil, "snapshot MAC of 0 bytes"},
			{"short", snapshot[:31], "snapshot MAC of 31 bytes"},
			{"long", append(append([]byte(nil), snapshot...), 0x00), "snapshot MAC of 33 bytes"},
			{"empty", []byte{}, "snapshot MAC of 0 bytes"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := VerifySnapshotMAC(keys, hash, 3, "regular_high", tc.expected)
				if !errors.Is(err, ErrBadEnvelopeMAC) {
					t.Fatalf("error = %v, want ErrBadEnvelopeMAC", err)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error %q does not mention %q", err, tc.want)
				}
			})
		}
	})

	t.Run("patch MAC length", func(t *testing.T) {
		patch := vectorBytes(t, vectorPatchMACABC)
		for _, expected := range [][]byte{nil, patch[:16], patch[:31], append(append([]byte(nil), patch...), 0xff)} {
			err := VerifyPatchMAC(keys, snapshot, nil, 3, "regular_high", expected)
			if !errors.Is(err, ErrBadEnvelopeMAC) {
				t.Fatalf("length %d: error = %v, want ErrBadEnvelopeMAC", len(expected), err)
			}
		}
	})

	t.Run("zero key set never matches the vectors", func(t *testing.T) {
		if err := VerifySnapshotMAC(Keys{}, hash, 3, "regular_high", snapshot); !errors.Is(err, ErrBadEnvelopeMAC) {
			t.Fatalf("error = %v, want ErrBadEnvelopeMAC", err)
		}
	})

	t.Run("empty collection still hashes", func(t *testing.T) {
		// The collection name is hashed as bytes, so an empty name is a
		// distinct MAC rather than an error; this pins that it differs.
		empty := SnapshotMAC(keys, hash, 3, "")
		if bytes.Equal(empty, snapshot) {
			t.Fatal("empty collection name produced the named-collection MAC")
		}
		if len(empty) != EnvelopeMACSize {
			t.Fatalf("MAC is %d bytes, want %d", len(empty), EnvelopeMACSize)
		}
	})
}

// TestValueMACs checks the collector matches the order and payload rule the
// patch MAC uses.
func TestValueMACs(t *testing.T) {
	keys := envelopeKeys(t)
	mutations := []PatchMutation{
		{Operation: OperationSet, ValueMAC: vectorBytes(t, vectorMACa)},
		{Operation: OperationRemove, ValueMAC: nil}, // REMOVE without a payload
		{Operation: OperationSet, ValueMAC: vectorBytes(t, vectorMACb)},
		{Operation: OperationRemove, ValueMAC: vectorBytes(t, vectorMACc)},
	}
	got := ValueMACs(mutations)
	if len(got) != 3 {
		t.Fatalf("collected %d value MACs, want 3", len(got))
	}
	if !bytes.Equal(got[0], vectorBytes(t, vectorMACa)) ||
		!bytes.Equal(got[1], vectorBytes(t, vectorMACb)) ||
		!bytes.Equal(got[2], vectorBytes(t, vectorMACc)) {
		t.Fatalf("value MACs out of wire order: %x", got)
	}
	if err := VerifyPatchMAC(keys, vectorBytes(t, vectorSnapshotMACABC), got, 3, "regular_high",
		vectorBytes(t, vectorPatchMACABC)); err != nil {
		t.Fatalf("VerifyPatchMAC over collected MACs: %v", err)
	}
}
