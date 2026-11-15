package signal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

type stateFixture struct {
	alice   *State
	bob     *State
	headers []Header
	keys    []MessageKeys
}

func newStateFixture(tb testing.TB, skipped int) *stateFixture {
	tb.Helper()
	c := newConversation(tb)
	fixture := &stateFixture{alice: c.alice, bob: c.bob}
	for i := 0; i < skipped+1; i++ {
		header, keys, err := c.alice.NextOutbound()
		if err != nil {
			tb.Fatal(err)
		}
		fixture.headers = append(fixture.headers, header)
		fixture.keys = append(fixture.keys, keys)
	}
	if _, err := c.bob.Receive(fixture.headers[skipped]); err != nil {
		tb.Fatal(err)
	}
	return fixture
}

func TestStateSerializationRoundTrip(t *testing.T) {
	fixture := newStateFixture(t, 3)
	raw, err := fixture.bob.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseState(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := parsed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("state is not deterministic across a round trip")
	}

	for i := 0; i < 3; i++ {
		keys, err := parsed.Receive(fixture.headers[i])
		if err != nil {
			t.Fatalf("receive skipped %d: %v", i, err)
		}
		if keys != fixture.keys[i] {
			t.Fatalf("skipped %d keys differ", i)
		}
	}
	header, keys, err := fixture.alice.NextOutbound()
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsed.Receive(header)
	if err != nil {
		t.Fatalf("receive next: %v", err)
	}
	if got != keys {
		t.Fatal("next message keys differ")
	}
}

func TestStateSerializationRejects(t *testing.T) {
	valid, err := newStateFixture(t, 1).bob.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":          nil,
		"short":          valid[:stateHeaderSize-1],
		"bad version":    mutate(valid, func(b []byte) { b[0] = 0xFF }),
		"trailing":       append(append([]byte(nil), valid...), 0x00),
		"chain overflow": mutate(valid, func(b []byte) { binary.BigEndian.PutUint16(b[137:139], MaxSerializedChains+1) }),
		"skipped overflow": mutate(valid, func(b []byte) {
			offset := 139 + int(binary.BigEndian.Uint16(b[137:139]))*(2*KeySize+4)
			binary.BigEndian.PutUint16(b[offset:offset+2], MaxSkippedKeys+1)
		}),
		"oversized": make([]byte, maxStateBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseState(raw); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("want ErrInvalidState, got %v", err)
			}
		})
	}
}

func TestStateSerializationRejectsDuplicates(t *testing.T) {
	state := &State{
		receiverChains: map[[KeySize]byte]*receiverChain{{0x01}: {}},
		skipped:        make(map[skippedKey]MessageKeys),
	}
	raw, err := state.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// chainCount at 137, one 68-byte chain record, then skippedCount.
	chain := raw[139 : 139+2*KeySize+4]
	duplicated := append([]byte(nil), raw[:137]...)
	duplicated = binary.BigEndian.AppendUint16(duplicated, 2)
	duplicated = append(duplicated, chain...)
	duplicated = append(duplicated, chain...)
	duplicated = append(duplicated, raw[139+len(chain):]...)
	if _, err := ParseState(duplicated); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("duplicate chain: %v", err)
	}

	state.skipped[skippedKey{ratchet: [KeySize]byte{0x02}}] = MessageKeys{}
	raw, err = state.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	offset := 139 + len(chain)
	skippedCount := binary.BigEndian.Uint16(raw[offset : offset+2])
	if skippedCount != 1 {
		t.Fatalf("skipped count = %d", skippedCount)
	}
	record := raw[offset+2:]
	dup := append([]byte(nil), raw[:offset]...)
	dup = binary.BigEndian.AppendUint16(dup, 2)
	dup = append(dup, record...)
	dup = append(dup, record...)
	if _, err := ParseState(dup); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("duplicate skipped: %v", err)
	}
}

func TestStateMarshalLimits(t *testing.T) {
	chains := make(map[[KeySize]byte]*receiverChain, MaxSerializedChains+1)
	for i := 0; i <= MaxSerializedChains; i++ {
		var key [KeySize]byte
		key[0] = byte(i)
		chains[key] = &receiverChain{}
	}
	if _, err := (&State{receiverChains: chains, skipped: map[skippedKey]MessageKeys{}}).MarshalBinary(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("chain limit: %v", err)
	}

	skipped := make(map[skippedKey]MessageKeys, MaxSkippedKeys+1)
	for i := 0; i <= MaxSkippedKeys; i++ {
		skipped[skippedKey{ratchet: [KeySize]byte{0x03}, index: uint32(i)}] = MessageKeys{}
	}
	if _, err := (&State{receiverChains: map[[KeySize]byte]*receiverChain{}, skipped: skipped}).MarshalBinary(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("skipped limit: %v", err)
	}
}

func TestStateClear(t *testing.T) {
	state := newStateFixture(t, 2).bob
	state.Clear()
	if state.root != (RootKey{}) || state.senderRatchet != (KeyPair{}) || state.senderChain != (ChainKey{}) {
		t.Fatal("key material not cleared")
	}
	if len(state.skipped) != 0 {
		t.Fatal("skipped keys not cleared")
	}
}

func mutate(raw []byte, change func([]byte)) []byte {
	out := append([]byte(nil), raw...)
	change(out)
	return out
}
