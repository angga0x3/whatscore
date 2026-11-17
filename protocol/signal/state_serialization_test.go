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

// TestStateSerializationKeepsPendingPreKey pins the metadata that keeps a
// first-contact send recoverable across a restart: the bootstrap envelope must
// survive until a reply proves the remote device installed the session.
func TestStateSerializationKeepsPendingPreKey(t *testing.T) {
	state := newStateFixture(t, 0).alice
	pending := PendingPreKey{
		RegistrationID: 4242, SignedPreKeyID: 7, PreKeyID: 9,
		BaseKey: [KeySize]byte{0xA1, 0xB2},
	}
	state.SetPendingPreKey(pending)
	if !state.HasPendingPreKey() {
		t.Fatal("pending was not set")
	}

	raw, err := state.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseState(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.HasPendingPreKey() {
		t.Fatal("pending prekey lost in serialization")
	}
	wrapped, pendingApplied, err := parsed.WrapPendingPreKey([]byte{0x33, 0x01}, [KeySize]byte{0x11})
	if err != nil || !pendingApplied {
		t.Fatalf("wrap = %v, %v", pendingApplied, err)
	}
	if len(wrapped) == 0 || wrapped[0] != WireVersion {
		t.Fatalf("wrapped = %x", wrapped)
	}
	message, err := ParsePreKeyMessage(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if message.RegistrationID != 4242 || message.SignedPreKeyID != 7 || message.PreKeyID != 9 || message.BaseKey != pending.BaseKey {
		t.Fatalf("envelope = %#v", message)
	}

	// Clearing it is what an authenticated reply does, and it must persist too.
	parsed.ClearPendingPreKey()
	raw, err = parsed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseState(raw)
	if err != nil {
		t.Fatal(err)
	}
	if again.HasPendingPreKey() {
		t.Fatal("cleared pending prekey came back after a round trip")
	}
}

// TestStateSerializationKeepsBootstrapBase pins the identifier that lets a
// receiver recognise a retransmitted prekey envelope without touching an
// already consumed one-time prekey.
func TestStateSerializationKeepsBootstrapBase(t *testing.T) {
	peerIdentity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ourIdentity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := GenerateSignedPreKey(1, XEdDSASigner{Private: ourIdentity.Private})
	if err != nil {
		t.Fatal(err)
	}
	oneTime, err := GeneratePreKey(2)
	if err != nil {
		t.Fatal(err)
	}
	initiated, err := Initiate(peerIdentity, PreKeyBundle{
		IdentityKey:           ourIdentity.Public,
		SignedPreKeyID:        signed.ID,
		SignedPreKey:          signed.Pair.Public,
		SignedPreKeySignature: signed.Signature,
		OneTimePreKeyID:       oneTime.ID,
		OneTimePreKey:         &oneTime.Pair.Public,
	})
	if err != nil {
		t.Fatal(err)
	}
	senderState, err := NewInitiator(initiated.Keys.RootKey, signed.Pair.Public, initiated.Keys.ChainKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := senderState.Encrypt([]byte{0x0a, 0x02, 'h', 'i'}, peerIdentity.Public, ourIdentity.Public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := initiated.BuildPreKeyMessage(peerIdentity.Public, 4242, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := AcceptPreKeyMessage(wire, ourIdentity, signed, &oneTime)
	if err != nil {
		t.Fatal(err)
	}
	if !state.MatchesBootstrap(initiated.EphemeralPublic) {
		t.Fatal("bootstrap base not recorded")
	}
	raw, err := state.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseState(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.MatchesBootstrap(initiated.EphemeralPublic) {
		t.Fatal("bootstrap base lost in serialization")
	}
	if parsed.MatchesBootstrap([KeySize]byte{0x99}) {
		t.Fatal("unrelated base matched")
	}
}

// TestStateSerializationReadsLegacyV1 keeps sessions written before pending
// bootstrap metadata existed readable: a snapshot from the older build has no
// trailing flags, and treating them as required would orphan every stored peer.
func TestStateSerializationReadsLegacyV1(t *testing.T) {
	state := newStateFixture(t, 1).bob
	raw, err := state.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Version 2 appends two flag bytes; drop them and mark the blob version 1.
	if len(raw) < 3 {
		t.Fatal("unexpectedly short state")
	}
	legacy := append([]byte(nil), raw[:len(raw)-2]...)
	legacy[0] = 1
	parsed, err := ParseState(legacy)
	if err != nil {
		t.Fatalf("legacy state: %v", err)
	}
	if parsed.HasPendingPreKey() {
		t.Fatal("legacy state grew pending metadata")
	}
}
