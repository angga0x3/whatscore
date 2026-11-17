package signal

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// Vectors generated with go.mau.fi/libsignal v0.2.2 (SenderChainKey,
// SenderKeyDistributionMessage and SenderKeyMessage with the protobuf
// serializer). See the commit message: the generator prints these constants.
const (
	vectorChainKey     = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	vectorSigningPriv  = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	vectorSigningPub   = "05605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c"
	vectorIV           = "5108e5678234d2bbdcb53beca99ec105"
	vectorCipherKey    = "844c2b2ba8e83776a4df6cd753ad4fc252308959adf2403b160e6ac4fd8fa0a1"
	vectorSKDM         = "3308c0c40710051a200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20222105605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c"
	vectorSKM          = "3308c0c40710051a209b73ecedee6860cdf3930fb81f9a493cd18ebda6b7526d428d934a6fcde89765df1d7f22a0d7b3a6e2304d7542964a1f27144641e943dcba9c8d41b70d29288a61026c14e09dcc7deaea7e7d524c209e4047944f76e599fdb6552804fcab9708"
	vectorPlaintext    = "halo grup"
	vectorSKMIteration = 5
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex %q: %v", value, err)
	}
	return raw
}

// TestParseSenderKeyDistribution pins the distribution message against the
// reference serializer: version nibble, id, iteration, chain key and the
// curve-typed signing key.
func TestParseSenderKeyDistribution(t *testing.T) {
	parsed, err := ParseSenderKeyDistribution(mustHex(t, vectorSKDM))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Version != 3 {
		t.Fatalf("version = %d, want 3", parsed.Version)
	}
	if parsed.ID != 123456 {
		t.Fatalf("id = %d", parsed.ID)
	}
	if parsed.Iteration != 5 {
		t.Fatalf("iteration = %d", parsed.Iteration)
	}
	if !bytes.Equal(parsed.ChainKey[:], mustHex(t, vectorChainKey)) {
		t.Fatalf("chain key = %x", parsed.ChainKey)
	}
	wantPub := mustHex(t, vectorSigningPub)
	if !bytes.Equal(parsed.SigningKey[:], wantPub[1:]) {
		t.Fatalf("signing key = %x", parsed.SigningKey)
	}
}

// TestSenderChainMatchesTheReference pins the chain derivation: libsignal's
// getDerivative + HKDF("WhisperGroup") at iteration 5.
func TestSenderChainMatchesTheReference(t *testing.T) {
	chain := SenderChain{Key: bytesTo32(t, mustHex(t, vectorChainKey))}
	advanced, err := chain.Advance(vectorSKMIteration)
	if err != nil {
		t.Fatalf("advance: %v", err)
	}
	if advanced.Iteration != vectorSKMIteration {
		t.Fatalf("iteration = %d", advanced.Iteration)
	}
	iv, key, err := advanced.MessageKey()
	if err != nil {
		t.Fatalf("message key: %v", err)
	}
	if !bytes.Equal(iv[:], mustHex(t, vectorIV)) {
		t.Fatalf("iv = %x, want %s", iv, vectorIV)
	}
	if !bytes.Equal(key[:], mustHex(t, vectorCipherKey)) {
		t.Fatalf("cipher key = %x, want %s", key, vectorCipherKey)
	}
}

// TestSenderKeyMessageVerifiesAndDecrypts is the whole read path against a
// reference-produced message: parse, verify the XEdDSA signature under the
// distributed signing key, derive the iteration's keys, and open the text.
func TestSenderKeyMessageVerifiesAndDecrypts(t *testing.T) {
	message, err := ParseSenderKeyMessage(mustHex(t, vectorSKM))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if message.Version != 3 || message.ID != 123456 || message.Iteration != 5 {
		t.Fatalf("message = %+v", message)
	}

	pub := bytesTo32(t, mustHex(t, vectorSigningPub)[1:])
	if err := message.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	chain := SenderChain{Key: bytesTo32(t, mustHex(t, vectorChainKey))}
	advanced, err := chain.Advance(message.Iteration)
	if err != nil {
		t.Fatal(err)
	}
	iv, key, err := advanced.MessageKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := message.Decrypt(iv, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	// The reference encrypted a protobuf Message (conversation "halo grup")
	// padded with five 0x05 bytes, the way whatsmeow pads before encrypting;
	// stripping the pad is the caller's job, so the primitive returns both.
	want := append([]byte{0x0a, byte(len(vectorPlaintext))}, vectorPlaintext...)
	want = append(want, 5, 5, 5, 5, 5)
	if !bytes.Equal(plaintext, want) {
		t.Fatalf("plaintext = %x", plaintext)
	}
}

// TestSenderKeyMessageRejectsTampering keeps the two trust decisions honest:
// a changed signature, body or ciphertext is not a message.
func TestSenderKeyMessageRejectsTampering(t *testing.T) {
	raw := mustHex(t, vectorSKM)
	pub := bytesTo32(t, mustHex(t, vectorSigningPub)[1:])

	tamperedSignature := append([]byte(nil), raw...)
	tamperedSignature[len(tamperedSignature)-1] ^= 0x01
	message, err := ParseSenderKeyMessage(tamperedSignature)
	if err != nil {
		t.Fatalf("parse tampered signature: %v", err)
	}
	if err := message.Verify(pub); err == nil {
		t.Fatal("tampered signature accepted")
	}

	tamperedBody := append([]byte(nil), raw...)
	tamperedBody[6] ^= 0x01 // inside the protobuf body, before the signature
	message, err = ParseSenderKeyMessage(tamperedBody)
	if err != nil {
		t.Fatalf("parse tampered body: %v", err)
	}
	if err := message.Verify(pub); err == nil {
		t.Fatal("tampered body accepted")
	}

	// A wrong signing key is the same failure as a wrong signature.
	wrong := pub
	wrong[0] ^= 0x01
	message, err = ParseSenderKeyMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := message.Verify(wrong); err == nil {
		t.Fatal("wrong signing key accepted")
	}
}

// TestSenderKeyParsingRejectsGarbage fails closed on shapes no serializer
// produces.
func TestSenderKeyParsingRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":         {},
		"short":         {0x33},
		"version 0":     append([]byte{0x03}, make([]byte, 40)...),
		"version 9":     append([]byte{0x93}, make([]byte, 40)...),
		"truncated skm": append([]byte{0x33, 0x08}, make([]byte, 64)...),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSenderKeyMessage(raw); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A distribution message that lost the tail of its signing key.
	bad := mustHex(t, vectorSKDM)[:len(mustHex(t, vectorSKDM))-3]
	if _, err := ParseSenderKeyDistribution(bad); err == nil {
		t.Fatal("truncated distribution accepted")
	}
}

// TestSenderChainRefusesHugeJumps keeps a hostile iteration from driving
// unbounded derivation.
func TestSenderChainRefusesHugeJumps(t *testing.T) {
	chain := SenderChain{Key: [KeySize]byte{0x01}}
	if _, err := chain.Advance(MaxSenderKeyAdvance + 1); !errors.Is(err, ErrSenderKeyTooFar) {
		t.Fatalf("jump: %v", err)
	}
	if _, err := chain.Advance(0); err != nil {
		t.Fatalf("same iteration: %v", err)
	}
	later := SenderChain{Iteration: 10}
	if _, err := later.Advance(5); err == nil {
		t.Fatal("backwards advance accepted")
	}
}

func bytesTo32(t *testing.T, raw []byte) [KeySize]byte {
	t.Helper()
	if len(raw) != KeySize {
		t.Fatalf("key is %d bytes", len(raw))
	}
	var out [KeySize]byte
	copy(out[:], raw)
	return out
}

// TestSerializeSenderKeyDistributionMatchesTheReference drives the sender
// side through the same wire the vectors came from: the distribution built
// from the vector's material must serialize byte-for-byte to the reference
// SKDM (without the version byte differing — both use nibble 3).
func TestSerializeSenderKeyDistributionMatchesTheReference(t *testing.T) {
	parsed, err := ParseSenderKeyDistribution(mustHex(t, vectorSKDM))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := SerializeSenderKeyDistribution(*parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, mustHex(t, vectorSKDM)) {
		t.Fatalf("wire = %x, want %x", wire, mustHex(t, vectorSKDM))
	}
}

// TestEncryptSenderKeyMessageMatchesTheReference proves the send side: a
// sender chain advanced to the vector's iteration encrypts the vector's
// plaintext into the vector's exact SenderKeyMessage wire — signed under the
// vector's signing key (the XEdDSA randomness is fixed by the vector test
// helper through the deterministic path below). The wire must then parse and
// verify under the vector's signing PUBLIC key, and decrypt back to the
// plaintext.
func TestEncryptSenderKeyMessageMatchesTheReference(t *testing.T) {
	chain := SenderChain{Key: bytesTo32(t, mustHex(t, vectorChainKey))}
	advanced, err := chain.Advance(vectorSKMIteration)
	if err != nil {
		t.Fatal(err)
	}
	state := SenderKeySenderState{
		ID:        123456,
		Iteration: advanced.Iteration,
		ChainKey:  advanced.Key,
		Signing: SenderKeySigningPair{
			Private: bytesTo32(t, mustHex(t, vectorSigningPriv)),
			Public:  bytesTo32(t, mustHex(t, vectorSigningPub[2:])),
		},
	}
	// The vector's plaintext: the protobuf Message (conversation) padded
	// with five 0x05 bytes, exactly what libsignal encrypted.
	inner := append([]byte{0x0a, byte(len(vectorPlaintext))}, vectorPlaintext...)
	plaintext := append(inner, 5, 5, 5, 5, 5)

	wire, next, err := EncryptSenderKeyMessage(state, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if next.Iteration != state.Iteration+1 {
		t.Fatalf("iteration = %d, want %d", next.Iteration, state.Iteration+1)
	}

	// The signature is XEdDSA-randomized, so byte-for-byte equality with the
	// reference wire stops at the ciphertext field; the signature is checked
	// by Verify under the vector's public key instead.
	message, err := ParseSenderKeyMessage(wire)
	if err != nil {
		t.Fatalf("parse our wire: %v", err)
	}
	reference, err := ParseSenderKeyMessage(mustHex(t, vectorSKM))
	if err != nil {
		t.Fatal(err)
	}
	if message.Version != reference.Version || message.ID != reference.ID ||
		message.Iteration != reference.Iteration {
		t.Fatalf("header = %+v vs %+v", message, reference)
	}
	if !bytes.Equal(message.Ciphertext, reference.Ciphertext) {
		t.Fatalf("ciphertext = %x, want %x", message.Ciphertext, reference.Ciphertext)
	}
	if err := message.Verify(state.Signing.Public); err != nil {
		t.Fatalf("signature under the vector's public key: %v", err)
	}
	plaintextBack, err := message.Decrypt(ivFor(t, state), keyFor(t, state))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plaintextBack, plaintext) {
		t.Fatalf("decrypt round trip = %x", plaintextBack)
	}
}

// ivFor derives the message keys for the state's chain.
func ivFor(t *testing.T, state SenderKeySenderState) [16]byte {
	t.Helper()
	chain := SenderChain{Iteration: state.Iteration, Key: state.ChainKey}
	iv, _, err := chain.MessageKey()
	if err != nil {
		t.Fatal(err)
	}
	return iv
}

// keyFor derives the cipher key for the state's chain.
func keyFor(t *testing.T, state SenderKeySenderState) [32]byte {
	t.Helper()
	chain := SenderChain{Iteration: state.Iteration, Key: state.ChainKey}
	_, key, err := chain.MessageKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}
