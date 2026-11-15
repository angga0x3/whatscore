package xeddsa

import "testing"

// TestVerifyRejectsSignBitFlip pins the one XEdDSA-specific verification rule
// (PF-067): the Edwards sign travels in the top bit of the last signature byte,
// so flipping that bit on an otherwise valid signature must fail. The
// authoritative cross-check against the reference implementation lives in
// vectors_test.go.
func TestVerifyRejectsSignBitFlip(t *testing.T) {
	vec := referenceVectors[0]
	var pub [32]byte
	copy(pub[:], decode(t, vec.pub))
	msg := decode(t, vec.msg)
	sig := decode(t, vec.sig)

	if err := Verify(pub, msg, sig); err != nil {
		t.Fatalf("baseline vector rejected: %v", err)
	}
	flipped := append([]byte(nil), sig...)
	flipped[63] ^= 0x80
	if err := Verify(pub, msg, flipped); err == nil {
		t.Fatal("sign-bit flip accepted")
	}
}
