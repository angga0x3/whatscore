// Package xeddsa signs and verifies XEdDSA signatures: Ed25519-shaped
// signatures under a Curve25519 (Montgomery) public key.
//
// Verification is a public-key operation on the Montgomery key.
//
// Signing implements the construction used by libsignal's curve25519-donna
// port, which is *not* RFC 8032:
//
//	A        = clamp(privScalar) · B                      (public point)
//	r        = SHA-512(0xFE,0xFF... ‖ privScalar ‖ msg ‖ random[64])
//	R        = r · B
//	S        = r + SHA-512(R ‖ A ‖ msg) · clamp(privScalar)   (mod L)
//	signature = R ‖ S, with signature[63] |= A[31] & 0x80
//
// Three details matter and each was measured, not assumed (PF-067):
//
//  1. The signing scalar is the *same* clamped scalar as the public point;
//     there is no second SHA-512 expansion of the private key.
//  2. The nonce hashes a 0xFE-prefixed diversifier, the private scalar, the
//     message, and 64 bytes of randomness.
//  3. The Edwards sign bit travels in the top bit of the last S byte, and the
//     verifier moves it back onto the converted public key.
//
// Known-answer vectors in the tests were generated with go.mau.fi/libsignal
// v0.2.2, the reference implementation, not with this code.
//
// ADR 0001 records why this exists despite the "no hand-rolled crypto" rule:
// the field arithmetic is filippo.io/edwards25519 (the audited library behind
// crypto/ed25519), and only the XEdDSA framing above is ours.
package xeddsa

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

var p25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// diversifier is the prefix libsignal hashes into the nonce (PF-067).
var diversifier = [32]byte{
	0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

var (
	// ErrInvalidSignature is returned when verification fails.
	ErrInvalidSignature = errors.New("xeddsa: signature verification failed")
	// ErrInvalidKey is returned for unusable key material.
	ErrInvalidKey = errors.New("xeddsa: invalid key")
)

// Verify checks a 64-byte XEdDSA signature over msg under a Montgomery u
// public key.
func Verify(pub [32]byte, msg, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes", ErrInvalidSignature, len(sig))
	}

	// Convert the Montgomery u to the Edwards y, then take the sign bit from
	// the signature, mirroring libsignal's verify.
	var edY, one, montX, montXMinusOne, montXPlusOne field.Element
	if _, err := montX.SetBytes(pub[:]); err != nil {
		return fmt.Errorf("%w: montgomery key: %w", ErrInvalidKey, err)
	}
	_ = one.One()
	montXMinusOne.Subtract(&montX, &one)
	montXPlusOne.Add(&montX, &one)
	montXPlusOne.Invert(&montXPlusOne)
	edY.Multiply(&montXMinusOne, &montXPlusOne)

	var encoded [32]byte
	copy(encoded[:], edY.Bytes())
	encoded[31] |= sig[63] & 0x80

	normalized := append([]byte(nil), sig...)
	normalized[63] &= 0x7F

	if !ed25519.Verify(ed25519.PublicKey(encoded[:]), msg, normalized) {
		return ErrInvalidSignature
	}
	return nil
}

// Sign produces an XEdDSA signature of msg under priv using randomness. The
// randomness is a parameter rather than drawn internally so known-answer
// vectors can pin the whole construction; callers pass 32 bytes (or more) from
// crypto/rand.
func Sign(priv [32]byte, msg, randomness []byte) ([]byte, error) {
	if priv == ([32]byte{}) {
		return nil, fmt.Errorf("%w: zero private scalar", ErrInvalidKey)
	}
	if len(randomness) != 64 {
		return nil, fmt.Errorf("%w: randomness is %d bytes, want 64", ErrInvalidKey, len(randomness))
	}

	scalar, err := edwards25519.NewScalar().SetBytesWithClamping(priv[:])
	if err != nil {
		return nil, fmt.Errorf("%w: clamped scalar: %w", ErrInvalidKey, err)
	}
	publicPoint := new(edwards25519.Point).ScalarBaseMult(scalar)
	publicKey := publicPoint.Bytes()

	hash := sha512.New()
	hash.Write(diversifier[:])
	hash.Write(priv[:])
	hash.Write(msg)
	hash.Write(randomness)
	var nonceDigest [64]byte
	hash.Sum(nonceDigest[:0])

	nonce, err := edwards25519.NewScalar().SetUniformBytes(nonceDigest[:])
	if err != nil {
		return nil, fmt.Errorf("%w: nonce scalar: %w", ErrInvalidKey, err)
	}
	R := new(edwards25519.Point).ScalarBaseMult(nonce)
	encodedR := R.Bytes()

	hash.Reset()
	hash.Write(encodedR)
	hash.Write(publicKey)
	hash.Write(msg)
	var challengeDigest [64]byte
	hash.Sum(challengeDigest[:0])
	challenge, err := edwards25519.NewScalar().SetUniformBytes(challengeDigest[:])
	if err != nil {
		return nil, fmt.Errorf("%w: challenge scalar: %w", ErrInvalidKey, err)
	}

	s := edwards25519.NewScalar().MultiplyAdd(challenge, scalar, nonce)

	signature := make([]byte, 0, ed25519.SignatureSize)
	signature = append(signature, encodedR...)
	signature = append(signature, s.Bytes()...)
	signature[63] |= publicKey[31] & 0x80
	return signature, nil
}

// EdwardsYFromMontgomeryU computes y = (u−1)/(u+1) mod p, encoded
// little-endian with the sign bit cleared.
func EdwardsYFromMontgomeryU(pub [32]byte) ([]byte, error) {
	uLE := make([]byte, 32)
	for i := range pub {
		uLE[i] = pub[31-i]
	}
	u := new(big.Int).SetBytes(uLE)

	uPlus1 := new(big.Int).Add(u, big.NewInt(1))
	uPlus1.Mod(uPlus1, p25519)
	if uPlus1.Sign() == 0 {
		return nil, fmt.Errorf("%w: montgomery u + 1 is not invertible mod p", ErrInvalidKey)
	}
	inv := new(big.Int).ModInverse(uPlus1, p25519)
	if inv == nil {
		return nil, fmt.Errorf("%w: montgomery u + 1 is not invertible mod p", ErrInvalidKey)
	}
	uMinus1 := new(big.Int).Sub(u, big.NewInt(1))
	y := new(big.Int).Mul(uMinus1, inv)
	y.Mod(y, p25519)

	be := y.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := range be {
		out[i] = be[31-i]
	}
	out[31] &= 0x7f
	return out, nil
}
