// Package xeddsa signs and verifies XEdDSA signatures: Ed25519 signatures
// under a Curve25519 (Montgomery) key.
//
// Verification is a pure public-key operation. Signing keeps a clamped
// Curve25519 scalar and produces an Ed25519 signature on the birationally
// equivalent Edwards point. This is exactly what libsignal's Curve25519
// signing does, and it is why an X25519 key can authenticate messages without
// a separate Ed25519 key.
//
// Signing is deliberately absent: XEdDSA's signing construction differs from
// RFC 8032 in its nonce input and in how the sign bit is carried, so an
// implementation that verifies locally can still be rejected by the real
// service. See docs/protocol/signal.md (PF-067) and ADR 0001.
package xeddsa

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
)

var p25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// ErrInvalidSignature is returned when verification fails.
var ErrInvalidSignature = errors.New("xeddsa: signature verification failed")

// ErrInvalidKey is returned for unusable key material.
var ErrInvalidKey = errors.New("xeddsa: invalid key")

// Verify checks a 64-byte XEdDSA signature over msg with a Montgomery u public
// key. Either Edwards sign is accepted, because a Montgomery coordinate does
// not carry the sign bit.
func Verify(pub [32]byte, msg, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes", ErrInvalidSignature, len(sig))
	}
	candidates, err := candidatePoints(pub)
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		if ed25519.Verify(ed25519.PublicKey(candidate), msg, sig) {
			return nil
		}
	}
	return ErrInvalidSignature
}

// candidatePoints returns the Edwards encodings that could correspond to a
// Montgomery u coordinate: y with the sign bit clear, and its negation.
func candidatePoints(pub [32]byte) ([][]byte, error) {
	y, err := EdwardsYFromMontgomeryU(pub)
	if err != nil {
		return nil, err
	}
	negated := append([]byte(nil), y...)
	negated[31] |= 0x80
	return [][]byte{y, negated}, nil
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
