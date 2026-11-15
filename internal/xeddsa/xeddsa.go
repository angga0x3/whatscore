// Package xeddsa verifies XEdDSA signatures (Curve25519 keys, Ed25519
// signatures) by mapping the Montgomery public key to its Edwards form.
package xeddsa

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
)

var p25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// Verify checks a 64-byte XEdDSA signature over msg with a Montgomery u
// public key. The Edwards sign bit is assumed clear, matching the server
// keys these signatures use.
func Verify(pub [32]byte, msg, sig []byte) error {
	y, err := EdwardsYFromMontgomeryU(pub)
	if err != nil {
		return err
	}
	if ed25519.Verify(ed25519.PublicKey(y), msg, sig) {
		return nil
	}
	// XEdDSA signatures can use either Edwards sign; Montgomery keys do not
	// carry it. Try the negated point before rejecting.
	negated := append([]byte(nil), y...)
	negated[31] |= 0x80
	if ed25519.Verify(ed25519.PublicKey(negated), msg, sig) {
		return nil
	}
	return fmt.Errorf("xeddsa: signature verification failed")
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
		return nil, fmt.Errorf("xeddsa: montgomery u + 1 is not invertible mod p")
	}
	inv := new(big.Int).ModInverse(uPlus1, p25519)
	if inv == nil {
		return nil, fmt.Errorf("xeddsa: montgomery u + 1 is not invertible mod p")
	}

	uMinus1 := new(big.Int).Sub(u, big.NewInt(1))
	y := new(big.Int).Mul(uMinus1, inv)
	y.Mod(y, p25519)

	be := y.FillBytes(make([]byte, 32))
	yBytes := make([]byte, 32)
	for i := range be {
		yBytes[i] = be[31-i]
	}
	yBytes[31] &= 0x7f
	return yBytes, nil
}
