package xeddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"testing"
)

var testP = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

func testKey(t *testing.T, odd bool) (ed25519.PrivateKey, [32]byte) {
	t.Helper()
	for attempt := 0; attempt < 1000; attempt++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if (pub[31]>>7 == 1) != odd {
			continue
		}
		yb := make([]byte, 32)
		for i := range pub {
			yb[i] = pub[31-i]
		}
		yb[0] &= 0x7f
		y := new(big.Int).SetBytes(yb)
		denom := new(big.Int).Sub(big.NewInt(1), y)
		denom.Mod(denom, testP)
		inv := new(big.Int).ModInverse(denom, testP)
		if inv == nil {
			continue
		}
		u := new(big.Int).Mul(new(big.Int).Add(big.NewInt(1), y), inv)
		u.Mod(u, testP)
		be := u.FillBytes(make([]byte, 32))
		var mont [32]byte
		for i := range be {
			mont[i] = be[31-i]
		}
		return priv, mont
	}
	t.Fatal("could not generate key")
	return nil, [32]byte{}
}

func TestVerifyBothSignBits(t *testing.T) {
	for _, odd := range []bool{false, true} {
		priv, mont := testKey(t, odd)
		msg := []byte("signed prekey")
		sig := ed25519.Sign(priv, msg)
		if err := Verify(mont, msg, sig); err != nil {
			t.Fatalf("odd=%v: %v", odd, err)
		}
		if err := Verify(mont, []byte("tampered"), sig); err == nil {
			t.Fatalf("odd=%v: tampered message accepted", odd)
		}
	}
}
