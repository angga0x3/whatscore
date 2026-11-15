package signal

import (
	"crypto/ed25519"
	"errors"
	"math/big"
	"testing"
)

var signerTestP = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

func TestGenerateSignedPreKey(t *testing.T) {
	signing, _ := signingKey(t)
	signer := Ed25519Signer{Private: signing}

	signed, err := GenerateSignedPreKey(7, signer)
	if err != nil {
		t.Fatal(err)
	}
	if signed.ID != 7 || len(signed.Signature) != SignatureSize {
		t.Fatalf("signed prekey = %#v", signed)
	}
	// The signature must verify under the matching Montgomery identity, which
	// is derived from the same Ed25519 seed.
	identity := montgomeryFromEd25519(t, signing.Seed())
	if err := signed.Verify(identity); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestGenerateSignedPreKeyErrors(t *testing.T) {
	if _, err := GenerateSignedPreKey(1, nil); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("nil signer: %v", err)
	}
	if _, err := GenerateSignedPreKey(1, Ed25519Signer{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("empty key: %v", err)
	}
	if _, err := GenerateSignedPreKey(1, SignerFunc(func([32]byte) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	})); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("short signature: %v", err)
	}
	sentinel := errors.New("hsm down")
	if _, err := GenerateSignedPreKey(1, SignerFunc(func([32]byte) ([]byte, error) {
		return nil, sentinel
	})); !errors.Is(err, sentinel) {
		t.Fatalf("signer error: %v", err)
	}
}

func TestParsePreKeyBundle(t *testing.T) {
	_, bob := signingKey(t)
	signed := fixedKey(t, 0x21)
	valid := PreKeyBundle{
		IdentityKey:           bob.Public,
		SignedPreKey:          signed.Public,
		SignedPreKeySignature: make([]byte, SignatureSize),
	}
	if err := ParsePreKeyBundle(valid); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("zero signature: %v", err)
	}

	oneTime := fixedKey(t, 0x31)
	valid.OneTimePreKey = &oneTime.Public
	valid.OneTimePreKeyID = 3
	// Still fails on the signature, which is checked first.
	if err := ParsePreKeyBundle(valid); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want signature error first, got %v", err)
	}
}

// montgomeryFromEd25519 maps an Ed25519 seed's public point to the Curve25519
// u coordinate used by the identity key.
func montgomeryFromEd25519(tb testing.TB, seed []byte) [32]byte {
	tb.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	yb := make([]byte, 32)
	for i := range pub {
		yb[i] = pub[31-i]
	}
	yb[0] &= 0x7f
	y := new(big.Int).SetBytes(yb)
	one := big.NewInt(1)
	denom := new(big.Int).Sub(one, y)
	denom.Mod(denom, signerTestP)
	inv := new(big.Int).ModInverse(denom, signerTestP)
	if inv == nil {
		tb.Fatal("y == 1 has no curve25519 image")
	}
	u := new(big.Int).Mul(new(big.Int).Add(one, y), inv)
	u.Mod(u, signerTestP)
	be := u.FillBytes(make([]byte, 32))
	var out [32]byte
	for i := range be {
		out[i] = be[31-i]
	}
	return out
}
