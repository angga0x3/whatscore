package signal

import (
	"errors"
	"testing"
)

func TestGenerateSignedPreKey(t *testing.T) {
	_, identity := signingKey(t)
	signed, err := GenerateSignedPreKey(7, XEdDSASigner{Private: identity.Private})
	if err != nil {
		t.Fatal(err)
	}
	if signed.ID != 7 || len(signed.Signature) != SignatureSize {
		t.Fatalf("signed prekey = %#v", signed)
	}
	if err := signed.Verify(identity.Public); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// A different identity must reject it.
	_, other := signingKey(t)
	if err := signed.Verify(other.Public); err == nil {
		t.Fatal("signature verified under the wrong identity")
	}
}

func TestGenerateSignedPreKeyErrors(t *testing.T) {
	if _, err := GenerateSignedPreKey(1, nil); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("nil signer: %v", err)
	}
	if _, err := GenerateSignedPreKey(1, XEdDSASigner{}); !errors.Is(err, ErrInvalidKey) {
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
