package signal

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ErrNoSigner is returned when a signature is required but no Signer is set.
var ErrNoSigner = errors.New("signal: no prekey signer configured")

// Signer produces prekey signatures. Signing XEdDSA is not part of the
// standard library (ADR 0001), so the operation is injected: a caller that
// has a vetted signer supplies it, and everything else keeps working.
type Signer interface {
	// SignPreKey signs 0x05 || preKey with the identity key and returns a
	// 64-byte XEdDSA signature.
	SignPreKey(preKey [KeySize]byte) ([]byte, error)
}

// SignerFunc adapts a function to Signer.
type SignerFunc func(preKey [KeySize]byte) ([]byte, error)

// SignPreKey implements Signer.
func (f SignerFunc) SignPreKey(preKey [KeySize]byte) ([]byte, error) { return f(preKey) }

// Ed25519Signer signs with an Ed25519 private key. It is the reference
// algorithm XEdDSA verification accepts when the Edwards x coordinate is
// even; use it only where that property holds (ADR 0001 review).
type Ed25519Signer struct {
	Private ed25519.PrivateKey
}

// SignPreKey implements Signer.
func (s Ed25519Signer) SignPreKey(preKey [KeySize]byte) ([]byte, error) {
	if len(s.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: ed25519 key is %d bytes", ErrInvalidKey, len(s.Private))
	}
	message := make([]byte, 0, 1+KeySize)
	message = append(message, PublicKeyType)
	message = append(message, preKey[:]...)
	return ed25519.Sign(s.Private, message), nil
}

// GenerateSignedPreKey creates a signed prekey using signer. A nil signer
// returns ErrNoSigner.
func GenerateSignedPreKey(id uint32, signer Signer) (SignedPreKey, error) {
	if signer == nil {
		return SignedPreKey{}, ErrNoSigner
	}
	pair, err := GenerateKeyPair()
	if err != nil {
		return SignedPreKey{}, err
	}
	signature, err := signer.SignPreKey(pair.Public)
	if err != nil {
		return SignedPreKey{}, fmt.Errorf("signal: sign prekey: %w", err)
	}
	if len(signature) != SignatureSize {
		return SignedPreKey{}, fmt.Errorf("%w: signature is %d bytes", ErrBadSignature, len(signature))
	}
	return SignedPreKey{ID: id, Pair: pair, Signature: signature}, nil
}

// ParsePreKeyBundle validates a bundle and verifies its signed prekey.
func ParsePreKeyBundle(bundle PreKeyBundle) error {
	if err := VerifySignedPreKey(bundle.IdentityKey, bundle.SignedPreKey, bundle.SignedPreKeySignature); err != nil {
		return err
	}
	if bundle.OneTimePreKey == nil && bundle.OneTimePreKeyID != 0 {
		return fmt.Errorf("%w: one-time prekey id without a key", ErrInvalidBundle)
	}
	if bundle.OneTimePreKey != nil && bundle.OneTimePreKeyID == 0 {
		return fmt.Errorf("%w: one-time prekey without an id", ErrInvalidBundle)
	}
	return nil
}
