package signal

import (
	"errors"
	"fmt"
)

// ErrNoSigner is returned when a signature is required but no Signer is set.
var ErrNoSigner = errors.New("signal: no prekey signer configured")

// Signer produces prekey signatures. The operation is injected so the engine
// does not depend on one implementation; XEdDSASigner is the one that matches
// the reference construction (PF-067).
type Signer interface {
	// SignPreKey signs 0x05 || preKey with the identity key and returns a
	// 64-byte XEdDSA signature.
	SignPreKey(preKey [KeySize]byte) ([]byte, error)
}

// SignerFunc adapts a function to Signer.
type SignerFunc func(preKey [KeySize]byte) ([]byte, error)

// SignPreKey implements Signer.
func (f SignerFunc) SignPreKey(preKey [KeySize]byte) ([]byte, error) { return f(preKey) }

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
