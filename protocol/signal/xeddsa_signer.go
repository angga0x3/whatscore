package signal

import (
	"crypto/rand"
	"fmt"

	"github.com/angga0x3/whatscore/internal/xeddsa"
)

// XEdDSASigner signs with the XEdDSA construction (PF-067), which is what
// libsignal uses for signed prekeys and device identities. Prefer it over
// Ed25519Signer: an Ed25519 signature only verifies here when the key's Edwards
// x happens to be even, whereas XEdDSA carries the sign bit in the signature.
type XEdDSASigner struct {
	// Private is the clamped Curve25519 scalar, i.e. the identity key's
	// private half.
	Private [KeySize]byte
}

// SignPreKey implements Signer.
func (s XEdDSASigner) SignPreKey(preKey [KeySize]byte) ([]byte, error) {
	message := make([]byte, 0, 1+KeySize)
	message = append(message, PublicKeyType)
	message = append(message, preKey[:]...)
	return s.sign(message)
}

// SignDeviceIdentity signs the PF-017 device-identity message:
// 0x06,0x01 ‖ details ‖ identityPub ‖ accountSignatureKey.
func (s XEdDSASigner) SignDeviceIdentity(details, identityPub, accountSignatureKey []byte) ([]byte, error) {
	if len(identityPub) != KeySize || len(accountSignatureKey) != KeySize {
		return nil, fmt.Errorf("%w: identity or account key is not %d bytes", ErrInvalidKey, KeySize)
	}
	message := make([]byte, 0, 2+len(details)+2*KeySize)
	message = append(message, DeviceSignaturePrefix...)
	message = append(message, details...)
	message = append(message, identityPub...)
	message = append(message, accountSignatureKey...)
	return s.sign(message)
}

func (s XEdDSASigner) sign(message []byte) ([]byte, error) {
	if s.Private == ([KeySize]byte{}) {
		return nil, fmt.Errorf("%w: zero signing scalar", ErrInvalidKey)
	}
	randomness := make([]byte, 64)
	if _, err := rand.Read(randomness); err != nil {
		return nil, fmt.Errorf("signal: xeddsa randomness: %w", err)
	}
	signature, err := xeddsa.Sign(s.Private, message, randomness)
	if err != nil {
		return nil, fmt.Errorf("signal: xeddsa sign: %w", err)
	}
	return signature, nil
}

// DeviceSignaturePrefix is the PF-017 prefix of the device-identity message.
var DeviceSignaturePrefix = []byte{0x06, 0x01}
