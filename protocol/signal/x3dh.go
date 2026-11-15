// Package signal implements the Signal-style session establishment used by
// WhatsApp: X3DH key agreement over Curve25519 with HKDF-SHA256
// ("WhisperText", 64 bytes -> root key + chain key).
//
// The Double Ratchet and message encryption are not implemented yet. Findings
// are recorded in docs/protocol/signal.md (PF-050..PF-053) and pinned by the
// independent vectors in tests/fixtures/signal_vectors.json.
package signal

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/angga0x3/whatscore/internal/xeddsa"
)

const (
	// KeySize is the Curve25519 key length.
	KeySize = 32
	// DerivedKeySize is the X3DH output: root key plus chain key.
	DerivedKeySize = 64
	// KDFInfo is the X3DH HKDF info string (PF-051).
	KDFInfo = "WhisperText"
	// PublicKeyType is the libsignal curve type byte signed with a prekey.
	PublicKeyType = 0x05
	// SignatureSize is the XEdDSA signature length.
	SignatureSize = 64
)

var (
	// ErrInvalidKey is returned for unusable key material or DH output.
	ErrInvalidKey = errors.New("signal: invalid key")
	// ErrInvalidBundle is returned for an inconsistent prekey bundle.
	ErrInvalidBundle = errors.New("signal: invalid prekey bundle")
	// ErrBadSignature is returned when the signed prekey does not verify.
	ErrBadSignature = errors.New("signal: bad signed prekey signature")
)

// KeyPair is a Curve25519 key pair.
type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// GenerateKeyPair returns a fresh clamped Curve25519 key pair.
func GenerateKeyPair() (KeyPair, error) {
	var pair KeyPair
	if _, err := rand.Read(pair.Private[:]); err != nil {
		return KeyPair{}, fmt.Errorf("signal: key material: %w", err)
	}
	clamp(&pair.Private)
	pub, err := curve25519.X25519(pair.Private[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("%w: derive public key: %w", ErrInvalidKey, err)
	}
	copy(pair.Public[:], pub)
	return pair, nil
}

// PreKeyBundle is the remote device's published key material.
type PreKeyBundle struct {
	IdentityKey           [KeySize]byte
	SignedPreKeyID        uint32
	SignedPreKey          [KeySize]byte
	SignedPreKeySignature []byte
	OneTimePreKeyID       uint32
	OneTimePreKey         *[KeySize]byte
}

// InitialKeys is the X3DH output.
type InitialKeys struct {
	RootKey  [KeySize]byte
	ChainKey [KeySize]byte
}

// InitiatorResult carries the initiator's derived keys and the keys that must
// be sent to the responder.
type InitiatorResult struct {
	Keys             InitialKeys
	EphemeralPublic  [KeySize]byte
	SignedPreKeyID   uint32
	OneTimePreKeyID  uint32
	HasOneTimePreKey bool
}

// VerifySignedPreKey checks the XEdDSA signature over 0x05 || signedPreKey
// under identityKey (PF-053).
func VerifySignedPreKey(identityKey, signedPreKey [KeySize]byte, signature []byte) error {
	if len(signature) != SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d", ErrBadSignature, len(signature), SignatureSize)
	}
	message := make([]byte, 0, 1+KeySize)
	message = append(message, PublicKeyType)
	message = append(message, signedPreKey[:]...)
	if err := xeddsa.Verify(identityKey, message, signature); err != nil {
		return fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	return nil
}

// Initiate runs the X3DH initiator side over a verified bundle.
func Initiate(identity KeyPair, bundle PreKeyBundle) (*InitiatorResult, error) {
	if len(bundle.SignedPreKeySignature) != SignatureSize {
		return nil, fmt.Errorf("%w: missing signed prekey signature", ErrInvalidBundle)
	}
	if err := VerifySignedPreKey(bundle.IdentityKey, bundle.SignedPreKey, bundle.SignedPreKeySignature); err != nil {
		return nil, err
	}
	ephemeral, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	dh1, err := dh(identity.Private, bundle.SignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("signal: DH1: %w", err)
	}
	dh2, err := dh(ephemeral.Private, bundle.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("signal: DH2: %w", err)
	}
	dh3, err := dh(ephemeral.Private, bundle.SignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("signal: DH3: %w", err)
	}

	master := masterSecret(dh1, dh2, dh3)
	hasOneTime := bundle.OneTimePreKey != nil
	if hasOneTime {
		dh4, err := dh(ephemeral.Private, *bundle.OneTimePreKey)
		if err != nil {
			return nil, fmt.Errorf("signal: DH4: %w", err)
		}
		master = append(master, dh4[:]...)
	}
	keys, err := deriveKeys(master)
	if err != nil {
		return nil, err
	}
	return &InitiatorResult{
		Keys:             keys,
		EphemeralPublic:  ephemeral.Public,
		SignedPreKeyID:   bundle.SignedPreKeyID,
		OneTimePreKeyID:  bundle.OneTimePreKeyID,
		HasOneTimePreKey: hasOneTime,
	}, nil
}

// Respond runs the X3DH responder side with the private prekeys.
func Respond(identity, signedPreKey KeyPair, oneTime *KeyPair, initiatorIdentity, initiatorEphemeral [KeySize]byte) (InitialKeys, error) {
	dh1, err := dh(signedPreKey.Private, initiatorIdentity)
	if err != nil {
		return InitialKeys{}, fmt.Errorf("signal: DH1: %w", err)
	}
	dh2, err := dh(identity.Private, initiatorEphemeral)
	if err != nil {
		return InitialKeys{}, fmt.Errorf("signal: DH2: %w", err)
	}
	dh3, err := dh(signedPreKey.Private, initiatorEphemeral)
	if err != nil {
		return InitialKeys{}, fmt.Errorf("signal: DH3: %w", err)
	}
	master := masterSecret(dh1, dh2, dh3)
	if oneTime != nil {
		dh4, err := dh(oneTime.Private, initiatorEphemeral)
		if err != nil {
			return InitialKeys{}, fmt.Errorf("signal: DH4: %w", err)
		}
		master = append(master, dh4[:]...)
	}
	return deriveKeys(master)
}

func masterSecret(dhs ...[KeySize]byte) []byte {
	out := make([]byte, 0, (1+len(dhs))*KeySize)
	for i := 0; i < KeySize; i++ {
		out = append(out, 0xFF) // discontinuity (PF-050)
	}
	for _, secret := range dhs {
		out = append(out, secret[:]...)
	}
	return out
}

func deriveKeys(master []byte) (InitialKeys, error) {
	raw, err := hkdf.Key(sha256.New, master, nil, KDFInfo, DerivedKeySize)
	if err != nil {
		return InitialKeys{}, fmt.Errorf("%w: hkdf: %w", ErrInvalidKey, err)
	}
	var keys InitialKeys
	copy(keys.RootKey[:], raw[:KeySize])
	copy(keys.ChainKey[:], raw[KeySize:DerivedKeySize])
	return keys, nil
}

func dh(private, public [KeySize]byte) ([KeySize]byte, error) {
	secret, err := curve25519.X25519(private[:], public[:])
	if err != nil {
		return [KeySize]byte{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	var out [KeySize]byte
	copy(out[:], secret)
	return out, nil
}

func clamp(key *[KeySize]byte) {
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
}
