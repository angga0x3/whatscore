package libsignalstore

// Session helpers: create libsignal key material from our existing key data.

import (
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/state/record"
	"golang.org/x/crypto/curve25519"
)

// NewIdentityKeyPair creates a libsignal identity key pair from raw bytes.
func NewIdentityKeyPair(privateBytes [32]byte) *identity.KeyPair {
	priv := ecc.NewDjbECPrivateKey(privateBytes)
	pub := priv.PublicKey()
	return identity.NewKeyPair(identity.NewKey(pub), priv)
}

// NewSessionRecord creates an empty session record.
func NewSessionRecord() *record.Session {
	return record.NewSession(nil, nil)
}

// NewPreKeyRecord creates a prekey record from a key pair.
func NewPreKeyRecord(id uint32, priv [32]byte) *record.PreKey {
	keyPair := ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(publicFromPrivate(priv)),
		ecc.NewDjbECPrivateKey(priv),
	)
	return record.NewPreKey(id, keyPair)
}

// NewSignedPreKeyRecord creates a signed prekey record.
func NewSignedPreKeyRecord(id uint32, priv [32]byte, signature []byte) *record.SignedPreKeyRecord {
	keyPair := ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(publicFromPrivate(priv)),
		ecc.NewDjbECPrivateKey(priv),
	)
	return record.NewSignedPreKey(id, keyPair, signature)
}

func publicFromPrivate(priv [32]byte) [32]byte {
	// Curve25519 basepoint multiplication
	var base [32]byte
	base[31] = 9
	out, _ := curve25519.X25519(priv[:], base[:])
	var outSlice, outFixed = []byte{}, [32]byte
	copy(outFixed[:], out)
	return outFixed
}
