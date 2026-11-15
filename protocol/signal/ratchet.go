package signal

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

const (
	// RatchetInfo is the root-ratchet HKDF info (PF-054).
	RatchetInfo = "WhisperRatchet"
	// MessageKeysInfo is the message-key HKDF info (PF-056).
	MessageKeysInfo = "WhisperMessageKeys"
	// MessageKeysSize is cipher key + MAC key + IV.
	MessageKeysSize  = 32 + 32 + 16
	chainSeedMessage = 0x01
	chainSeedNext    = 0x02
)

// RootKey is the Double Ratchet root key.
type RootKey [KeySize]byte

// ChainKey is one direction's chain key.
type ChainKey [KeySize]byte

// MessageKeys are the keys for one message.
type MessageKeys struct {
	CipherKey [KeySize]byte
	MACKey    [KeySize]byte
	IV        [16]byte
	Index     uint32
}

// CreateChain performs one DH ratchet step (PF-054):
//
//	(chainKey, nextRootKey) = HKDF-SHA256(
//	    ikm=X25519(ourRatchetPriv, theirRatchetPub), salt=rootKey,
//	    info="WhisperRatchet", L=64)
func (r RootKey) CreateChain(ourPriv, theirPub [KeySize]byte) (RootKey, ChainKey, error) {
	secret, err := dh(ourPriv, theirPub)
	if err != nil {
		return RootKey{}, ChainKey{}, fmt.Errorf("signal: ratchet dh: %w", err)
	}
	raw, err := hkdf.Key(sha256.New, secret[:], r[:], RatchetInfo, DerivedKeySize)
	if err != nil {
		return RootKey{}, ChainKey{}, fmt.Errorf("%w: ratchet hkdf: %w", ErrInvalidKey, err)
	}
	var next RootKey
	var chain ChainKey
	copy(next[:], raw[:KeySize])
	copy(chain[:], raw[KeySize:])
	return next, chain, nil
}

// MessageKey returns HMAC-SHA256(chainKey, 0x01) (PF-055).
func (c ChainKey) MessageKey() [KeySize]byte {
	return chainMAC(c, chainSeedMessage)
}

// Next returns HMAC-SHA256(chainKey, 0x02) (PF-055).
func (c ChainKey) Next() ChainKey {
	return ChainKey(chainMAC(c, chainSeedNext))
}

// DeriveMessageKeys expands a message key into cipher key, MAC key, and IV
// (PF-056):
//
//	HKDF-SHA256(ikm=messageKey, salt=nil, info="WhisperMessageKeys", L=80)
func DeriveMessageKeys(messageKey [KeySize]byte, index uint32) (MessageKeys, error) {
	raw, err := hkdf.Key(sha256.New, messageKey[:], nil, MessageKeysInfo, MessageKeysSize)
	if err != nil {
		return MessageKeys{}, fmt.Errorf("%w: message keys: %w", ErrInvalidKey, err)
	}
	var keys MessageKeys
	copy(keys.CipherKey[:], raw[:KeySize])
	copy(keys.MACKey[:], raw[KeySize:2*KeySize])
	copy(keys.IV[:], raw[2*KeySize:])
	keys.Index = index
	return keys, nil
}

func chainMAC(key ChainKey, seed byte) [KeySize]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte{seed})
	var out [KeySize]byte
	copy(out[:], mac.Sum(nil))
	return out
}
