package signal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

const (
	// Version is the Signal protocol version.
	Version = 3
	// WireVersion is the version byte preceding a SignalMessage.
	WireVersion = 0x33
	// MACSize is the truncated SignalMessage MAC length (PF-061).
	MACSize = 8
	// IdentityKeyPrefix is the serialized identity key type byte.
	IdentityKeyPrefix = 0x05
)

var (
	// ErrInvalidMessage is returned for malformed SignalMessage bytes.
	ErrInvalidMessage = errors.New("signal: invalid message")
	// ErrBadMAC is returned when the message MAC does not verify.
	ErrBadMAC = errors.New("signal: bad message MAC")
)

// Message is a parsed SignalMessage (PF-060).
type Message struct {
	Version    byte
	Header     Header
	Ciphertext []byte
	MAC        []byte

	body []byte
}

// EncryptMessage builds a SignalMessage for one plaintext and header
// (PF-060..PF-062).
func EncryptMessage(keys MessageKeys, header Header, plaintext []byte, sender, receiver [KeySize]byte) ([]byte, error) {
	block, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		return nil, fmt.Errorf("signal: cipher: %w", err)
	}
	padded := pad(plaintext)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, keys.IV[:]).CryptBlocks(ciphertext, padded)

	counter, previous := header.MessageNumber, header.PreviousChainLength
	envelope := &protobuf.WhisperMessage{
		RatchetKey:      serializedKey(header.RatchetKey),
		Counter:         &counter,
		PreviousCounter: &previous,
		Ciphertext:      ciphertext,
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal: %w", ErrInvalidMessage, err)
	}

	body := make([]byte, 0, 1+len(payload))
	body = append(body, WireVersion)
	body = append(body, payload...)
	mac := messageMAC(keys.MACKey, sender, receiver, body)
	wire := append(body, mac...)
	return wire, nil
}

// ParseMessage decodes a SignalMessage without verifying its MAC.
func ParseMessage(wire []byte) (*Message, error) {
	if len(wire) < 1+MACSize+2 {
		return nil, fmt.Errorf("%w: %d bytes", ErrInvalidMessage, len(wire))
	}
	if wire[0] != WireVersion {
		return nil, fmt.Errorf("%w: version %#x", ErrInvalidMessage, wire[0])
	}
	body := append([]byte(nil), wire[:len(wire)-MACSize]...)
	mac := append([]byte(nil), wire[len(wire)-MACSize:]...)

	var envelope protobuf.WhisperMessage
	if err := proto.Unmarshal(body[1:], &envelope); err != nil {
		return nil, fmt.Errorf("%w: unmarshal: %w", ErrInvalidMessage, err)
	}
	if len(envelope.GetRatchetKey()) != 1+KeySize || envelope.GetRatchetKey()[0] != IdentityKeyPrefix {
		return nil, fmt.Errorf("%w: bad ratchet key", ErrInvalidMessage)
	}
	if envelope.Counter == nil || envelope.PreviousCounter == nil || len(envelope.GetCiphertext()) == 0 {
		return nil, fmt.Errorf("%w: missing fields", ErrInvalidMessage)
	}

	message := &Message{
		Version:    Version,
		Ciphertext: append([]byte(nil), envelope.GetCiphertext()...),
		MAC:        mac,
		body:       body,
	}
	copy(message.Header.RatchetKey[:], envelope.GetRatchetKey()[1:])
	message.Header.MessageNumber = envelope.GetCounter()
	message.Header.PreviousChainLength = envelope.GetPreviousCounter()
	return message, nil
}

// VerifyMAC checks the truncated MAC over both identities and the body.
func (m *Message) VerifyMAC(keys MessageKeys, sender, receiver [KeySize]byte) error {
	if !hmac.Equal(messageMAC(keys.MACKey, sender, receiver, m.body), m.MAC) {
		return ErrBadMAC
	}
	return nil
}

// DecryptPayload decrypts the ciphertext with the message keys.
func (m *Message) DecryptPayload(keys MessageKeys) ([]byte, error) {
	block, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		return nil, fmt.Errorf("signal: cipher: %w", err)
	}
	if len(m.Ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext length %d", ErrInvalidMessage, len(m.Ciphertext))
	}
	plaintext := make([]byte, len(m.Ciphertext))
	cipher.NewCBCDecrypter(block, keys.IV[:]).CryptBlocks(plaintext, m.Ciphertext)
	return unpad(plaintext)
}

// DecryptMessage verifies the MAC and decrypts a SignalMessage.
func DecryptMessage(wire []byte, keys MessageKeys, sender, receiver [KeySize]byte) ([]byte, error) {
	message, err := ParseMessage(wire)
	if err != nil {
		return nil, err
	}
	if err := message.VerifyMAC(keys, sender, receiver); err != nil {
		return nil, err
	}
	return message.DecryptPayload(keys)
}

// Encrypt writes one encrypted message using the next sending-chain keys.
func (s *State) Encrypt(plaintext []byte, sender, receiver [KeySize]byte) ([]byte, error) {
	header, keys, err := s.NextOutbound()
	if err != nil {
		return nil, err
	}
	return EncryptMessage(keys, header, plaintext, sender, receiver)
}

// Decrypt parses the header, resolves the ratchet keys, verifies the MAC,
// and decrypts the payload.
func (s *State) Decrypt(wire []byte, sender, receiver [KeySize]byte) ([]byte, error) {
	message, err := ParseMessage(wire)
	if err != nil {
		return nil, err
	}
	keys, err := s.Receive(message.Header)
	if err != nil {
		return nil, err
	}
	if err := message.VerifyMAC(keys, sender, receiver); err != nil {
		return nil, err
	}
	return message.DecryptPayload(keys)
}

func messageMAC(macKey [KeySize]byte, sender, receiver [KeySize]byte, body []byte) []byte {
	mac := hmac.New(sha256.New, macKey[:])
	mac.Write(serializedKey(sender))
	mac.Write(serializedKey(receiver))
	mac.Write(body)
	return mac.Sum(nil)[:MACSize]
}

func serializedKey(key [KeySize]byte) []byte {
	out := make([]byte, 0, 1+KeySize)
	out = append(out, IdentityKeyPrefix)
	return append(out, key[:]...)
}

func pad(plaintext []byte) []byte {
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	out := make([]byte, len(plaintext)+padding)
	copy(out, plaintext)
	for i := len(plaintext); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out
}

func unpad(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: padded length %d", ErrInvalidMessage, len(plaintext))
	}
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > aes.BlockSize {
		return nil, fmt.Errorf("%w: padding length %d", ErrInvalidMessage, padding)
	}
	for _, b := range plaintext[len(plaintext)-padding:] {
		if int(b) != padding {
			return nil, fmt.Errorf("%w: inconsistent padding", ErrInvalidMessage)
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}
