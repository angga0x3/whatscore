package signal

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/internal/cbc"
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
	ciphertext, err := cbc.Encrypt(keys.CipherKey[:], keys.IV[:], plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}

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

// ParseMessage decodes a SignalMessage without verifying its MAC. The
// returned message borrows wire; do not mutate it before decryption.
func ParseMessage(wire []byte) (*Message, error) {
	if len(wire) < 1+MACSize+2 {
		return nil, fmt.Errorf("%w: %d bytes", ErrInvalidMessage, len(wire))
	}
	if wire[0] != WireVersion {
		return nil, fmt.Errorf("%w: version %#x", ErrInvalidMessage, wire[0])
	}
	body := wire[:len(wire)-MACSize]
	mac := wire[len(wire)-MACSize:]

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
		Ciphertext: envelope.GetCiphertext(),
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
	plaintext, err := cbc.Decrypt(keys.CipherKey[:], keys.IV[:], m.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	return plaintext, nil
}

// DecryptMessage verifies the MAC and decrypts a SignalMessage.
func DecryptMessage(wire []byte, keys MessageKeys, sender, receiver [KeySize]byte) ([]byte, error) {
	message, err := ParseMessage(wire)
	if err != nil {
		return nil, err
	}
	return decryptParsed(message, keys, sender, receiver)
}

func decryptParsed(message *Message, keys MessageKeys, sender, receiver [KeySize]byte) ([]byte, error) {
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
	return decryptParsed(message, keys, sender, receiver)
}

func messageMAC(macKey [KeySize]byte, sender, receiver [KeySize]byte, body []byte) []byte {
	mac := hmac.New(sha256.New, macKey[:])
	var buf [1 + KeySize]byte
	buf[0] = IdentityKeyPrefix
	copy(buf[1:], sender[:])
	mac.Write(buf[:])
	copy(buf[1:], receiver[:])
	mac.Write(buf[:])
	mac.Write(body)
	return mac.Sum(nil)[:MACSize]
}

func serializedKey(key [KeySize]byte) []byte {
	out := make([]byte, 0, 1+KeySize)
	out = append(out, IdentityKeyPrefix)
	return append(out, key[:]...)
}
