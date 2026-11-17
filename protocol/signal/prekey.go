package signal

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// PreKey is a one-time prekey.
type PreKey struct {
	ID   uint32
	Pair KeyPair
}

// GeneratePreKey returns a fresh one-time prekey.
func GeneratePreKey(id uint32) (PreKey, error) {
	pair, err := GenerateKeyPair()
	if err != nil {
		return PreKey{}, err
	}
	return PreKey{ID: id, Pair: pair}, nil
}

// SignedPreKey is a prekey signed by the identity key. Creating the signature
// is blocked by ADR 0001; this type carries an externally produced signature.
type SignedPreKey struct {
	ID        uint32
	Pair      KeyPair
	Signature []byte
}

// Verify checks the identity signature over the signed prekey.
func (s SignedPreKey) Verify(identity [KeySize]byte) error {
	return VerifySignedPreKey(identity, s.Pair.Public, s.Signature)
}

// PreKeyMessage is the first message of a session (PF-063).
type PreKeyMessage struct {
	Version        byte
	RegistrationID uint32
	PreKeyID       uint32
	SignedPreKeyID uint32
	BaseKey        [KeySize]byte
	IdentityKey    [KeySize]byte
	Message        []byte
}

// BuildPreKeyMessage serializes version || protobuf (no separate MAC; the
// embedded SignalMessage carries its own).
func BuildPreKeyMessage(message PreKeyMessage) ([]byte, error) {
	if message.Version == 0 {
		message.Version = Version
	}
	if message.Version != Version {
		return nil, fmt.Errorf("%w: version %d", ErrInvalidMessage, message.Version)
	}
	if len(message.Message) == 0 {
		return nil, fmt.Errorf("%w: empty embedded message", ErrInvalidMessage)
	}

	registrationID, signedPreKeyID := message.RegistrationID, message.SignedPreKeyID
	envelope := &protobuf.PreKeySignalMessage{
		RegistrationId: &registrationID,
		SignedPreKeyId: &signedPreKeyID,
		BaseKey:        serializedKey(message.BaseKey),
		IdentityKey:    serializedKey(message.IdentityKey),
		Message:        message.Message,
	}
	if message.PreKeyID != 0 {
		preKeyID := message.PreKeyID
		envelope.PreKeyId = &preKeyID
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal: %w", ErrInvalidMessage, err)
	}
	return append([]byte{WireVersion}, payload...), nil
}

// ParsePreKeyMessage decodes a PreKeySignalMessage.
func ParsePreKeyMessage(wire []byte) (*PreKeyMessage, error) {
	if len(wire) < 2 {
		return nil, fmt.Errorf("%w: %d bytes", ErrInvalidMessage, len(wire))
	}
	if wire[0] != WireVersion {
		return nil, fmt.Errorf("%w: version %#x", ErrInvalidMessage, wire[0])
	}
	var envelope protobuf.PreKeySignalMessage
	if err := proto.Unmarshal(wire[1:], &envelope); err != nil {
		return nil, fmt.Errorf("%w: unmarshal: %w", ErrInvalidMessage, err)
	}
	if envelope.RegistrationId == nil || envelope.SignedPreKeyId == nil {
		return nil, fmt.Errorf("%w: missing prekey ids", ErrInvalidMessage)
	}
	message := &PreKeyMessage{
		Version:        Version,
		RegistrationID: envelope.GetRegistrationId(),
		SignedPreKeyID: envelope.GetSignedPreKeyId(),
		PreKeyID:       envelope.GetPreKeyId(),
		Message:        append([]byte(nil), envelope.GetMessage()...),
	}
	if len(envelope.GetBaseKey()) != 1+KeySize || envelope.GetBaseKey()[0] != IdentityKeyPrefix {
		return nil, fmt.Errorf("%w: bad base key", ErrInvalidMessage)
	}
	if len(envelope.GetIdentityKey()) != 1+KeySize || envelope.GetIdentityKey()[0] != IdentityKeyPrefix {
		return nil, fmt.Errorf("%w: bad identity key", ErrInvalidMessage)
	}
	if len(message.Message) == 0 {
		return nil, fmt.Errorf("%w: empty embedded message", ErrInvalidMessage)
	}
	copy(message.BaseKey[:], envelope.GetBaseKey()[1:])
	copy(message.IdentityKey[:], envelope.GetIdentityKey()[1:])
	return message, nil
}

// BuildPreKeyMessage wraps the first encrypted message for a new session.
func (r *InitiatorResult) BuildPreKeyMessage(senderIdentity [KeySize]byte, registrationID uint32, signalMessage []byte) ([]byte, error) {
	message := PreKeyMessage{
		Version:        Version,
		RegistrationID: registrationID,
		SignedPreKeyID: r.SignedPreKeyID,
		BaseKey:        r.EphemeralPublic,
		IdentityKey:    senderIdentity,
		Message:        signalMessage,
	}
	if r.HasOneTimePreKey {
		message.PreKeyID = r.OneTimePreKeyID
	}
	return BuildPreKeyMessage(message)
}

// AcceptPreKeyMessage bootstraps the responder session from a
// PreKeySignalMessage and decrypts its embedded first message (PF-064).
func AcceptPreKeyMessage(wire []byte, ourIdentity KeyPair, signedPreKey SignedPreKey, oneTime *PreKey) (*State, []byte, error) {
	message, err := ParsePreKeyMessage(wire)
	if err != nil {
		return nil, nil, err
	}
	if message.SignedPreKeyID != signedPreKey.ID {
		return nil, nil, fmt.Errorf("%w: signed prekey id %d, have %d", ErrInvalidMessage, message.SignedPreKeyID, signedPreKey.ID)
	}
	if message.PreKeyID != 0 {
		if oneTime == nil || oneTime.ID != message.PreKeyID {
			return nil, nil, fmt.Errorf("%w: missing one-time prekey %d", ErrInvalidMessage, message.PreKeyID)
		}
	} else if oneTime != nil {
		return nil, nil, fmt.Errorf("%w: unexpected one-time prekey", ErrInvalidMessage)
	}

	var oneTimePair *KeyPair
	if oneTime != nil {
		oneTimePair = &oneTime.Pair
	}
	keys, err := Respond(ourIdentity, signedPreKey.Pair, oneTimePair, message.IdentityKey, message.BaseKey)
	if err != nil {
		return nil, nil, err
	}
	state := NewResponder(keys.RootKey, signedPreKey.Pair, keys.ChainKey)
	plaintext, err := state.Decrypt(message.Message, message.IdentityKey, ourIdentity.Public)
	if err != nil {
		return nil, nil, err
	}
	state.bootstrapBase = &message.BaseKey
	return state, plaintext, nil
}
