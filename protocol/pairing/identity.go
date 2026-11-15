package pairing

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/internal/xeddsa"
	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// ErrInvalidDeviceIdentity is returned when the pair-success identity
// container fails authentication or is malformed.
var ErrInvalidDeviceIdentity = errors.New("pairing: invalid device identity")

var (
	accountSignaturePrefix       = []byte{6, 0}
	hostedAccountSignaturePrefix = []byte{6, 5}
)

// DeviceIdentity is a verified ADVSignedDeviceIdentity (PF-017).
type DeviceIdentity struct {
	RawID            uint32
	Timestamp        uint64
	KeyIndex         uint32
	AccountType      protobuf.ADVEncryptionType
	DeviceType       protobuf.ADVEncryptionType
	Details          []byte
	AccountKey       []byte
	AccountSignature []byte
	DeviceSignature  []byte
}

// VerifyDeviceIdentity authenticates the device-identity container from a
// pair-success stanza: HMAC-SHA256 with the adv secret, then the account
// XEdDSA signature over prefix || details || identityPub.
func VerifyDeviceIdentity(container, advSecret, identityPub []byte) (*DeviceIdentity, error) {
	if len(advSecret) != 32 {
		return nil, fmt.Errorf("%w: adv secret is %d bytes, want 32", ErrInvalidDeviceIdentity, len(advSecret))
	}
	if len(identityPub) != 32 {
		return nil, fmt.Errorf("%w: identity key is %d bytes, want 32", ErrInvalidDeviceIdentity, len(identityPub))
	}

	var outer protobuf.ADVSignedDeviceIdentityHMAC
	if err := proto.Unmarshal(container, &outer); err != nil {
		return nil, fmt.Errorf("%w: container: %w", ErrInvalidDeviceIdentity, err)
	}
	details := outer.GetDetails()
	if len(details) == 0 {
		return nil, fmt.Errorf("%w: empty details", ErrInvalidDeviceIdentity)
	}
	if len(outer.GetHMAC()) != sha256.Size {
		return nil, fmt.Errorf("%w: hmac is %d bytes, want %d", ErrInvalidDeviceIdentity, len(outer.GetHMAC()), sha256.Size)
	}

	mac := hmac.New(sha256.New, advSecret)
	if outer.GetAccountType() == protobuf.ADVEncryptionType_HOSTED {
		mac.Write(hostedAccountSignaturePrefix)
	}
	mac.Write(details)
	if !hmac.Equal(mac.Sum(nil), outer.GetHMAC()) {
		return nil, fmt.Errorf("%w: hmac mismatch", ErrInvalidDeviceIdentity)
	}

	var signed protobuf.ADVSignedDeviceIdentity
	if err := proto.Unmarshal(details, &signed); err != nil {
		return nil, fmt.Errorf("%w: signed identity: %w", ErrInvalidDeviceIdentity, err)
	}
	if len(signed.GetDetails()) == 0 {
		return nil, fmt.Errorf("%w: empty device details", ErrInvalidDeviceIdentity)
	}
	if len(signed.GetAccountSignatureKey()) != 32 {
		return nil, fmt.Errorf("%w: account key is %d bytes, want 32", ErrInvalidDeviceIdentity, len(signed.GetAccountSignatureKey()))
	}
	if len(signed.GetAccountSignature()) != 64 {
		return nil, fmt.Errorf("%w: account signature is %d bytes, want 64", ErrInvalidDeviceIdentity, len(signed.GetAccountSignature()))
	}

	prefix := accountSignaturePrefix
	if outer.GetAccountType() == protobuf.ADVEncryptionType_HOSTED {
		prefix = hostedAccountSignaturePrefix
	}
	message := make([]byte, 0, len(prefix)+len(signed.GetDetails())+len(identityPub))
	message = append(message, prefix...)
	message = append(message, signed.GetDetails()...)
	message = append(message, identityPub...)

	var accountKey [32]byte
	copy(accountKey[:], signed.GetAccountSignatureKey())
	if err := xeddsa.Verify(accountKey, message, signed.GetAccountSignature()); err != nil {
		return nil, fmt.Errorf("%w: account signature: %w", ErrInvalidDeviceIdentity, err)
	}

	var device protobuf.ADVDeviceIdentity
	if err := proto.Unmarshal(signed.GetDetails(), &device); err != nil {
		return nil, fmt.Errorf("%w: device details: %w", ErrInvalidDeviceIdentity, err)
	}

	return &DeviceIdentity{
		RawID:            device.GetRawID(),
		Timestamp:        device.GetTimestamp(),
		KeyIndex:         device.GetKeyIndex(),
		AccountType:      outer.GetAccountType(),
		DeviceType:       device.GetDeviceType(),
		Details:          cloneBytes(signed.GetDetails()),
		AccountKey:       cloneBytes(signed.GetAccountSignatureKey()),
		AccountSignature: cloneBytes(signed.GetAccountSignature()),
		DeviceSignature:  cloneBytes(signed.GetDeviceSignature()),
	}, nil
}

// DeviceSigner signs the PF-017 device-identity message. The interface keeps
// this package independent of one signing construction; signal.XEdDSASigner is
// the only implementation that matches the server.
type DeviceSigner interface {
	SignDeviceIdentity(details, identityPub, accountSignatureKey []byte) ([]byte, error)
}

// SignDeviceIdentity returns the self-signed ADVSignedDeviceIdentity the client
// sends back in <pair-device-sign>. It signs
// 0x06,0x01 ‖ details ‖ identityPub ‖ accountSignatureKey and then drops the
// account key, which is what the server expects to receive back: the account
// signature key stays server-side.
func SignDeviceIdentity(verified *DeviceIdentity, identityPub []byte, signer DeviceSigner) ([]byte, error) {
	if verified == nil {
		return nil, fmt.Errorf("%w: nil device identity", ErrInvalidDeviceIdentity)
	}
	if signer == nil {
		return nil, fmt.Errorf("%w: no device signer", ErrInvalidDeviceIdentity)
	}
	if len(identityPub) != 32 {
		return nil, fmt.Errorf("%w: identity key is %d bytes, want 32", ErrInvalidDeviceIdentity, len(identityPub))
	}
	if len(verified.AccountKey) != 32 {
		return nil, fmt.Errorf("%w: account key is %d bytes, want 32", ErrInvalidDeviceIdentity, len(verified.AccountKey))
	}

	signature, err := signer.SignDeviceIdentity(verified.Details, identityPub, verified.AccountKey)
	if err != nil {
		return nil, fmt.Errorf("%w: device signature: %w", ErrInvalidDeviceIdentity, err)
	}
	if len(signature) != 64 {
		return nil, fmt.Errorf("%w: device signature is %d bytes, want 64", ErrInvalidDeviceIdentity, len(signature))
	}

	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protobuf.ADVSignedDeviceIdentity{
		Details:          cloneBytes(verified.Details),
		AccountSignature: cloneBytes(verified.AccountSignature),
		DeviceSignature:  signature,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling self-signed identity: %w", ErrInvalidDeviceIdentity, err)
	}
	return raw, nil
}
