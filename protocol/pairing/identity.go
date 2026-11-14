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
