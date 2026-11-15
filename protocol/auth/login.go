package auth

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// maxDeviceID is the largest representable companion device ID: the reference
// stores it in a uint16 (PF-026).
const maxDeviceID = 0xFFFF

// ErrInvalidLoginPayload is returned for a malformed login payload envelope or
// for a registration payload passed to the login parser (PF-026, PF-027).
var ErrInvalidLoginPayload = errors.New("auth: invalid login payload")

// LoginInput is the typed input for BuildLoginPayload.
type LoginInput struct {
	// Version is the WhatsApp Web client version; it supplies the
	// user-agent app version (PF-021).
	Version       Version
	UserAgent     UserAgent
	WebInfo       WebInfo
	ConnectType   protobuf.ClientPayload_ConnectType
	ConnectReason protobuf.ClientPayload_ConnectReason
	// Username is the user part of the paired account JID (PF-026 field 1).
	Username uint64
	// Device is the companion device ID (PF-026 field 18).
	Device uint32
}

// LoginPayload is the parsed login payload (PF-026).
type LoginPayload struct {
	Version       Version
	UserAgent     UserAgent
	WebInfo       WebInfo
	ConnectType   protobuf.ClientPayload_ConnectType
	ConnectReason protobuf.ClientPayload_ConnectReason
	Passive       bool
	Pull          bool
	LidDbMigrated bool
	Username      uint64
	Device        uint32
}

// BuildLoginPayload validates in and marshals the login ClientPayload
// deterministically (PF-026, PF-027). The login form sets username=1,
// device=18, passive=true, pull=true, and lidDbMigrated=41, and never carries
// devicePairingData=19.
func BuildLoginPayload(in LoginInput) ([]byte, error) {
	if err := validateLoginInput(in); err != nil {
		return nil, err
	}

	passive, pull, lidDbMigrated := true, true, true
	payload := &protobuf.ClientPayload{
		Username:      proto.Uint64(in.Username),
		Passive:       &passive,
		UserAgent:     newUserAgentProto(in.UserAgent, in.Version),
		WebInfo:       &protobuf.ClientPayload_WebInfo{WebSubPlatform: in.WebInfo.SubPlatform.Enum()},
		ConnectType:   in.ConnectType.Enum(),
		ConnectReason: in.ConnectReason.Enum(),
		Device:        proto.Uint32(in.Device),
		Pull:          &pull,
		LidDbMigrated: &lidDbMigrated,
	}

	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling: %w", ErrInvalidLoginPayload, err)
	}
	return raw, nil
}

// ParseLoginPayload decodes and validates a login ClientPayload. It rejects a
// registration payload: the two forms are discriminated by devicePairingData
// (registration) versus username and device (login) (PF-027).
func ParseLoginPayload(raw []byte) (*LoginPayload, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidLoginPayload)
	}
	var payload protobuf.ClientPayload
	if err := proto.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("%w: unmarshaling: %w", ErrInvalidLoginPayload, err)
	}
	if isRegistrationForm(&payload) {
		return nil, fmt.Errorf("%w: registration payload has no login fields", ErrInvalidLoginPayload)
	}
	if payload.Username == nil || payload.Device == nil {
		return nil, fmt.Errorf("%w: missing username or device", ErrInvalidLoginPayload)
	}
	if payload.Passive == nil || !payload.GetPassive() {
		return nil, fmt.Errorf("%w: login payload is not passive", ErrInvalidLoginPayload)
	}
	if payload.Pull == nil || !payload.GetPull() {
		return nil, fmt.Errorf("%w: login payload does not request pull", ErrInvalidLoginPayload)
	}
	if payload.LidDbMigrated == nil || !payload.GetLidDbMigrated() {
		return nil, fmt.Errorf("%w: login payload does not mark lidDbMigrated", ErrInvalidLoginPayload)
	}

	ua, version, err := parseEnvelope(&payload)
	if err != nil {
		return nil, err
	}
	if version.Primary == 0 {
		return nil, fmt.Errorf("%w: client version primary component is zero", ErrInvalidUserAgent)
	}
	login := LoginPayload{
		Version:       version,
		UserAgent:     ua,
		WebInfo:       WebInfo{SubPlatform: payload.GetWebInfo().GetWebSubPlatform()},
		ConnectType:   payload.GetConnectType(),
		ConnectReason: payload.GetConnectReason(),
		Passive:       payload.GetPassive(),
		Pull:          payload.GetPull(),
		LidDbMigrated: payload.GetLidDbMigrated(),
		Username:      payload.GetUsername(),
		Device:        payload.GetDevice(),
	}
	if err := validateLoginIdentity(login.Username, login.Device); err != nil {
		return nil, err
	}
	return &login, nil
}

// isRegistrationForm reports whether the payload carries the registration
// marker (devicePairingData=19) without the login markers (PF-027).
func isRegistrationForm(payload *protobuf.ClientPayload) bool {
	if payload.DevicePairingData != nil {
		return true
	}
	return payload.Username == nil && payload.Device == nil
}

func validateLoginInput(in LoginInput) error {
	if in.Version.Primary == 0 {
		return fmt.Errorf("%w: client version primary component is zero", ErrInvalidClientPayload)
	}
	if err := validateUserAgent(in.UserAgent); err != nil {
		return err
	}
	if !knownConnectType(in.ConnectType) {
		return fmt.Errorf("%w: unknown connect type %d", ErrInvalidClientPayload, in.ConnectType)
	}
	if !knownConnectReason(in.ConnectReason) {
		return fmt.Errorf("%w: unknown connect reason %d", ErrInvalidClientPayload, in.ConnectReason)
	}
	if !knownWebSubPlatform(in.WebInfo.SubPlatform) {
		return fmt.Errorf("%w: unknown web sub-platform %d", ErrInvalidClientPayload, in.WebInfo.SubPlatform)
	}
	return validateLoginIdentity(in.Username, in.Device)
}

func validateLoginIdentity(username uint64, device uint32) error {
	if username == 0 {
		return fmt.Errorf("%w: username is zero", ErrInvalidLoginPayload)
	}
	if device == 0 {
		return fmt.Errorf("%w: device ID is zero", ErrInvalidLoginPayload)
	}
	if device > maxDeviceID {
		return fmt.Errorf("%w: device ID %d exceeds %d", ErrInvalidLoginPayload, device, maxDeviceID)
	}
	return nil
}
