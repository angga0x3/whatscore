// Package auth builds and parses the post-handshake ClientPayload: the
// registration form a companion device sends while pairing (PF-020..PF-025)
// and the login form a paired device sends when reconnecting (PF-026,
// PF-027). Registration crypto is out of scope.
package auth

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

const (
	// IdentityKeySize is the length of a Curve25519 identity public key.
	IdentityKeySize = 32
	// SignedPreKeySize is the length of a Curve25519 signed prekey.
	SignedPreKeySize = 32
	// SignedPreKeySignatureSize is the length of an XEdDSA prekey signature.
	SignedPreKeySignatureSize = 64
	// BuildHashSize is the length of the MD5 build hash (PF-023).
	BuildHashSize = 16

	registrationIDSize = 4
	signedPreKeyIDSize = 3
	curve25519KeyType  = 0x05 // libsignal DjbType; PF-023
	maxSignedPreKeyID  = 0xFFFFFF
)

var (
	// ErrInvalidClientPayload is returned for malformed or inconsistent
	// ClientPayload envelopes.
	ErrInvalidClientPayload = errors.New("auth: invalid client payload")
	// ErrInvalidUserAgent is returned for a missing or malformed user agent.
	ErrInvalidUserAgent = errors.New("auth: invalid user agent")
	// ErrInvalidRegistrationData is returned for malformed device pairing
	// registration data.
	ErrInvalidRegistrationData = errors.New("auth: invalid registration data")
	// ErrInvalidDeviceProps is returned for malformed DeviceProps bytes.
	ErrInvalidDeviceProps = errors.New("auth: invalid device props")
)

// Version is a three-component client version (PF-021, PF-024).
type Version struct {
	Primary   uint32
	Secondary uint32
	Tertiary  uint32
}

// String renders the version as the dotted form used for the build hash.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Primary, v.Secondary, v.Tertiary)
}

// UserAgent is the registration user-agent metadata (PF-021).
type UserAgent struct {
	Platform       protobuf.ClientPayload_UserAgent_Platform
	ReleaseChannel protobuf.ClientPayload_UserAgent_ReleaseChannel
	MCC            string
	MNC            string
	OSVersion      string
	Manufacturer   string
	Device         string
	OSBuildNumber  string
	LocaleLanguage string
	LocaleCountry  string
}

// WebInfo is the WhatsApp Web sub-platform metadata (PF-022).
type WebInfo struct {
	SubPlatform protobuf.ClientPayload_WebInfo_WebSubPlatform
}

// Registration is the device pairing registration key material (PF-023).
// The long-term identity key and signed prekey are public values.
type Registration struct {
	RegistrationID        uint32
	IdentityKey           []byte
	SignedPreKeyID        uint32
	SignedPreKey          []byte
	SignedPreKeySignature []byte
}

// DeviceProps is the companion DeviceProps message carried inside the
// registration data (PF-024). HistorySyncConfig is out of scope.
type DeviceProps struct {
	OS              string
	Version         Version
	PlatformType    protobuf.DeviceProps_PlatformType
	RequireFullSync bool
}

// Input is the typed input for BuildClientPayload.
type Input struct {
	// Version is the WhatsApp Web client version; it supplies both the
	// user-agent app version and the MD5 build hash.
	Version       Version
	UserAgent     UserAgent
	WebInfo       WebInfo
	ConnectType   protobuf.ClientPayload_ConnectType
	ConnectReason protobuf.ClientPayload_ConnectReason
	Registration  Registration
	DeviceProps   DeviceProps
}

// ClientPayload is the parsed registration payload.
type ClientPayload struct {
	Version       Version
	UserAgent     UserAgent
	WebInfo       WebInfo
	ConnectType   protobuf.ClientPayload_ConnectType
	ConnectReason protobuf.ClientPayload_ConnectReason
	Passive       bool
	Pull          bool
	Registration  Registration
	DeviceProps   DeviceProps
	BuildHash     []byte
}

// BuildClientPayload validates in and marshals the registration
// ClientPayload deterministically (PF-020..PF-025).
func BuildClientPayload(in Input) ([]byte, error) {
	if err := validateInput(in); err != nil {
		return nil, err
	}
	deviceProps, err := marshalDeviceProps(in.DeviceProps)
	if err != nil {
		return nil, err
	}

	registrationID := make([]byte, registrationIDSize)
	binary.BigEndian.PutUint32(registrationID, in.Registration.RegistrationID)
	signedPreKeyID := make([]byte, registrationIDSize)
	binary.BigEndian.PutUint32(signedPreKeyID, in.Registration.SignedPreKeyID)
	buildHash := md5.Sum([]byte(in.Version.String()))

	passive, pull := false, false
	payload := &protobuf.ClientPayload{
		Passive:   &passive,
		UserAgent: newUserAgentProto(in.UserAgent, in.Version),
		WebInfo: &protobuf.ClientPayload_WebInfo{
			WebSubPlatform: in.WebInfo.SubPlatform.Enum(),
		},
		ConnectType:   in.ConnectType.Enum(),
		ConnectReason: in.ConnectReason.Enum(),
		DevicePairingData: &protobuf.ClientPayload_DevicePairingRegistrationData{
			ERegid:      registrationID,
			EKeytype:    []byte{curve25519KeyType},
			EIdent:      cloneBytes(in.Registration.IdentityKey),
			ESkeyID:     signedPreKeyID[1:],
			ESkeyVal:    cloneBytes(in.Registration.SignedPreKey),
			ESkeySig:    cloneBytes(in.Registration.SignedPreKeySignature),
			BuildHash:   cloneBytes(buildHash[:]),
			DeviceProps: deviceProps,
		},
		Pull: &pull,
	}

	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling: %w", ErrInvalidClientPayload, err)
	}
	return raw, nil
}

// ParseClientPayload decodes and validates a registration ClientPayload.
func ParseClientPayload(raw []byte) (*ClientPayload, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidClientPayload)
	}
	var payload protobuf.ClientPayload
	if err := proto.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("%w: unmarshaling: %w", ErrInvalidClientPayload, err)
	}
	// A paired-device login carries username=1/device=18 and no
	// devicePairingData=19; reject it here rather than reporting a missing
	// registration block (PF-027).
	if payload.Username != nil || payload.Device != nil {
		return nil, fmt.Errorf("%w: login payload has no devicePairingData", ErrInvalidClientPayload)
	}

	ua, version, err := parseEnvelope(&payload)
	if err != nil {
		return nil, err
	}
	if payload.Passive != nil && payload.GetPassive() {
		return nil, fmt.Errorf("%w: registration payload is passive", ErrInvalidClientPayload)
	}
	if payload.Pull != nil && payload.GetPull() {
		return nil, fmt.Errorf("%w: registration payload requests pull", ErrInvalidClientPayload)
	}

	registration, err := parseRegistration(payload.GetDevicePairingData())
	if err != nil {
		return nil, err
	}
	if version.Primary == 0 {
		return nil, fmt.Errorf("%w: client version primary component is zero", ErrInvalidUserAgent)
	}
	buildHash := cloneBytes(payload.GetDevicePairingData().GetBuildHash())
	deviceProps, err := parseDeviceProps(registration.deviceProps)
	if err != nil {
		return nil, err
	}

	return &ClientPayload{
		Version:       version,
		UserAgent:     ua,
		WebInfo:       WebInfo{SubPlatform: payload.GetWebInfo().GetWebSubPlatform()},
		ConnectType:   payload.GetConnectType(),
		ConnectReason: payload.GetConnectReason(),
		Passive:       payload.GetPassive(),
		Pull:          payload.GetPull(),
		Registration: Registration{
			RegistrationID:        registration.RegistrationID,
			IdentityKey:           registration.IdentityKey,
			SignedPreKeyID:        registration.SignedPreKeyID,
			SignedPreKey:          registration.SignedPreKey,
			SignedPreKeySignature: registration.SignedPreKeySignature,
		},
		DeviceProps: deviceProps,
		BuildHash:   buildHash,
	}, nil
}

type parsedRegistration struct {
	Registration
	deviceProps []byte
}

// newUserAgentProto renders the user agent and app version (PF-021).
func newUserAgentProto(ua UserAgent, version Version) *protobuf.ClientPayload_UserAgent {
	return &protobuf.ClientPayload_UserAgent{
		Platform:       ua.Platform.Enum(),
		ReleaseChannel: ua.ReleaseChannel.Enum(),
		AppVersion: &protobuf.ClientPayload_UserAgent_AppVersion{
			Primary:   proto.Uint32(version.Primary),
			Secondary: proto.Uint32(version.Secondary),
			Tertiary:  proto.Uint32(version.Tertiary),
		},
		Mcc:                         proto.String(ua.MCC),
		Mnc:                         proto.String(ua.MNC),
		OsVersion:                   proto.String(ua.OSVersion),
		Manufacturer:                proto.String(ua.Manufacturer),
		Device:                      proto.String(ua.Device),
		OsBuildNumber:               proto.String(ua.OSBuildNumber),
		LocaleLanguageIso6391:       proto.String(ua.LocaleLanguage),
		LocaleCountryIso31661Alpha2: proto.String(ua.LocaleCountry),
	}
}

// parseEnvelope validates the fields shared by the registration and login
// forms: user agent (PF-021), connection metadata, and WebInfo (PF-022).
func parseEnvelope(payload *protobuf.ClientPayload) (UserAgent, Version, error) {
	userAgent := payload.GetUserAgent()
	if userAgent == nil {
		return UserAgent{}, Version{}, fmt.Errorf("%w: missing userAgent", ErrInvalidUserAgent)
	}
	if userAgent.Platform == nil || userAgent.AppVersion == nil || userAgent.ReleaseChannel == nil {
		return UserAgent{}, Version{}, fmt.Errorf("%w: incomplete userAgent", ErrInvalidUserAgent)
	}
	ua := UserAgent{
		Platform:       userAgent.GetPlatform(),
		ReleaseChannel: userAgent.GetReleaseChannel(),
		MCC:            userAgent.GetMcc(),
		MNC:            userAgent.GetMnc(),
		OSVersion:      userAgent.GetOsVersion(),
		Manufacturer:   userAgent.GetManufacturer(),
		Device:         userAgent.GetDevice(),
		OSBuildNumber:  userAgent.GetOsBuildNumber(),
		LocaleLanguage: userAgent.GetLocaleLanguageIso6391(),
		LocaleCountry:  userAgent.GetLocaleCountryIso31661Alpha2(),
	}
	if err := validateUserAgent(ua); err != nil {
		return UserAgent{}, Version{}, err
	}
	if payload.ConnectType == nil || payload.ConnectReason == nil {
		return UserAgent{}, Version{}, fmt.Errorf("%w: missing connection metadata", ErrInvalidClientPayload)
	}
	if !knownConnectType(payload.GetConnectType()) {
		return UserAgent{}, Version{}, fmt.Errorf("%w: unknown connect type %d",
			ErrInvalidClientPayload, payload.GetConnectType())
	}
	if !knownConnectReason(payload.GetConnectReason()) {
		return UserAgent{}, Version{}, fmt.Errorf("%w: unknown connect reason %d",
			ErrInvalidClientPayload, payload.GetConnectReason())
	}
	if payload.WebInfo == nil || payload.GetWebInfo().WebSubPlatform == nil {
		return UserAgent{}, Version{}, fmt.Errorf("%w: missing webInfo", ErrInvalidClientPayload)
	}
	if !knownWebSubPlatform(payload.GetWebInfo().GetWebSubPlatform()) {
		return UserAgent{}, Version{}, fmt.Errorf("%w: unknown web sub-platform %d",
			ErrInvalidClientPayload, payload.GetWebInfo().GetWebSubPlatform())
	}
	appVersion := userAgent.GetAppVersion()
	return ua, Version{
		Primary:   appVersion.GetPrimary(),
		Secondary: appVersion.GetSecondary(),
		Tertiary:  appVersion.GetTertiary(),
	}, nil
}

func parseRegistration(raw *protobuf.ClientPayload_DevicePairingRegistrationData) (parsedRegistration, error) {
	if raw == nil {
		return parsedRegistration{}, fmt.Errorf("%w: missing devicePairingData", ErrInvalidRegistrationData)
	}
	var out parsedRegistration
	if err := checkLength("eRegid", raw.GetERegid(), registrationIDSize); err != nil {
		return parsedRegistration{}, err
	}
	keyType := raw.GetEKeytype()
	if len(keyType) != 1 || keyType[0] != curve25519KeyType {
		return parsedRegistration{}, fmt.Errorf("%w: eKeytype is %x, want %02x",
			ErrInvalidRegistrationData, keyType, curve25519KeyType)
	}
	if err := checkLength("eIdent", raw.GetEIdent(), IdentityKeySize); err != nil {
		return parsedRegistration{}, err
	}
	if err := checkLength("eSkeyID", raw.GetESkeyID(), signedPreKeyIDSize); err != nil {
		return parsedRegistration{}, err
	}
	if err := checkLength("eSkeyVal", raw.GetESkeyVal(), SignedPreKeySize); err != nil {
		return parsedRegistration{}, err
	}
	if err := checkLength("eSkeySig", raw.GetESkeySig(), SignedPreKeySignatureSize); err != nil {
		return parsedRegistration{}, err
	}
	if err := checkLength("buildHash", raw.GetBuildHash(), BuildHashSize); err != nil {
		return parsedRegistration{}, err
	}

	var signedPreKeyID [registrationIDSize]byte
	copy(signedPreKeyID[1:], raw.GetESkeyID())
	out.RegistrationID = binary.BigEndian.Uint32(raw.GetERegid())
	out.IdentityKey = cloneBytes(raw.GetEIdent())
	out.SignedPreKeyID = binary.BigEndian.Uint32(signedPreKeyID[:])
	out.SignedPreKey = cloneBytes(raw.GetESkeyVal())
	out.SignedPreKeySignature = cloneBytes(raw.GetESkeySig())
	out.deviceProps = cloneBytes(raw.GetDeviceProps())
	return out, nil
}

func parseDeviceProps(raw []byte) (DeviceProps, error) {
	if len(raw) == 0 {
		return DeviceProps{}, fmt.Errorf("%w: missing deviceProps", ErrInvalidDeviceProps)
	}
	var props protobuf.DeviceProps
	if err := proto.Unmarshal(raw, &props); err != nil {
		return DeviceProps{}, fmt.Errorf("%w: unmarshaling: %w", ErrInvalidDeviceProps, err)
	}
	if props.PlatformType == nil {
		return DeviceProps{}, fmt.Errorf("%w: missing platformType", ErrInvalidDeviceProps)
	}
	out := DeviceProps{
		OS:              props.GetOs(),
		Version:         Version{},
		PlatformType:    props.GetPlatformType(),
		RequireFullSync: props.GetRequireFullSync(),
	}
	if version := props.GetVersion(); version != nil {
		out.Version = Version{
			Primary:   version.GetPrimary(),
			Secondary: version.GetSecondary(),
			Tertiary:  version.GetTertiary(),
		}
	}
	if err := validateDeviceProps(out); err != nil {
		return DeviceProps{}, err
	}
	return out, nil
}

func marshalDeviceProps(props DeviceProps) ([]byte, error) {
	if err := validateDeviceProps(props); err != nil {
		return nil, err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protobuf.DeviceProps{
		Os: proto.String(props.OS),
		Version: &protobuf.DeviceProps_AppVersion{
			Primary:   proto.Uint32(props.Version.Primary),
			Secondary: proto.Uint32(props.Version.Secondary),
			Tertiary:  proto.Uint32(props.Version.Tertiary),
		},
		PlatformType:    props.PlatformType.Enum(),
		RequireFullSync: proto.Bool(props.RequireFullSync),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling: %w", ErrInvalidDeviceProps, err)
	}
	return raw, nil
}

func validateInput(in Input) error {
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
	if err := validateRegistration(in.Registration); err != nil {
		return err
	}
	return validateDeviceProps(in.DeviceProps)
}

func validateUserAgent(ua UserAgent) error {
	if !knownPlatform(ua.Platform) {
		return fmt.Errorf("%w: unknown platform %d", ErrInvalidUserAgent, ua.Platform)
	}
	if !knownReleaseChannel(ua.ReleaseChannel) {
		return fmt.Errorf("%w: unknown release channel %d", ErrInvalidUserAgent, ua.ReleaseChannel)
	}
	if ua.Device == "" {
		return fmt.Errorf("%w: empty device", ErrInvalidUserAgent)
	}
	if ua.OSVersion == "" {
		return fmt.Errorf("%w: empty osVersion", ErrInvalidUserAgent)
	}
	if ua.LocaleLanguage == "" {
		return fmt.Errorf("%w: empty locale language", ErrInvalidUserAgent)
	}
	if ua.LocaleCountry == "" {
		return fmt.Errorf("%w: empty locale country", ErrInvalidUserAgent)
	}
	return nil
}

func validateRegistration(reg Registration) error {
	if len(reg.IdentityKey) != IdentityKeySize {
		return fmt.Errorf("%w: identity key is %d bytes, want %d",
			ErrInvalidRegistrationData, len(reg.IdentityKey), IdentityKeySize)
	}
	if len(reg.SignedPreKey) != SignedPreKeySize {
		return fmt.Errorf("%w: signed prekey is %d bytes, want %d",
			ErrInvalidRegistrationData, len(reg.SignedPreKey), SignedPreKeySize)
	}
	if len(reg.SignedPreKeySignature) != SignedPreKeySignatureSize {
		return fmt.Errorf("%w: signed prekey signature is %d bytes, want %d",
			ErrInvalidRegistrationData, len(reg.SignedPreKeySignature), SignedPreKeySignatureSize)
	}
	if reg.SignedPreKeyID > maxSignedPreKeyID {
		return fmt.Errorf("%w: signed prekey ID %d does not fit in %d bytes",
			ErrInvalidRegistrationData, reg.SignedPreKeyID, signedPreKeyIDSize)
	}
	return nil
}

func validateDeviceProps(props DeviceProps) error {
	if props.OS == "" {
		return fmt.Errorf("%w: empty os", ErrInvalidDeviceProps)
	}
	if !knownPlatformType(props.PlatformType) {
		return fmt.Errorf("%w: unknown platform type %d", ErrInvalidDeviceProps, props.PlatformType)
	}
	return nil
}

func checkLength(name string, value []byte, want int) error {
	if len(value) != want {
		return fmt.Errorf("%w: %s is %d bytes, want %d", ErrInvalidRegistrationData, name, len(value), want)
	}
	return nil
}

func knownPlatform(v protobuf.ClientPayload_UserAgent_Platform) bool {
	_, ok := protobuf.ClientPayload_UserAgent_Platform_name[int32(v)]
	return ok
}

func knownReleaseChannel(v protobuf.ClientPayload_UserAgent_ReleaseChannel) bool {
	_, ok := protobuf.ClientPayload_UserAgent_ReleaseChannel_name[int32(v)]
	return ok
}

func knownConnectType(v protobuf.ClientPayload_ConnectType) bool {
	_, ok := protobuf.ClientPayload_ConnectType_name[int32(v)]
	return ok
}

func knownConnectReason(v protobuf.ClientPayload_ConnectReason) bool {
	_, ok := protobuf.ClientPayload_ConnectReason_name[int32(v)]
	return ok
}

func knownWebSubPlatform(v protobuf.ClientPayload_WebInfo_WebSubPlatform) bool {
	_, ok := protobuf.ClientPayload_WebInfo_WebSubPlatform_name[int32(v)]
	return ok
}

func knownPlatformType(v protobuf.DeviceProps_PlatformType) bool {
	_, ok := protobuf.DeviceProps_PlatformType_name[int32(v)]
	return ok
}

func cloneBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	return append([]byte(nil), src...)
}
