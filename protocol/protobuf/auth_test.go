package protobuf_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

func TestClientPayloadWireFields(t *testing.T) {
	passive, pull := false, false
	platform := protobuf.ClientPayload_UserAgent_WEB
	release := protobuf.ClientPayload_UserAgent_RELEASE
	subPlatform := protobuf.ClientPayload_WebInfo_WEB_BROWSER
	connectType := protobuf.ClientPayload_WIFI_UNKNOWN
	connectReason := protobuf.ClientPayload_USER_ACTIVATED
	primary, secondary, tertiary := uint32(2), uint32(3000), uint32(1052556849)

	payload := &protobuf.ClientPayload{
		Passive: &passive,
		UserAgent: &protobuf.ClientPayload_UserAgent{
			Platform:       &platform,
			ReleaseChannel: &release,
			AppVersion: &protobuf.ClientPayload_UserAgent_AppVersion{
				Primary: &primary, Secondary: &secondary, Tertiary: &tertiary,
			},
			Mcc:                         proto.String("000"),
			Mnc:                         proto.String("000"),
			OsVersion:                   proto.String("0.1"),
			Manufacturer:                proto.String(""),
			Device:                      proto.String("Desktop"),
			OsBuildNumber:               proto.String("0.1"),
			LocaleLanguageIso6391:       proto.String("en"),
			LocaleCountryIso31661Alpha2: proto.String("US"),
		},
		WebInfo:       &protobuf.ClientPayload_WebInfo{WebSubPlatform: &subPlatform},
		ConnectType:   &connectType,
		ConnectReason: &connectReason,
		DevicePairingData: &protobuf.ClientPayload_DevicePairingRegistrationData{
			ERegid:      []byte{0x00, 0x00, 0x30, 0x39},
			EKeytype:    []byte{0x05},
			EIdent:      bytes.Repeat([]byte{0x11}, 32),
			ESkeyID:     []byte{0x00, 0x00, 0x01},
			ESkeyVal:    bytes.Repeat([]byte{0x22}, 32),
			ESkeySig:    bytes.Repeat([]byte{0x33}, 64),
			BuildHash:   bytes.Repeat([]byte{0x44}, 16),
			DeviceProps: []byte{0x0a, 0x01, 0x78},
		},
		Pull: &pull,
	}
	raw := roundTrip(t, payload)

	fields := splitFields(t, raw)
	wantTop := map[protowire.Number]protowire.Type{
		3: protowire.VarintType, 5: protowire.BytesType, 6: protowire.BytesType,
		12: protowire.VarintType, 13: protowire.VarintType, 19: protowire.BytesType,
		33: protowire.VarintType,
	}
	for number, typ := range wantTop {
		if fields[number] != typ {
			t.Fatalf("ClientPayload field %d type = %v, want %v (all: %v)", number, fields[number], typ, fields)
		}
	}
	for _, omitted := range []protowire.Number{1, 18, 20} {
		if _, ok := fields[omitted]; ok {
			t.Fatalf("ClientPayload unexpectedly contains omitted field %d", omitted)
		}
	}

	userAgent := splitFields(t, bytesField(t, raw, 5))
	wantUserAgent := map[protowire.Number]protowire.Type{
		1: protowire.VarintType, 2: protowire.BytesType, 3: protowire.BytesType,
		4: protowire.BytesType, 5: protowire.BytesType, 6: protowire.BytesType,
		7: protowire.BytesType, 8: protowire.BytesType, 10: protowire.VarintType,
		11: protowire.BytesType, 12: protowire.BytesType,
	}
	for number, typ := range wantUserAgent {
		if userAgent[number] != typ {
			t.Fatalf("UserAgent field %d type = %v, want %v (all: %v)", number, userAgent[number], typ, userAgent)
		}
	}
	appVersion := splitFields(t, bytesField(t, bytesField(t, raw, 5), 2))
	for number := protowire.Number(1); number <= 3; number++ {
		if appVersion[number] != protowire.VarintType {
			t.Fatalf("UserAgent.AppVersion field %d type = %v", number, appVersion[number])
		}
	}

	if webInfo := splitFields(t, bytesField(t, raw, 6)); webInfo[4] != protowire.VarintType {
		t.Fatalf("WebInfo.webSubPlatform type = %v", webInfo[4])
	}

	registration := splitFields(t, bytesField(t, raw, 19))
	for number := protowire.Number(1); number <= 8; number++ {
		if registration[number] != protowire.BytesType {
			t.Fatalf("DevicePairingRegistrationData field %d type = %v", number, registration[number])
		}
	}
}

func TestDevicePropsWireFields(t *testing.T) {
	platformType := protobuf.DeviceProps_CHROME
	primary, secondary, tertiary := uint32(0), uint32(1), uint32(0)
	props := &protobuf.DeviceProps{
		Os:              proto.String("whatscore"),
		PlatformType:    &platformType,
		RequireFullSync: proto.Bool(false),
		Version: &protobuf.DeviceProps_AppVersion{
			Primary: &primary, Secondary: &secondary, Tertiary: &tertiary,
		},
	}
	raw := roundTrip(t, props)

	fields := splitFields(t, raw)
	want := map[protowire.Number]protowire.Type{
		1: protowire.BytesType, 2: protowire.BytesType,
		3: protowire.VarintType, 4: protowire.VarintType,
	}
	for number, typ := range want {
		if fields[number] != typ {
			t.Fatalf("DeviceProps field %d type = %v, want %v (all: %v)", number, fields[number], typ, fields)
		}
	}
	if _, ok := fields[5]; ok {
		t.Fatal("DeviceProps unexpectedly contains omitted historySyncConfig field 5")
	}
	version := splitFields(t, bytesField(t, raw, 2))
	for number := protowire.Number(1); number <= 3; number++ {
		if version[number] != protowire.VarintType {
			t.Fatalf("DeviceProps.AppVersion field %d type = %v", number, version[number])
		}
	}
}

func TestAuthEnumNumbers(t *testing.T) {
	cases := []struct {
		name string
		got  int32
		want int32
	}{
		{"UserAgent.Platform.WEB", int32(protobuf.ClientPayload_UserAgent_WEB), 14},
		{"UserAgent.Platform.ANDROID", int32(protobuf.ClientPayload_UserAgent_ANDROID), 0},
		{"UserAgent.ReleaseChannel.RELEASE", int32(protobuf.ClientPayload_UserAgent_RELEASE), 0},
		{"ConnectType.WIFI_UNKNOWN", int32(protobuf.ClientPayload_WIFI_UNKNOWN), 1},
		{"ConnectType.CELLULAR_HSPAP", int32(protobuf.ClientPayload_CELLULAR_HSPAP), 112},
		{"ConnectReason.USER_ACTIVATED", int32(protobuf.ClientPayload_USER_ACTIVATED), 1},
		{"WebSubPlatform.WEB_BROWSER", int32(protobuf.ClientPayload_WebInfo_WEB_BROWSER), 0},
		{"DeviceProps.PlatformType.UNKNOWN", int32(protobuf.DeviceProps_UNKNOWN), 0},
		{"DeviceProps.PlatformType.CHROME", int32(protobuf.DeviceProps_CHROME), 1},
		{"DeviceProps.PlatformType.ANDROID_PHONE", int32(protobuf.DeviceProps_ANDROID_PHONE), 16},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}
