package auth

import (
	"bytes"
	"crypto/md5"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

const testVersion = "2.3000.1052556849"

func validInput() Input {
	return Input{
		Version: Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849},
		UserAgent: UserAgent{
			Platform:       protobuf.ClientPayload_UserAgent_WEB,
			ReleaseChannel: protobuf.ClientPayload_UserAgent_RELEASE,
			MCC:            "000",
			MNC:            "000",
			OSVersion:      "0.1",
			Manufacturer:   "",
			Device:         "Desktop",
			OSBuildNumber:  "0.1",
			LocaleLanguage: "en",
			LocaleCountry:  "US",
		},
		WebInfo:       WebInfo{SubPlatform: protobuf.ClientPayload_WebInfo_WEB_BROWSER},
		ConnectType:   protobuf.ClientPayload_WIFI_UNKNOWN,
		ConnectReason: protobuf.ClientPayload_USER_ACTIVATED,
		Registration: Registration{
			RegistrationID:        12345,
			IdentityKey:           bytes.Repeat([]byte{0x11}, IdentityKeySize),
			SignedPreKeyID:        7,
			SignedPreKey:          bytes.Repeat([]byte{0x22}, SignedPreKeySize),
			SignedPreKeySignature: bytes.Repeat([]byte{0x33}, SignedPreKeySignatureSize),
		},
		DeviceProps: DeviceProps{
			OS:              "whatscore",
			Version:         Version{Primary: 0, Secondary: 1, Tertiary: 0},
			PlatformType:    protobuf.DeviceProps_UNKNOWN,
			RequireFullSync: false,
		},
	}
}

func mustBuild(t *testing.T, in Input) []byte {
	t.Helper()
	raw, err := BuildClientPayload(in)
	if err != nil {
		t.Fatalf("BuildClientPayload: %v", err)
	}
	return raw
}

func mustParse(t *testing.T, raw []byte) *ClientPayload {
	t.Helper()
	payload, err := ParseClientPayload(raw)
	if err != nil {
		t.Fatalf("ParseClientPayload: %v", err)
	}
	return payload
}

func mutate(t *testing.T, raw []byte, edit func(*protobuf.ClientPayload)) []byte {
	t.Helper()
	var payload protobuf.ClientPayload
	if err := proto.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	edit(&payload)
	out, err := proto.Marshal(&payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func TestBuildParseRoundTrip(t *testing.T) {
	in := validInput()
	raw := mustBuild(t, in)
	got := mustParse(t, raw)

	buildHash := md5.Sum([]byte(testVersion))
	want := &ClientPayload{
		Version:       in.Version,
		UserAgent:     in.UserAgent,
		WebInfo:       in.WebInfo,
		ConnectType:   in.ConnectType,
		ConnectReason: in.ConnectReason,
		Registration:  in.Registration,
		DeviceProps:   in.DeviceProps,
		BuildHash:     buildHash[:],
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, want)
	}

	var wire protobuf.ClientPayload
	if err := proto.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal wire: %v", err)
	}
	if got := wire.GetUserAgent().GetAppVersion(); got.GetPrimary() != in.Version.Primary ||
		got.GetSecondary() != in.Version.Secondary || got.GetTertiary() != in.Version.Tertiary {
		t.Fatalf("app version = %d.%d.%d, want %s",
			got.GetPrimary(), got.GetSecondary(), got.GetTertiary(), testVersion)
	}
	if got := wire.GetDevicePairingData(); !bytes.Equal(got.GetERegid(), []byte{0x00, 0x00, 0x30, 0x39}) {
		t.Fatalf("eRegid = %x, want big-endian registration ID", got.GetERegid())
	}
	if got := wire.GetDevicePairingData().GetESkeyID(); !bytes.Equal(got, []byte{0x00, 0x00, 0x07}) {
		t.Fatalf("eSkeyID = %x, want 3-byte big-endian ID", got)
	}
	if got := wire.GetDevicePairingData().GetEKeytype(); !bytes.Equal(got, []byte{0x05}) {
		t.Fatalf("eKeytype = %x, want 05", got)
	}
	if got := wire.GetDevicePairingData().GetBuildHash(); !bytes.Equal(got, buildHash[:]) {
		t.Fatalf("buildHash = %x, want %x", got, buildHash)
	}
}

func TestParseCopiesKeyMaterial(t *testing.T) {
	in := validInput()
	raw := mustBuild(t, in)
	got := mustParse(t, raw)
	for i := range raw {
		raw[i] = 0
	}
	if !bytes.Equal(got.Registration.IdentityKey, in.Registration.IdentityKey) {
		t.Fatal("parsed identity key aliases the input buffer")
	}
	if !bytes.Equal(got.Registration.SignedPreKey, in.Registration.SignedPreKey) {
		t.Fatal("parsed signed prekey aliases the input buffer")
	}
}

func TestBuildDeterministic(t *testing.T) {
	in := validInput()
	first := mustBuild(t, in)
	second := mustBuild(t, in)
	if !bytes.Equal(first, second) {
		t.Fatal("BuildClientPayload is not deterministic")
	}
	parsed := mustParse(t, first)
	rebuilt := mustBuild(t, Input{
		Version:       parsed.Version,
		UserAgent:     parsed.UserAgent,
		WebInfo:       parsed.WebInfo,
		ConnectType:   parsed.ConnectType,
		ConnectReason: parsed.ConnectReason,
		Registration:  parsed.Registration,
		DeviceProps:   parsed.DeviceProps,
	})
	if !bytes.Equal(first, rebuilt) {
		t.Fatal("build/parse/build is not stable")
	}
}

func TestBuildValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Input)
		want error
	}{
		{"zero version", func(in *Input) { in.Version = Version{} }, ErrInvalidClientPayload},
		{"short identity key", func(in *Input) {
			in.Registration.IdentityKey = in.Registration.IdentityKey[:31]
		}, ErrInvalidRegistrationData},
		{"short signed prekey", func(in *Input) {
			in.Registration.SignedPreKey = in.Registration.SignedPreKey[:31]
		}, ErrInvalidRegistrationData},
		{"short signature", func(in *Input) {
			in.Registration.SignedPreKeySignature = in.Registration.SignedPreKeySignature[:63]
		}, ErrInvalidRegistrationData},
		{"signed prekey ID overflow", func(in *Input) {
			in.Registration.SignedPreKeyID = 0x1000000
		}, ErrInvalidRegistrationData},
		{"unknown platform", func(in *Input) {
			in.UserAgent.Platform = 99
		}, ErrInvalidUserAgent},
		{"unknown release channel", func(in *Input) {
			in.UserAgent.ReleaseChannel = 99
		}, ErrInvalidUserAgent},
		{"empty device", func(in *Input) { in.UserAgent.Device = "" }, ErrInvalidUserAgent},
		{"empty os version", func(in *Input) { in.UserAgent.OSVersion = "" }, ErrInvalidUserAgent},
		{"empty locale language", func(in *Input) { in.UserAgent.LocaleLanguage = "" }, ErrInvalidUserAgent},
		{"empty locale country", func(in *Input) { in.UserAgent.LocaleCountry = "" }, ErrInvalidUserAgent},
		{"unknown connect type", func(in *Input) { in.ConnectType = 99 }, ErrInvalidClientPayload},
		{"unknown connect reason", func(in *Input) { in.ConnectReason = 99 }, ErrInvalidClientPayload},
		{"unknown web sub-platform", func(in *Input) { in.WebInfo.SubPlatform = 99 }, ErrInvalidClientPayload},
		{"empty device props os", func(in *Input) { in.DeviceProps.OS = "" }, ErrInvalidDeviceProps},
		{"unknown platform type", func(in *Input) { in.DeviceProps.PlatformType = 99 }, ErrInvalidDeviceProps},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.edit(&in)
			if _, err := BuildClientPayload(in); !errors.Is(err, tc.want) {
				t.Fatalf("BuildClientPayload error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseMalformed(t *testing.T) {
	valid := mustBuild(t, validInput())
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, ErrInvalidClientPayload},
		{"bad tag", []byte{0xff}, ErrInvalidClientPayload},
		{"truncated field", []byte{0x2a, 0x05, 0x00}, ErrInvalidClientPayload},
		{"missing user agent", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.UserAgent = nil
		}), ErrInvalidUserAgent},
		{"incomplete user agent", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.UserAgent.Platform = nil
		}), ErrInvalidUserAgent},
		{"zero app version", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.UserAgent.AppVersion = &protobuf.ClientPayload_UserAgent_AppVersion{
				Primary: proto.Uint32(0), Secondary: proto.Uint32(0), Tertiary: proto.Uint32(0),
			}
		}), ErrInvalidUserAgent},
		{"missing registration", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData = nil
		}), ErrInvalidRegistrationData},
		{"short eRegid", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData.ERegid = []byte{0x00, 0x01, 0x02}
		}), ErrInvalidRegistrationData},
		{"wrong eKeytype", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData.EKeytype = []byte{0x06}
		}), ErrInvalidRegistrationData},
		{"short eIdent", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData.EIdent = p.DevicePairingData.EIdent[:31]
		}), ErrInvalidRegistrationData},
		{"short eSkeyID", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData.ESkeyID = []byte{0x00, 0x01}
		}), ErrInvalidRegistrationData},
		{"short eSkeyVal", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData.ESkeyVal = p.DevicePairingData.ESkeyVal[:31]
		}), ErrInvalidRegistrationData},
		{"short eSkeySig", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData.ESkeySig = p.DevicePairingData.ESkeySig[:63]
		}), ErrInvalidRegistrationData},
		{"short build hash", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData.BuildHash = p.DevicePairingData.BuildHash[:15]
		}), ErrInvalidRegistrationData},
		{"empty device props", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData.DeviceProps = nil
		}), ErrInvalidDeviceProps},
		{"garbage device props", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData.DeviceProps = []byte{0xff}
		}), ErrInvalidDeviceProps},
		{"device props without platform", mutate(t, valid, func(p *protobuf.ClientPayload) {
			raw, err := proto.Marshal(&protobuf.DeviceProps{Os: proto.String("whatscore")})
			if err != nil {
				t.Fatal(err)
			}
			p.DevicePairingData.DeviceProps = raw
		}), ErrInvalidDeviceProps},
		{"passive registration", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.Passive = proto.Bool(true)
		}), ErrInvalidClientPayload},
		{"pull registration", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.Pull = proto.Bool(true)
		}), ErrInvalidClientPayload},
		{"missing connect type", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.ConnectType = nil
		}), ErrInvalidClientPayload},
		{"missing connect reason", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.ConnectReason = nil
		}), ErrInvalidClientPayload},
		{"missing web info", mutate(t, valid, func(p *protobuf.ClientPayload) {
			p.WebInfo = nil
		}), ErrInvalidClientPayload},
		{"unknown web sub-platform", mutate(t, valid, func(p *protobuf.ClientPayload) {
			unknown := protobuf.ClientPayload_WebInfo_WebSubPlatform(99)
			p.WebInfo.WebSubPlatform = &unknown
		}), ErrInvalidClientPayload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseClientPayload(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("ParseClientPayload error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	if got := (Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849}).String(); got != testVersion {
		t.Fatalf("Version.String() = %q, want %q", got, testVersion)
	}
}
