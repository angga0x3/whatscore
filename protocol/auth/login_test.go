package auth

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

func validLoginInput() LoginInput {
	return LoginInput{
		Version:       Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849},
		UserAgent:     validInput().UserAgent,
		WebInfo:       WebInfo{SubPlatform: protobuf.ClientPayload_WebInfo_WEB_BROWSER},
		ConnectType:   protobuf.ClientPayload_WIFI_UNKNOWN,
		ConnectReason: protobuf.ClientPayload_USER_ACTIVATED,
		Username:      15551234567,
		Device:        3,
	}
}

func mustBuildLogin(t *testing.T, in LoginInput) []byte {
	t.Helper()
	raw, err := BuildLoginPayload(in)
	if err != nil {
		t.Fatalf("BuildLoginPayload: %v", err)
	}
	return raw
}

func mustParseLogin(t *testing.T, raw []byte) *LoginPayload {
	t.Helper()
	payload, err := ParseLoginPayload(raw)
	if err != nil {
		t.Fatalf("ParseLoginPayload: %v", err)
	}
	return payload
}

func mutateLogin(t *testing.T, raw []byte, edit func(*protobuf.ClientPayload)) []byte {
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

func topLevelFields(t *testing.T, raw []byte) map[protowire.Number]protowire.Type {
	t.Helper()
	fields := make(map[protowire.Number]protowire.Type)
	for len(raw) > 0 {
		number, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			t.Fatalf("consume tag: %v", protowire.ParseError(n))
		}
		raw = raw[n:]
		var m int
		switch typ {
		case protowire.VarintType:
			_, m = protowire.ConsumeVarint(raw)
		case protowire.Fixed32Type:
			_, m = protowire.ConsumeFixed32(raw)
		case protowire.Fixed64Type:
			_, m = protowire.ConsumeFixed64(raw)
		case protowire.BytesType:
			_, m = protowire.ConsumeBytes(raw)
		default:
			t.Fatalf("unexpected wire type %v for field %d", typ, number)
		}
		if m < 0 {
			t.Fatalf("consume field %d: %v", number, protowire.ParseError(m))
		}
		fields[number] = typ
		raw = raw[m:]
	}
	return fields
}

func TestBuildParseLoginRoundTrip(t *testing.T) {
	in := validLoginInput()
	raw := mustBuildLogin(t, in)
	got := mustParseLogin(t, raw)

	want := &LoginPayload{
		Version:       in.Version,
		UserAgent:     in.UserAgent,
		WebInfo:       in.WebInfo,
		ConnectType:   in.ConnectType,
		ConnectReason: in.ConnectReason,
		Passive:       true,
		Pull:          true,
		LidDbMigrated: true,
		Username:      in.Username,
		Device:        in.Device,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, want)
	}
}

func TestLoginWireFieldPresence(t *testing.T) {
	raw := mustBuildLogin(t, validLoginInput())
	fields := topLevelFields(t, raw)

	want := map[protowire.Number]protowire.Type{
		1:  protowire.VarintType, // username
		3:  protowire.VarintType, // passive
		5:  protowire.BytesType,  // userAgent
		6:  protowire.BytesType,  // webInfo
		12: protowire.VarintType, // connectType
		13: protowire.VarintType, // connectReason
		18: protowire.VarintType, // device
		33: protowire.VarintType, // pull
		41: protowire.VarintType, // lidDbMigrated
	}
	for number, typ := range want {
		if fields[number] != typ {
			t.Fatalf("ClientPayload field %d type = %v, want %v (all: %v)",
				number, fields[number], typ, fields)
		}
	}
	if _, ok := fields[19]; ok {
		t.Fatal("login payload unexpectedly contains devicePairingData field 19")
	}

	var wire protobuf.ClientPayload
	if err := proto.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal wire: %v", err)
	}
	if wire.GetUsername() != validLoginInput().Username {
		t.Fatalf("username = %d, want %d", wire.GetUsername(), validLoginInput().Username)
	}
	if wire.GetDevice() != validLoginInput().Device {
		t.Fatalf("device = %d, want %d", wire.GetDevice(), validLoginInput().Device)
	}
	if !wire.GetPassive() || !wire.GetPull() || !wire.GetLidDbMigrated() {
		t.Fatalf("passive=%v pull=%v lidDbMigrated=%v, want all true",
			wire.GetPassive(), wire.GetPull(), wire.GetLidDbMigrated())
	}
	if wire.GetDevicePairingData() != nil {
		t.Fatal("login payload carries devicePairingData")
	}
}

func TestBuildLoginPayloadDeterministic(t *testing.T) {
	in := validLoginInput()
	first := mustBuildLogin(t, in)
	second := mustBuildLogin(t, in)
	if !bytes.Equal(first, second) {
		t.Fatal("BuildLoginPayload is not deterministic")
	}

	parsed := mustParseLogin(t, first)
	rebuilt := mustBuildLogin(t, LoginInput{
		Version:       parsed.Version,
		UserAgent:     parsed.UserAgent,
		WebInfo:       parsed.WebInfo,
		ConnectType:   parsed.ConnectType,
		ConnectReason: parsed.ConnectReason,
		Username:      parsed.Username,
		Device:        parsed.Device,
	})
	if !bytes.Equal(first, rebuilt) {
		t.Fatal("build/parse/build is not stable")
	}
}

func TestRegistrationLoginMutualRejection(t *testing.T) {
	registration := mustBuild(t, validInput())
	login := mustBuildLogin(t, validLoginInput())

	t.Run("login parser rejects registration payload", func(t *testing.T) {
		_, err := ParseLoginPayload(registration)
		if !errors.Is(err, ErrInvalidLoginPayload) {
			t.Fatalf("ParseLoginPayload(registration) error = %v, want %v", err, ErrInvalidLoginPayload)
		}
	})

	t.Run("registration parser rejects login payload", func(t *testing.T) {
		_, err := ParseClientPayload(login)
		if !errors.Is(err, ErrInvalidClientPayload) {
			t.Fatalf("ParseClientPayload(login) error = %v, want %v", err, ErrInvalidClientPayload)
		}
	})

	t.Run("ambiguous payload rejected by both", func(t *testing.T) {
		both := mutateLogin(t, login, func(p *protobuf.ClientPayload) {
			p.DevicePairingData = &protobuf.ClientPayload_DevicePairingRegistrationData{}
		})
		if _, err := ParseLoginPayload(both); !errors.Is(err, ErrInvalidLoginPayload) {
			t.Fatalf("ParseLoginPayload(ambiguous) error = %v, want %v", err, ErrInvalidLoginPayload)
		}
		if _, err := ParseClientPayload(both); !errors.Is(err, ErrInvalidClientPayload) {
			t.Fatalf("ParseClientPayload(ambiguous) error = %v, want %v", err, ErrInvalidClientPayload)
		}
	})
}

func TestBuildLoginValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*LoginInput)
		want error
	}{
		{"zero version", func(in *LoginInput) { in.Version = Version{} }, ErrInvalidClientPayload},
		{"zero username", func(in *LoginInput) { in.Username = 0 }, ErrInvalidLoginPayload},
		{"zero device", func(in *LoginInput) { in.Device = 0 }, ErrInvalidLoginPayload},
		{"device overflow", func(in *LoginInput) { in.Device = 0x10000 }, ErrInvalidLoginPayload},
		{"unknown platform", func(in *LoginInput) {
			in.UserAgent.Platform = 99
		}, ErrInvalidUserAgent},
		{"unknown release channel", func(in *LoginInput) {
			in.UserAgent.ReleaseChannel = 99
		}, ErrInvalidUserAgent},
		{"empty device string", func(in *LoginInput) { in.UserAgent.Device = "" }, ErrInvalidUserAgent},
		{"empty os version", func(in *LoginInput) { in.UserAgent.OSVersion = "" }, ErrInvalidUserAgent},
		{"empty locale language", func(in *LoginInput) {
			in.UserAgent.LocaleLanguage = ""
		}, ErrInvalidUserAgent},
		{"empty locale country", func(in *LoginInput) { in.UserAgent.LocaleCountry = "" }, ErrInvalidUserAgent},
		{"unknown connect type", func(in *LoginInput) { in.ConnectType = 99 }, ErrInvalidClientPayload},
		{"unknown connect reason", func(in *LoginInput) { in.ConnectReason = 99 }, ErrInvalidClientPayload},
		{"unknown web sub-platform", func(in *LoginInput) { in.WebInfo.SubPlatform = 99 }, ErrInvalidClientPayload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validLoginInput()
			tc.edit(&in)
			if _, err := BuildLoginPayload(in); !errors.Is(err, tc.want) {
				t.Fatalf("BuildLoginPayload error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseLoginMalformed(t *testing.T) {
	valid := mustBuildLogin(t, validLoginInput())
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, ErrInvalidLoginPayload},
		{"bad tag", []byte{0xff}, ErrInvalidLoginPayload},
		{"truncated field", []byte{0x12, 0x05, 0x00}, ErrInvalidLoginPayload},
		{"registration payload", mustBuild(t, validInput()), ErrInvalidLoginPayload},
		{"missing username", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.Username = nil
		}), ErrInvalidLoginPayload},
		{"missing device", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.Device = nil
		}), ErrInvalidLoginPayload},
		{"zero username", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.Username = proto.Uint64(0)
		}), ErrInvalidLoginPayload},
		{"zero device", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.Device = proto.Uint32(0)
		}), ErrInvalidLoginPayload},
		{"device overflow", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.Device = proto.Uint32(0x10000)
		}), ErrInvalidLoginPayload},
		{"missing passive", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.Passive = nil
		}), ErrInvalidLoginPayload},
		{"inactive login", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.Passive = proto.Bool(false)
		}), ErrInvalidLoginPayload},
		{"missing pull", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.Pull = nil
		}), ErrInvalidLoginPayload},
		{"non-pull login", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.Pull = proto.Bool(false)
		}), ErrInvalidLoginPayload},
		{"missing lidDbMigrated", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.LidDbMigrated = nil
		}), ErrInvalidLoginPayload},
		{"lidDbMigrated false", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.LidDbMigrated = proto.Bool(false)
		}), ErrInvalidLoginPayload},
		{"missing user agent", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.UserAgent = nil
		}), ErrInvalidUserAgent},
		{"incomplete user agent", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.UserAgent.Platform = nil
		}), ErrInvalidUserAgent},
		{"zero app version", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.UserAgent.AppVersion = &protobuf.ClientPayload_UserAgent_AppVersion{
				Primary: proto.Uint32(0), Secondary: proto.Uint32(0), Tertiary: proto.Uint32(0),
			}
		}), ErrInvalidUserAgent},
		{"missing connect type", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.ConnectType = nil
		}), ErrInvalidClientPayload},
		{"unknown connect type", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			unknown := protobuf.ClientPayload_ConnectType(99)
			p.ConnectType = &unknown
		}), ErrInvalidClientPayload},
		{"missing web info", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.WebInfo = nil
		}), ErrInvalidClientPayload},
		{"unknown web sub-platform", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			unknown := protobuf.ClientPayload_WebInfo_WebSubPlatform(99)
			p.WebInfo.WebSubPlatform = &unknown
		}), ErrInvalidClientPayload},
		{"registration data alongside login", mutateLogin(t, valid, func(p *protobuf.ClientPayload) {
			p.DevicePairingData = &protobuf.ClientPayload_DevicePairingRegistrationData{
				ERegid: []byte{0x00, 0x00, 0x30, 0x39},
			}
		}), ErrInvalidLoginPayload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseLoginPayload(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("ParseLoginPayload error = %v, want %v", err, tc.want)
			}
		})
	}
}
