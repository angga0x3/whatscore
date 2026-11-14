package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

var testP25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

func testAccountKey(t *testing.T) (ed25519.PrivateKey, [32]byte) {
	t.Helper()
	for attempt := 0; attempt < 1000; attempt++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if pub[31]&0x80 != 0 {
			continue
		}
		yBytes := make([]byte, 32)
		for i := range pub {
			yBytes[i] = pub[31-i]
		}
		yBytes[31] &= 0x7f
		y := new(big.Int).SetBytes(yBytes)
		denom := new(big.Int).Sub(big.NewInt(1), y)
		denom.Mod(denom, testP25519)
		inv := new(big.Int).ModInverse(denom, testP25519)
		if inv == nil {
			continue
		}
		u := new(big.Int).Mul(new(big.Int).Add(big.NewInt(1), y), inv)
		u.Mod(u, testP25519)
		var mont [32]byte
		be := u.FillBytes(make([]byte, 32))
		for i := range be {
			mont[i] = be[31-i]
		}
		return priv, mont
	}
	t.Fatal("could not generate a usable account key")
	return nil, [32]byte{}
}

func buildDeviceDetails(t *testing.T, accountType protobuf.ADVEncryptionType) []byte {
	t.Helper()
	rawID, timestamp, keyIndex := uint32(7), uint64(1234567890), uint32(2)
	deviceType := protobuf.ADVEncryptionType_E2EE
	raw, err := proto.Marshal(&protobuf.ADVDeviceIdentity{
		RawID:       &rawID,
		Timestamp:   &timestamp,
		KeyIndex:    &keyIndex,
		AccountType: &accountType,
		DeviceType:  &deviceType,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func wrapSigned(t *testing.T, signed *protobuf.ADVSignedDeviceIdentity, adv []byte, accountType protobuf.ADVEncryptionType) []byte {
	t.Helper()
	details, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, adv)
	if accountType == protobuf.ADVEncryptionType_HOSTED {
		mac.Write(hostedAccountSignaturePrefix)
	}
	mac.Write(details)
	container, err := proto.Marshal(&protobuf.ADVSignedDeviceIdentityHMAC{
		Details:     details,
		HMAC:        mac.Sum(nil),
		AccountType: &accountType,
	})
	if err != nil {
		t.Fatal(err)
	}
	return container
}

type identityFixture struct {
	container   []byte
	adv         []byte
	identityPub []byte
	priv        ed25519.PrivateKey
	want        *DeviceIdentity
}

func newIdentityFixture(t *testing.T, accountType protobuf.ADVEncryptionType) identityFixture {
	t.Helper()
	priv, mont := testAccountKey(t)
	adv := bytes.Repeat([]byte{0x42}, 32)
	identityPub := bytes.Repeat([]byte{0x5a}, 32)
	deviceDetails := buildDeviceDetails(t, accountType)

	prefix := accountSignaturePrefix
	if accountType == protobuf.ADVEncryptionType_HOSTED {
		prefix = hostedAccountSignaturePrefix
	}
	message := append(append(append([]byte{}, prefix...), deviceDetails...), identityPub...)
	accountSignature := ed25519.Sign(priv, message)
	deviceSignature := bytes.Repeat([]byte{0x77}, 64)

	signed := &protobuf.ADVSignedDeviceIdentity{
		Details:             deviceDetails,
		AccountSignatureKey: mont[:],
		AccountSignature:    accountSignature,
		DeviceSignature:     deviceSignature,
	}
	return identityFixture{
		container:   wrapSigned(t, signed, adv, accountType),
		adv:         adv,
		identityPub: identityPub,
		priv:        priv,
		want: &DeviceIdentity{
			RawID:            7,
			Timestamp:        1234567890,
			KeyIndex:         2,
			AccountType:      accountType,
			DeviceType:       protobuf.ADVEncryptionType_E2EE,
			Details:          deviceDetails,
			AccountKey:       mont[:],
			AccountSignature: accountSignature,
			DeviceSignature:  deviceSignature,
		},
	}
}

func TestVerifyDeviceIdentity(t *testing.T) {
	for _, accountType := range []protobuf.ADVEncryptionType{
		protobuf.ADVEncryptionType_E2EE,
		protobuf.ADVEncryptionType_HOSTED,
	} {
		t.Run(accountType.String(), func(t *testing.T) {
			fixture := newIdentityFixture(t, accountType)
			got, err := VerifyDeviceIdentity(fixture.container, fixture.adv, fixture.identityPub)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got.RawID != fixture.want.RawID || got.Timestamp != fixture.want.Timestamp ||
				got.KeyIndex != fixture.want.KeyIndex || got.AccountType != fixture.want.AccountType ||
				got.DeviceType != fixture.want.DeviceType {
				t.Fatalf("fields = %#v", got)
			}
			if !bytes.Equal(got.Details, fixture.want.Details) ||
				!bytes.Equal(got.AccountKey, fixture.want.AccountKey) ||
				!bytes.Equal(got.AccountSignature, fixture.want.AccountSignature) ||
				!bytes.Equal(got.DeviceSignature, fixture.want.DeviceSignature) {
				t.Fatal("byte fields mismatch")
			}
		})
	}
}

func TestVerifyDeviceIdentityRejects(t *testing.T) {
	fixture := newIdentityFixture(t, protobuf.ADVEncryptionType_E2EE)
	adv := fixture.adv
	identityPub := fixture.identityPub
	accountType := protobuf.ADVEncryptionType_E2EE

	var outer protobuf.ADVSignedDeviceIdentityHMAC
	if err := proto.Unmarshal(fixture.container, &outer); err != nil {
		t.Fatal(err)
	}
	var signed protobuf.ADVSignedDeviceIdentity
	if err := proto.Unmarshal(outer.GetDetails(), &signed); err != nil {
		t.Fatal(err)
	}

	tamperedHMAC := proto.Clone(&outer).(*protobuf.ADVSignedDeviceIdentityHMAC)
	tamperedHMAC.HMAC[0] ^= 0x01
	tamperedHMACBytes, _ := proto.Marshal(tamperedHMAC)

	tamperedDetails := append([]byte(nil), outer.GetDetails()...)
	tamperedDetails[len(tamperedDetails)-1] ^= 0x01
	tamperedContainer := wrapSigned(t, &protobuf.ADVSignedDeviceIdentity{
		Details:             tamperedDetails,
		AccountSignatureKey: signed.GetAccountSignatureKey(),
		AccountSignature:    signed.GetAccountSignature(),
	}, adv, accountType)

	badKey := proto.Clone(&signed).(*protobuf.ADVSignedDeviceIdentity)
	badKey.AccountSignatureKey = signed.GetAccountSignatureKey()[:31]
	badKeyContainer := wrapSigned(t, badKey, adv, accountType)

	badSig := proto.Clone(&signed).(*protobuf.ADVSignedDeviceIdentity)
	badSig.AccountSignature = signed.GetAccountSignature()[:63]
	badSigContainer := wrapSigned(t, badSig, adv, accountType)

	emptyDetails := proto.Clone(&signed).(*protobuf.ADVSignedDeviceIdentity)
	emptyDetails.Details = nil
	emptyDetailsContainer := wrapSigned(t, emptyDetails, adv, accountType)

	badSignedDetails := proto.Clone(&signed).(*protobuf.ADVSignedDeviceIdentity)
	badSignedDetails.Details = []byte{0xFF}
	badSignedContainer := wrapSigned(t, badSignedDetails, adv, accountType)

	badDeviceDetails := []byte{0x08}
	badDeviceMessage := append(append(append([]byte{}, accountSignaturePrefix...), badDeviceDetails...), identityPub...)
	badDeviceSig := ed25519.Sign(fixture.priv, badDeviceMessage)
	badDeviceSigned := &protobuf.ADVSignedDeviceIdentity{
		Details:             badDeviceDetails,
		AccountSignatureKey: signed.GetAccountSignatureKey(),
		AccountSignature:    badDeviceSig,
	}
	badDeviceContainer := wrapSigned(t, badDeviceSigned, adv, accountType)

	cases := []struct {
		name        string
		container   []byte
		adv         []byte
		identityPub []byte
	}{
		{"short adv secret", fixture.container, adv[:31], identityPub},
		{"short identity key", fixture.container, adv, identityPub[:31]},
		{"malformed container", []byte{0xFF}, adv, identityPub},
		{"hmac mismatch", tamperedHMACBytes, adv, identityPub},
		{"wrong adv secret", fixture.container, bytes.Repeat([]byte{0x43}, 32), identityPub},
		{"tampered details", tamperedContainer, adv, identityPub},
		{"wrong identity key", fixture.container, adv, bytes.Repeat([]byte{0x5b}, 32)},
		{"short account key", badKeyContainer, adv, identityPub},
		{"short account signature", badSigContainer, adv, identityPub},
		{"empty device details", emptyDetailsContainer, adv, identityPub},
		{"malformed signed details", badSignedContainer, adv, identityPub},
		{"malformed device details", badDeviceContainer, adv, identityPub},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyDeviceIdentity(tc.container, tc.adv, tc.identityPub); !errors.Is(err, ErrInvalidDeviceIdentity) {
				t.Fatalf("want ErrInvalidDeviceIdentity, got %v", err)
			}
		})
	}
}
