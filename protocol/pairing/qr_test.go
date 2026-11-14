package pairing

import (
	"errors"
	"strings"
	"testing"
)

func fixturePayload() QRPayload {
	var payload QRPayload
	for i := range payload.NoisePublicKey {
		payload.NoisePublicKey[i] = 0x11
		payload.IdentityPublicKey[i] = 0x22
		payload.AdvSecret[i] = 0x33
	}
	payload.Ref = "ref123"
	payload.ClientType = "test-client"
	return payload
}

func TestQRGolden(t *testing.T) {
	want := QRURLPrefix +
		"ref123," +
		"ERERERERERERERERERERERERERERERERERERERERERE=," +
		"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=," +
		"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=," +
		"test-client"
	got, err := fixturePayload().Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got != want {
		t.Fatalf("QR mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestQRRoundTrip(t *testing.T) {
	want := fixturePayload()
	code, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseQR(code)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, want)
	}
}

func TestQREmptyClientType(t *testing.T) {
	payload := fixturePayload()
	payload.ClientType = ""
	code, err := payload.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseQR(code)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientType != "" {
		t.Fatalf("client type = %q", got.ClientType)
	}
}

func TestQRInvalid(t *testing.T) {
	valid := fixturePayload()
	code, err := valid.Encode()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		code string
	}{
		{"wrong prefix", strings.Replace(code, "https://wa.me", "https://example.com", 1)},
		{"missing fields", QRURLPrefix + "ref123"},
		{"extra field", code + ",extra"},
		{"empty ref", strings.Replace(code, "ref123", "", 1)},
		{"ref with comma", QRURLPrefix + "a,b," + strings.Join(strings.Split(code, ",")[2:], ",")},
		{"bad base64", strings.Replace(code, strings.Split(code, ",")[1], "!!!", 1)},
		{"short key", strings.Replace(code, strings.Split(code, ",")[1], "ERER", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseQR(tc.code); !errors.Is(err, ErrInvalidQR) {
				t.Fatalf("want ErrInvalidQR, got %v", err)
			}
		})
	}
}

func TestQREncodeErrors(t *testing.T) {
	cases := []QRPayload{
		{Ref: ""},
		{Ref: "has space"},
		{Ref: "has,comma"},
		{Ref: strings.Repeat("a", 65)},
		{Ref: "ok", ClientType: "has,comma"},
		{Ref: "ok", ClientType: strings.Repeat("a", 33)},
	}
	for _, payload := range cases {
		if _, err := payload.Encode(); !errors.Is(err, ErrInvalidQR) {
			t.Fatalf("want ErrInvalidQR for %#v, got %v", payload, err)
		}
	}
}
