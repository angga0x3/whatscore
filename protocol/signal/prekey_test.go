package signal

import (
	"bytes"
	"errors"
	"testing"
)

func newPrekeyFixture(t *testing.T) (KeyPair, KeyPair, KeyPair, KeyPair, []byte) {
	t.Helper()
	_, alice := signingKey(t)
	bobSigning, bob := signingKey(t)
	bobSigned := fixedKey(t, 0x21)
	oneTime := fixedKey(t, 0x31)
	return alice, bob, bobSigned, oneTime, signPreKey(t, bobSigning, bobSigned.Public)
}

func TestPreKeyMessageBootstrap(t *testing.T) {
	for _, withOneTime := range []bool{false, true} {
		t.Run(map[bool]string{false: "no one-time", true: "one-time"}[withOneTime], func(t *testing.T) {
			alice, bob, bobSigned, oneTime, signature := newPrekeyFixture(t)
			bundle := PreKeyBundle{
				IdentityKey:           bob.Public,
				SignedPreKeyID:        7,
				SignedPreKey:          bobSigned.Public,
				SignedPreKeySignature: signature,
			}
			var storedOneTime *PreKey
			if withOneTime {
				bundle.OneTimePreKeyID = 9
				bundle.OneTimePreKey = &oneTime.Public
				storedOneTime = &PreKey{ID: 9, Pair: oneTime}
			}

			init, err := Initiate(alice, bundle)
			if err != nil {
				t.Fatal(err)
			}
			aliceState, err := NewInitiator(init.Keys.RootKey, bobSigned.Public, init.Keys.ChainKey)
			if err != nil {
				t.Fatal(err)
			}
			first, err := aliceState.Encrypt([]byte("first"), alice.Public, bob.Public)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := init.BuildPreKeyMessage(alice.Public, 1234, first)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParsePreKeyMessage(wire)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.RegistrationID != 1234 || parsed.SignedPreKeyID != 7 ||
				parsed.BaseKey != init.EphemeralPublic || parsed.IdentityKey != alice.Public ||
				parsed.PreKeyID != bundle.OneTimePreKeyID {
				t.Fatalf("parsed = %#v", parsed)
			}

			bobState, plaintext, err := AcceptPreKeyMessage(wire, bob, SignedPreKey{ID: 7, Pair: bobSigned, Signature: signature}, storedOneTime)
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			if !bytes.Equal(plaintext, []byte("first")) {
				t.Fatalf("plaintext = %q", plaintext)
			}

			reply, err := bobState.Encrypt([]byte("reply"), bob.Public, alice.Public)
			if err != nil {
				t.Fatal(err)
			}
			got, err := aliceState.Decrypt(reply, bob.Public, alice.Public)
			if err != nil {
				t.Fatalf("reply decrypt: %v", err)
			}
			if !bytes.Equal(got, []byte("reply")) {
				t.Fatalf("reply = %q", got)
			}
		})
	}
}

func TestAcceptPreKeyMessageRejectsMismatch(t *testing.T) {
	alice, bob, bobSigned, oneTime, signature := newPrekeyFixture(t)
	bundle := PreKeyBundle{
		IdentityKey:           bob.Public,
		SignedPreKeyID:        7,
		SignedPreKey:          bobSigned.Public,
		SignedPreKeySignature: signature,
		OneTimePreKeyID:       9,
		OneTimePreKey:         &oneTime.Public,
	}
	init, err := Initiate(alice, bundle)
	if err != nil {
		t.Fatal(err)
	}
	aliceState, _ := NewInitiator(init.Keys.RootKey, bobSigned.Public, init.Keys.ChainKey)
	first, _ := aliceState.Encrypt([]byte("x"), alice.Public, bob.Public)
	wire, err := init.BuildPreKeyMessage(alice.Public, 1, first)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := AcceptPreKeyMessage(wire, bob, SignedPreKey{ID: 8, Pair: bobSigned}, &PreKey{ID: 9, Pair: oneTime}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("wrong signed prekey id: %v", err)
	}
	if _, _, err := AcceptPreKeyMessage(wire, bob, SignedPreKey{ID: 7, Pair: bobSigned}, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("missing one-time: %v", err)
	}
	if _, _, err := AcceptPreKeyMessage(wire, bob, SignedPreKey{ID: 7, Pair: bobSigned}, &PreKey{ID: 8, Pair: oneTime}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("wrong one-time id: %v", err)
	}

	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, err := AcceptPreKeyMessage(tampered, bob, SignedPreKey{ID: 7, Pair: bobSigned}, &PreKey{ID: 9, Pair: oneTime}); err == nil {
		t.Fatal("tampered message accepted")
	}
}

func TestParsePreKeyMessageInvalid(t *testing.T) {
	valid, err := BuildPreKeyMessage(PreKeyMessage{
		RegistrationID: 1, SignedPreKeyID: 2,
		BaseKey: fixedKey(t, 0x33).Public, IdentityKey: fixedKey(t, 0x44).Public,
		Message: []byte("x"),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"short":         nil,
		"wrong version": {0x32, 0x00},
		"truncated":     valid[:len(valid)-1],
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePreKeyMessage(wire); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("want ErrInvalidMessage, got %v", err)
			}
		})
	}
	if _, err := BuildPreKeyMessage(PreKeyMessage{RegistrationID: 1, SignedPreKeyID: 2}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("empty embedded message: %v", err)
	}
}
