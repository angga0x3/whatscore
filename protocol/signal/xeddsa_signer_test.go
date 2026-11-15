package signal

import (
	"testing"

	"github.com/angga0x3/whatscore/internal/xeddsa"
)

func TestXEdDSASignerPreKeyVerifies(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer := XEdDSASigner{Private: identity.Private}

	preKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.SignPreKey(preKey.Public)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifySignedPreKey(identity.Public, preKey.Public, signature); err != nil {
		t.Fatalf("signed prekey rejected by our verifier: %v", err)
	}
	// The verifier is the one live-confirmed path, so also check through it
	// directly with a tampered message.
	message := append([]byte{PublicKeyType}, preKey.Public[:]...)
	if err := xeddsa.Verify(identity.Public, append(message, 0x00), signature); err == nil {
		t.Fatal("tampered signed-prekey message accepted")
	}
}

func TestXEdDSASignerDeviceIdentity(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer := XEdDSASigner{Private: identity.Private}
	details := []byte("synthetic device details")
	accountKey := make([]byte, KeySize)
	accountKey[0] = 0x07

	signature, err := signer.SignDeviceIdentity(details, identity.Public[:], accountKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	message := make([]byte, 0, 2+len(details)+2*KeySize)
	message = append(message, DeviceSignaturePrefix...)
	message = append(message, details...)
	message = append(message, identity.Public[:]...)
	message = append(message, accountKey...)
	if err := xeddsa.Verify(identity.Public, message, signature); err != nil {
		t.Fatalf("device signature rejected: %v", err)
	}

	if _, err := signer.SignDeviceIdentity(details, make([]byte, 31), accountKey); err == nil {
		t.Fatal("short identity key accepted")
	}
	if _, err := signer.SignDeviceIdentity(details, identity.Public[:], make([]byte, 31)); err == nil {
		t.Fatal("short account key accepted")
	}
}
