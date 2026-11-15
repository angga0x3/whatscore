package pairing

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/internal/xeddsa"
	"github.com/angga0x3/whatscore/protocol/noise"
	"github.com/angga0x3/whatscore/protocol/protobuf"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// buildServerPairSuccess assembles the device-identity container the way the
// server does: an account key signs 0x06,0x00 ‖ details ‖ identityPub, and the
// result is wrapped in an HMAC keyed with the adv secret.
func buildServerPairSuccess(t *testing.T, advSecret, identityPub []byte) []byte {
	t.Helper()
	accountKey, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("account key: %v", err)
	}
	deviceDetails, err := proto.Marshal(&protobuf.ADVDeviceIdentity{
		RawID:       proto.Uint32(884371735),
		Timestamp:   proto.Uint64(1794733065),
		KeyIndex:    proto.Uint32(8),
		AccountType: protobuf.ADVEncryptionType_E2EE.Enum(),
		DeviceType:  protobuf.ADVEncryptionType_E2EE.Enum(),
	})
	if err != nil {
		t.Fatalf("device details: %v", err)
	}

	// The account signature is over 0x06,0x00 ‖ details ‖ identityPub. The
	// XEdDSA construction signs 32 bytes after a curve-type prefix, so this
	// signs a hash-free message of that shape directly through the internal
	// signer rather than through SignPreKey, which fixes its own prefix.
	message := append(append([]byte{6, 0}, deviceDetails...), identityPub...)
	accountSig, err := signRaw(accountKey, message)
	if err != nil {
		t.Fatalf("account signature: %v", err)
	}

	signed, err := proto.Marshal(&protobuf.ADVSignedDeviceIdentity{
		Details:             deviceDetails,
		AccountSignatureKey: accountKey.Pub[:],
		AccountSignature:    accountSig,
	})
	if err != nil {
		t.Fatalf("signed identity: %v", err)
	}

	mac := hmac.New(sha256.New, advSecret)
	mac.Write(signed)
	container, err := proto.Marshal(&protobuf.ADVSignedDeviceIdentityHMAC{
		Details:     signed,
		HMAC:        mac.Sum(nil),
		AccountType: protobuf.ADVEncryptionType_E2EE.Enum(),
	})
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	return container
}

// signRaw signs an arbitrary message with the XEdDSA construction, which is
// what the server's account-signature step does.
func signRaw(key noise.KeyPair, message []byte) ([]byte, error) {
	randomness := make([]byte, 64)
	if _, err := rand.Read(randomness); err != nil {
		return nil, err
	}
	return xeddsa.Sign(key.Priv, message, randomness)
}

// TestPairSuccessToConfirmation walks the whole verified path with a container
// the server would produce: verify the HMAC and account signature, then build
// the pair-device-sign payload. This is what a real scan triggers, and until
// the token table learned the pair-success tokens no test could reach it.
func TestPairSuccessToConfirmation(t *testing.T) {
	identity, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	var advSecret [32]byte
	if _, err := rand.Read(advSecret[:]); err != nil {
		t.Fatalf("adv secret: %v", err)
	}

	container := buildServerPairSuccess(t, advSecret[:], identity.Pub[:])

	verified, err := VerifyDeviceIdentity(container, advSecret[:], identity.Pub[:])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.KeyIndex != 8 {
		t.Fatalf("key index is %d, want 8", verified.KeyIndex)
	}

	signed, err := SignDeviceIdentity(verified, identity.Pub[:], signal.XEdDSASigner{Private: identity.Priv})
	if err != nil {
		t.Fatalf("sign device identity: %v", err)
	}
	var out protobuf.ADVSignedDeviceIdentity
	if err := proto.Unmarshal(signed, &out); err != nil {
		t.Fatalf("unmarshal confirmation: %v", err)
	}
	if len(out.GetDeviceSignature()) != 64 {
		t.Fatalf("device signature is %d bytes", len(out.GetDeviceSignature()))
	}
	if len(out.GetAccountSignatureKey()) != 0 {
		t.Fatal("account key leaked into the confirmation")
	}
	if len(out.GetAccountSignature()) != 64 {
		t.Fatal("account signature missing from the confirmation")
	}
}
