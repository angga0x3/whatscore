package signal

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// TestPreKeyMessageCarriesTheKeyIDsItUses pins the field mapping a real
// prekey message exposed: the wire carries registrationId (5), preKeyId (1),
// signedPreKeyId (6), baseKey (2), identityKey (3), and message (4).
//
// This was verified against a genuine inbound message from the live service,
// which decoded as registrationID=1388247345 preKeyID=0 signedPreKeyID=1. The
// point of the test is that preKeyID=0 is legal: it means "no one-time prekey",
// and a client that cannot open such a message after a successful pairing has
// lost the signed prekey, not misparsed the envelope.
func TestPreKeyMessageCarriesTheKeyIDsItUses(t *testing.T) {
	// On the wire each key carries a libsignal curve-type prefix, and the
	// whole envelope is prefixed with the current version byte (PF-060).
	base := append([]byte{IdentityKeyPrefix}, make([]byte, KeySize)...)
	base[1] = 0x29
	ident := append([]byte{IdentityKeyPrefix}, make([]byte, KeySize)...)
	ident[1] = 0x17
	inner := []byte{0x33, 0x12}

	raw, err := proto.Marshal(&protobuf.PreKeySignalMessage{
		RegistrationId: proto.Uint32(1388247345),
		PreKeyId:       proto.Uint32(0),
		SignedPreKeyId: proto.Uint32(1),
		BaseKey:        base,
		IdentityKey:    ident,
		Message:        inner,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParsePreKeyMessage(append([]byte{WireVersion}, raw...))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.SignedPreKeyID != 1 {
		t.Fatalf("signed prekey id = %d, want 1", parsed.SignedPreKeyID)
	}
	if parsed.PreKeyID != 0 {
		t.Fatalf("prekey id = %d, want 0 (no one-time prekey)", parsed.PreKeyID)
	}
	if parsed.RegistrationID != 1388247345 {
		t.Fatalf("registration id = %d", parsed.RegistrationID)
	}
	var wantBase [KeySize]byte
	copy(wantBase[:], base[1:])
	if parsed.BaseKey != wantBase {
		t.Fatalf("base key changed: %x != %x", parsed.BaseKey, wantBase)
	}
}

// TestAcceptRejectsAMissingSignedPreKey pins the failure a lost key produces,
// so it is diagnosable instead of looking like corruption.
func TestAcceptRejectsAMissingSignedPreKey(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// A signed prekey the message does not reference.
	other, err := GenerateSignedPreKey(9, XEdDSASigner{Private: identity.Private})
	if err != nil {
		t.Fatal(err)
	}
	base := append([]byte{IdentityKeyPrefix}, make([]byte, KeySize)...)
	ident := append([]byte{IdentityKeyPrefix}, identity.Public[:]...)
	raw, err := proto.Marshal(&protobuf.PreKeySignalMessage{
		RegistrationId: proto.Uint32(1),
		SignedPreKeyId: proto.Uint32(1),
		BaseKey:        base,
		IdentityKey:    ident,
		Message:        []byte{0x01},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = AcceptPreKeyMessage(append([]byte{WireVersion}, raw...), identity, other, nil)
	if err == nil {
		t.Fatal("accepted a message for a signed prekey we do not hold")
	}
}
