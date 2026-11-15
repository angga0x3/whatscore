package signal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func fixedKey(tb testing.TB, seed byte) KeyPair {
	tb.Helper()
	var pair KeyPair
	for i := range pair.Private {
		pair.Private[i] = seed
	}
	clamp(&pair.Private)
	pub, err := curve25519.X25519(pair.Private[:], curve25519.Basepoint)
	if err != nil {
		tb.Fatal(err)
	}
	copy(pair.Public[:], pub)
	return pair
}

func signingKey(tb testing.TB) (ed25519.PrivateKey, KeyPair) {
	tb.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	digest := sha512.Sum512(private.Seed())
	var pair KeyPair
	copy(pair.Private[:], digest[:32])
	clamp(&pair.Private)
	pub, err := curve25519.X25519(pair.Private[:], curve25519.Basepoint)
	if err != nil {
		tb.Fatal(err)
	}
	copy(pair.Public[:], pub)
	return private, pair
}

// signPreKey signs a prekey the way production does: XEdDSA over the clamped
// identity scalar (PF-067). An Ed25519 signature here would only verify when the
// key's Edwards x happens to be even.
func signPreKey(tb testing.TB, identity KeyPair, preKey [32]byte) []byte {
	tb.Helper()
	signature, err := XEdDSASigner{Private: identity.Private}.SignPreKey(preKey)
	if err != nil {
		tb.Fatalf("sign prekey: %v", err)
	}
	return signature
}

func TestX3DHAgreement(t *testing.T) {
	for _, withOneTime := range []bool{false, true} {
		t.Run(map[bool]string{false: "no one-time", true: "one-time"}[withOneTime], func(t *testing.T) {
			_, alice := signingKey(t)
			_, bob := signingKey(t)
			bobSigned := fixedKey(t, 0x21)
			bobOneTime := fixedKey(t, 0x31)

			bundle := PreKeyBundle{
				IdentityKey:           bob.Public,
				SignedPreKeyID:        7,
				SignedPreKey:          bobSigned.Public,
				SignedPreKeySignature: signPreKey(t, bob, bobSigned.Public),
			}
			var oneTime *KeyPair
			if withOneTime {
				bundle.OneTimePreKeyID = 9
				bundle.OneTimePreKey = &bobOneTime.Public
				oneTime = &bobOneTime
			}

			initiator, err := Initiate(alice, bundle)
			if err != nil {
				t.Fatalf("Initiate: %v", err)
			}
			responder, err := Respond(bob, bobSigned, oneTime, alice.Public, initiator.EphemeralPublic)
			if err != nil {
				t.Fatalf("Respond: %v", err)
			}
			if initiator.Keys != responder {
				t.Fatalf("keys differ:\n initiator %x\n responder %x", initiator.Keys, responder)
			}
			if initiator.SignedPreKeyID != 7 || initiator.HasOneTimePreKey != withOneTime ||
				initiator.OneTimePreKeyID != bundle.OneTimePreKeyID {
				t.Fatalf("result = %#v", initiator)
			}
		})
	}
}

func TestX3DHRejectsBadSignature(t *testing.T) {
	_, alice := signingKey(t)
	_, bob := signingKey(t)
	bobSigned := fixedKey(t, 0x21)
	_, otherSigner := signingKey(t)

	cases := map[string][]byte{
		"missing":   nil,
		"short":     {1, 2, 3},
		"wrong key": signPreKey(t, otherSigner, bobSigned.Public),
	}
	for name, signature := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := PreKeyBundle{
				IdentityKey: bob.Public, SignedPreKey: bobSigned.Public, SignedPreKeySignature: signature,
			}
			if _, err := Initiate(alice, bundle); !errors.Is(err, ErrInvalidBundle) && !errors.Is(err, ErrBadSignature) {
				t.Fatalf("want signature error, got %v", err)
			}
		})
	}
}

type signalVector struct {
	Name           string `json:"name"`
	AliceIdentity  string `json:"alice_identity_priv"`
	BobIdentity    string `json:"bob_identity_priv"`
	BobIdentityPub string `json:"bob_identity_pub"`
	BobSigned      string `json:"bob_signed_priv"`
	BobSignedPub   string `json:"bob_signed_pub"`
	BobOneTime     string `json:"bob_one_time_priv"`
	BobOneTimePub  string `json:"bob_one_time_pub"`
	Ephemeral      string `json:"ephemeral_priv"`
	EphemeralPub   string `json:"ephemeral_pub"`
	DH1            string `json:"dh1"`
	DH2            string `json:"dh2"`
	DH3            string `json:"dh3"`
	DH4            string `json:"dh4"`
	Root           string `json:"root_key"`
	Chain          string `json:"chain_key"`
}

func decodeHex(t *testing.T, value string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad hex %q: %v", value, err)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func TestX3DHVectors(t *testing.T) {
	raw, err := os.ReadFile("../../tests/fixtures/signal_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var document struct {
		Info    string         `json:"info"`
		Vectors []signalVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.Info != KDFInfo {
		t.Fatalf("info = %q", document.Info)
	}
	if len(document.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vector := range document.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			alice := KeyPair{Private: decodeHex(t, vector.AliceIdentity)}
			alice.Public = derivePub(t, alice.Private)
			bob := KeyPair{Private: decodeHex(t, vector.BobIdentity)}
			bob.Public = derivePub(t, bob.Private)
			bobSigned := KeyPair{Private: decodeHex(t, vector.BobSigned)}
			bobSigned.Public = derivePub(t, bobSigned.Private)
			bobOneTime := KeyPair{Private: decodeHex(t, vector.BobOneTime)}
			bobOneTime.Public = derivePub(t, bobOneTime.Private)
			ephemeral := KeyPair{Private: decodeHex(t, vector.Ephemeral)}
			ephemeral.Public = derivePub(t, ephemeral.Private)

			if got := derivePub(t, bob.Private); got != decodeHex(t, vector.BobIdentityPub) {
				t.Fatalf("bob identity pub = %x", got)
			}
			if got := derivePub(t, bobSigned.Private); got != decodeHex(t, vector.BobSignedPub) {
				t.Fatalf("bob signed pub = %x", got)
			}
			if got := derivePub(t, bobOneTime.Private); got != decodeHex(t, vector.BobOneTimePub) {
				t.Fatalf("bob one-time pub = %x", got)
			}
			if got := derivePub(t, ephemeral.Private); got != decodeHex(t, vector.EphemeralPub) {
				t.Fatalf("ephemeral pub = %x", got)
			}

			dh1, err := dh(alice.Private, bobSigned.Public)
			if err != nil {
				t.Fatal(err)
			}
			dh2, err := dh(ephemeral.Private, bob.Public)
			if err != nil {
				t.Fatal(err)
			}
			dh3, err := dh(ephemeral.Private, bobSigned.Public)
			if err != nil {
				t.Fatal(err)
			}
			dh4, err := dh(ephemeral.Private, bobOneTime.Public)
			if err != nil {
				t.Fatal(err)
			}
			for i, got := range [][32]byte{dh1, dh2, dh3, dh4} {
				want := decodeHex(t, []string{vector.DH1, vector.DH2, vector.DH3, vector.DH4}[i])
				if got != want {
					t.Fatalf("dh%d = %x, want %x", i+1, got, want)
				}
			}
			keys, err := deriveKeys(masterSecret(dh1, dh2, dh3, dh4))
			if err != nil {
				t.Fatal(err)
			}
			if keys.RootKey != decodeHex(t, vector.Root) || keys.ChainKey != decodeHex(t, vector.Chain) {
				t.Fatalf("keys = %x/%x", keys.RootKey, keys.ChainKey)
			}
		})
	}
}

func derivePub(t *testing.T, private [32]byte) [32]byte {
	t.Helper()
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], pub)
	return out
}
