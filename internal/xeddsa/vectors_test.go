package xeddsa

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// vectors are generated with go.mau.fi/libsignal v0.2.2 (the reference
// implementation) by calling its CalculateSignature, then recorded here. They
// are inputs/outputs only: nothing in this package was used to produce them.
//
// Reference generator, run once outside this repo:
//
//	ecc.CalculateSignature(ecc.NewDjbECPrivateKey(priv), msg)
//
// with priv clamped and randomness drawn by the reference itself, so the
// signature bytes below are authoritative even though the randomness is not
// reproducible. The public key is X25519(priv, basepoint).
type vector struct {
	name string
	priv string
	pub  string
	msg  string
	sig  string
}

var referenceVectors = []vector{
	{
		name: "vector 0",
		priv: "60934f48a57d7a8907cb8db5d05f483587f31cbbc101f9f839dc6ac56dac1d7c",
		pub:  "5a77d9e4d5999dc0b6354e53b16f3566394b3312045bda454342af93dde0cf1f",
		msg:  "7768617473636f72652078656464736120766563746f722030",
		sig:  "d92431e7f22b9aa97cec94438fe489617ca732404f67950974ebf4332ce15306882518b74f5dca865b665ff963d0a900c3b860b3339d841ea31f4ca0b539ae09",
	},
	{
		name: "vector 1",
		priv: "80f927f0efe8eb3d4d1e10cc7eb95a371e8a760a0d75016eda8d85b94b5d996d",
		pub:  "822fadc0bfd8f1e57660f4b41290d0d58ae9e4b821d52c72d8ea038b7da1552a",
		msg:  "7768617473636f72652078656464736120766563746f722031",
		sig:  "3dede6ab2710ff3aa055f3ce0da95732754338299c6f3b830f14fe10eade51eeb13d5074fd8fb6bec34d1a76eab6356ac7acfcd9b1d93ceb11b0289d852fec89",
	},
	{
		name: "vector 2",
		priv: "200909d24ffd4ca351e560a88fd21922ce74b61ddc506f5a466b20818e955b61",
		pub:  "ba1994231e57fd5c6434bad5eb4880f63ac79e61cc4d08773ea654ad375c2547",
		msg:  "7768617473636f72652078656464736120766563746f722032",
		sig:  "a0b9debf80bc2e2d5496a0c0d66e445f30a9356b71d48c1295242ec2ecaf84860fa50cf91dd9f4ea8b1d01e088b2688078d55c84187e2cef16c5bf302f184d01",
	},
	{
		name: "vector 3",
		priv: "80f6eeb42723be88405c26a6fa6f801d062520842411d72282bfb541eaab6e7b",
		pub:  "18fa036a549a5c4b729ebaf86902b3ae6cf91d76a54a7d1d612f8a5924b42623",
		msg:  "7768617473636f72652078656464736120766563746f722033",
		sig:  "55723aee4327b2748766bc7f993f1ac540c189a2696308e44a5d546695eeba6a8e4829c8232374dc297e4153426dbe89f6adf87c0e2eec0b97ce1116eff60402",
	},
}

func decode(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("bad hex %q: %v", value, err)
	}
	return raw
}

// TestVerifyReferenceVectors is the important direction: signatures produced by
// the reference implementation must verify here. That is what proves the
// verifier matches libsignal, including the sign-bit handling.
func TestVerifyReferenceVectors(t *testing.T) {
	for _, vec := range referenceVectors {
		t.Run(vec.name, func(t *testing.T) {
			var pub [32]byte
			copy(pub[:], decode(t, vec.pub))
			if err := Verify(pub, decode(t, vec.msg), decode(t, vec.sig)); err != nil {
				t.Fatalf("reference signature rejected: %v", err)
			}
			if err := Verify(pub, []byte("tampered"), decode(t, vec.sig)); err == nil {
				t.Fatal("tampered message accepted")
			}
		})
	}
}

// TestSignIsAcceptedByReferenceShape proves our signer produces a shape the
// verifier accepts, and that the sign bit round-trips through signature[63].
func TestSignIsAcceptedByReferenceShape(t *testing.T) {
	for _, vec := range referenceVectors {
		t.Run(vec.name, func(t *testing.T) {
			var priv [32]byte
			copy(priv[:], decode(t, vec.priv))
			var pub [32]byte
			copy(pub[:], decode(t, vec.pub))
			msg := decode(t, vec.msg)

			randomness := bytes.Repeat([]byte{0x2a}, 64)
			sig, err := Sign(priv, msg, randomness)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := Verify(pub, msg, sig); err != nil {
				t.Fatalf("our signature rejected by our verifier: %v", err)
			}
			if err := Verify(pub, []byte("other"), sig); err == nil {
				t.Fatal("tampered message accepted")
			}
			// Signing is deterministic for fixed randomness: the same inputs
			// must reproduce the same bytes.
			again, err := Sign(priv, msg, randomness)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig, again) {
				t.Fatal("signing is not deterministic for fixed randomness")
			}
		})
	}
}

func TestSignRequires64BytesOfRandomness(t *testing.T) {
	var priv [32]byte
	if _, err := Sign(priv, []byte("m"), make([]byte, 32)); err == nil {
		t.Fatal("short randomness accepted")
	}
}

func TestVerifyRejectsWrongLength(t *testing.T) {
	var pub [32]byte
	if err := Verify(pub, []byte("m"), make([]byte, 63)); err == nil {
		t.Fatal("63-byte signature accepted")
	}
}
