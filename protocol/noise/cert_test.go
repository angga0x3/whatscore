package noise

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

var p25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// buildTestCertChainOpts carries the material for one synthetic
// two-certificate chain (PF-009): the test root signs the intermediate
// details, the intermediate key signs the leaf details, and the leaf key
// binds the server static key.
type buildTestCertChainOpts struct {
	rootEd    ed25519.PrivateKey // signs intermediate.details
	intEd     ed25519.PrivateKey // signs leaf.details
	intMont   [32]byte           // intermediate.key (Montgomery u)
	leafKey   []byte             // leaf.key (the server static public key)
	notBefore uint64
	notAfter  uint64
}

// marshalTestDetails serializes one NoiseCertificate.Details (PF-009
// field numbers: serial=1, issuerSerial=2, key=3, notBefore=4,
// notAfter=5).
func marshalTestDetails(t *testing.T, serial, issuerSerial uint32, key []byte, notBefore, notAfter uint64) []byte {
	t.Helper()
	s, i := serial, issuerSerial
	nb, na := notBefore, notAfter
	raw, err := proto.Marshal(&protobuf.CertChain_NoiseCertificate_Details{
		Serial:       &s,
		IssuerSerial: &i,
		Key:          append([]byte(nil), key...),
		NotBefore:    &nb,
		NotAfter:     &na,
	})
	if err != nil {
		t.Fatalf("marshal details: %v", err)
	}
	return raw
}

// buildTestCertChainStruct assembles the protobuf CertChain (PF-009:
// leaf=1, intermediate=2; each certificate details=1, signature=2) with
// serials 1/0 for the intermediate and 2/1 for the leaf.
func buildTestCertChainStruct(t *testing.T, o buildTestCertChainOpts) *protobuf.CertChain {
	t.Helper()
	intDetails := marshalTestDetails(t, 1, 0, o.intMont[:], o.notBefore, o.notAfter)
	leafDetails := marshalTestDetails(t, 2, 1, o.leafKey, o.notBefore, o.notAfter)
	return &protobuf.CertChain{
		Leaf: &protobuf.CertChain_NoiseCertificate{
			Details:   leafDetails,
			Signature: ed25519.Sign(o.intEd, leafDetails),
		},
		Intermediate: &protobuf.CertChain_NoiseCertificate{
			Details:   intDetails,
			Signature: ed25519.Sign(o.rootEd, intDetails),
		},
	}
}

// buildTestCertChain marshals the synthetic chain for use as a
// serverHello.payload plaintext.
func buildTestCertChain(t *testing.T, o buildTestCertChainOpts) []byte {
	t.Helper()
	raw, err := proto.Marshal(buildTestCertChainStruct(t, o))
	if err != nil {
		t.Fatalf("marshal cert chain: %v", err)
	}
	return raw
}

// generateTestSigningKeypair returns an Ed25519 private key whose public
// point has an even Edwards x coordinate together with the matching
// Montgomery u coordinate, proven by a self-signature round trip through
// the production verifyXEdDSA (PF-009). The retry loop is needed because
// the Montgomery↔Edwards conversion requires an even Edwards x and
// rejects degenerate points.
func generateTestSigningKeypair(t *testing.T) (ed25519.PrivateKey, [32]byte) {
	t.Helper()
	for attempt := 0; attempt < 1000; attempt++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 keygen: %v", err)
		}
		if pub[31]&0x80 != 0 {
			continue // odd Edwards x: the conversion would flip the sign bit
		}
		// Edwards y (sign bit cleared), decoded little-endian into big.Int.
		yBytes := make([]byte, 32)
		for i := range pub {
			yBytes[i] = pub[31-i]
		}
		yBytes[0] &= 0x7f
		y := new(big.Int).SetBytes(yBytes)

		// Edwards→Montgomery (PF-009 inverse map): u = (1+y)/(1-y) mod p.
		denom := new(big.Int).Sub(big.NewInt(1), y)
		denom.Mod(denom, p25519)
		if denom.Sign() == 0 {
			continue // y == 1: u at infinity
		}
		denomInv := new(big.Int).ModInverse(denom, p25519)
		if denomInv == nil {
			continue
		}
		num := new(big.Int).Add(big.NewInt(1), y)
		u := new(big.Int).Mul(num, denomInv)
		u.Mod(u, p25519)
		uPlus1 := new(big.Int).Add(u, big.NewInt(1))
		uPlus1.Mod(uPlus1, p25519)
		if uPlus1.Sign() == 0 {
			continue // degenerate for the reverse map
		}

		var mont [32]byte
		ube := u.FillBytes(make([]byte, 32))
		for i := range ube {
			mont[i] = ube[31-i]
		}

		// The pair is only usable if the production verifier accepts a
		// self-signature and rejects a tampered message.
		msg := []byte("whatscore synthetic test root self-check")
		sig := ed25519.Sign(priv, msg)
		if err := verifyXEdDSA(mont, msg, sig); err != nil {
			continue // conversion unusable for this key, retry
		}
		if err := verifyXEdDSA(mont, []byte("tampered"), sig); err == nil {
			t.Fatal("verifyXEdDSA accepted a tampered message")
		}
		return priv, mont
	}
	t.Fatal("could not generate a usable XEdDSA test keypair in 1000 attempts")
	return nil, [32]byte{}
}

// TestVerifyServerCertValid is the positive path of PF-009: a synthetic
// chain signed by a test root binds the decrypted server static key.
func TestVerifyServerCertValid(t *testing.T) {
	serverStatic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server static key: %v", err)
	}
	rootEd, rootMont := generateTestSigningKeypair(t)
	intEd, intMont := generateTestSigningKeypair(t)
	now := uint64(time.Now().Unix())
	certBytes := buildTestCertChain(t, buildTestCertChainOpts{
		rootEd:    rootEd,
		intEd:     intEd,
		intMont:   intMont,
		leafKey:   serverStatic.Pub[:],
		notBefore: now - 86400,
		notAfter:  now + 86400,
	})
	if err := VerifyServerCert(certBytes, serverStatic.Pub[:], rootMont[:]); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
}

// TestVerifyServerCertInvalid is table-driven over the PF-009 negative
// paths: tampered signatures, wrong pinned root, expired validity window,
// leaf key mismatch, and malformed input.
func TestVerifyServerCertInvalid(t *testing.T) {
	serverStatic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server static key: %v", err)
	}
	otherKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("decoy server static key: %v", err)
	}
	rootEd, rootMont := generateTestSigningKeypair(t)
	otherRootEd, otherRootMont := generateTestSigningKeypair(t)
	intEd, intMont := generateTestSigningKeypair(t)
	now := uint64(time.Now().Unix())

	mustMarshal := func(t *testing.T, c *protobuf.CertChain) []byte {
		t.Helper()
		raw, err := proto.Marshal(c)
		if err != nil {
			t.Fatalf("marshal cert chain: %v", err)
		}
		return raw
	}
	expectCertErr := func(t *testing.T, err error, wantStage string) {
		t.Helper()
		if err == nil {
			t.Fatal("want verification failure, got nil")
		}
		if !errors.Is(err, ErrCertificateInvalid) {
			t.Fatalf("want ErrCertificateInvalid, got %v", err)
		}
		var ce *CertError
		if !errors.As(err, &ce) {
			t.Fatalf("want *CertError, got %T", err)
		}
		if ce.Stage != wantStage {
			t.Fatalf("failure stage = %q, want %q (err: %v)", ce.Stage, wantStage, err)
		}
	}

	cases := []struct {
		name      string
		build     func(t *testing.T) ([]byte, []byte, []byte) // certBytes, serverStatic, rootPub
		wantStage string
	}{
		{
			name: "tampered leaf signature",
			build: func(t *testing.T) ([]byte, []byte, []byte) {
				chain := buildTestCertChainStruct(t, buildTestCertChainOpts{
					rootEd: rootEd, intEd: intEd, intMont: intMont,
					leafKey: serverStatic.Pub[:], notBefore: now - 86400, notAfter: now + 86400,
				})
				chain.Leaf.Signature[0] ^= 0x01
				return mustMarshal(t, chain), serverStatic.Pub[:], rootMont[:]
			},
			wantStage: "intermediate-signature",
		},
		{
			name: "tampered intermediate signature",
			build: func(t *testing.T) ([]byte, []byte, []byte) {
				chain := buildTestCertChainStruct(t, buildTestCertChainOpts{
					rootEd: rootEd, intEd: intEd, intMont: intMont,
					leafKey: serverStatic.Pub[:], notBefore: now - 86400, notAfter: now + 86400,
				})
				chain.Intermediate.Signature[63] ^= 0x80
				return mustMarshal(t, chain), serverStatic.Pub[:], rootMont[:]
			},
			wantStage: "root-signature",
		},
		{
			name: "wrong pinned root",
			build: func(t *testing.T) ([]byte, []byte, []byte) {
				raw := buildTestCertChain(t, buildTestCertChainOpts{
					rootEd: rootEd, intEd: intEd, intMont: intMont,
					leafKey: serverStatic.Pub[:], notBefore: now - 86400, notAfter: now + 86400,
				})
				return raw, serverStatic.Pub[:], otherRootMont[:]
			},
			wantStage: "root-signature",
		},
		{
			name: "expired notAfter",
			build: func(t *testing.T) ([]byte, []byte, []byte) {
				raw := buildTestCertChain(t, buildTestCertChainOpts{
					rootEd: rootEd, intEd: intEd, intMont: intMont,
					leafKey: serverStatic.Pub[:], notBefore: now - 86400, notAfter: now - 10,
				})
				return raw, serverStatic.Pub[:], rootMont[:]
			},
			wantStage: "validity",
		},
		{
			name: "not yet valid",
			build: func(t *testing.T) ([]byte, []byte, []byte) {
				raw := buildTestCertChain(t, buildTestCertChainOpts{
					rootEd: rootEd, intEd: intEd, intMont: intMont,
					leafKey: serverStatic.Pub[:], notBefore: now + 86400, notAfter: now + 172800,
				})
				return raw, serverStatic.Pub[:], rootMont[:]
			},
			wantStage: "validity",
		},
		{
			name: "leaf key does not bind the server static",
			build: func(t *testing.T) ([]byte, []byte, []byte) {
				raw := buildTestCertChain(t, buildTestCertChainOpts{
					rootEd: rootEd, intEd: intEd, intMont: intMont,
					leafKey: otherKey.Pub[:], notBefore: now - 86400, notAfter: now + 86400,
				})
				return raw, serverStatic.Pub[:], rootMont[:]
			},
			wantStage: "leaf-key",
		},
		{
			name: "intermediate issuerSerial nonzero",
			build: func(t *testing.T) ([]byte, []byte, []byte) {
				intDetails := marshalTestDetails(t, 1, 7, intMont[:], now-86400, now+86400)
				leafDetails := marshalTestDetails(t, 2, 1, serverStatic.Pub[:], now-86400, now+86400)
				chain := &protobuf.CertChain{
					Leaf: &protobuf.CertChain_NoiseCertificate{
						Details:   leafDetails,
						Signature: ed25519.Sign(intEd, leafDetails),
					},
					Intermediate: &protobuf.CertChain_NoiseCertificate{
						Details:   intDetails,
						Signature: ed25519.Sign(rootEd, intDetails),
					},
				}
				return mustMarshal(t, chain), serverStatic.Pub[:], rootMont[:]
			},
			wantStage: "intermediate-issuer",
		},
		{
			name: "leaf issuerSerial does not match intermediate serial",
			build: func(t *testing.T) ([]byte, []byte, []byte) {
				intDetails := marshalTestDetails(t, 1, 0, intMont[:], now-86400, now+86400)
				leafDetails := marshalTestDetails(t, 2, 9, serverStatic.Pub[:], now-86400, now+86400)
				chain := &protobuf.CertChain{
					Leaf: &protobuf.CertChain_NoiseCertificate{
						Details:   leafDetails,
						Signature: ed25519.Sign(intEd, leafDetails),
					},
					Intermediate: &protobuf.CertChain_NoiseCertificate{
						Details:   intDetails,
						Signature: ed25519.Sign(rootEd, intDetails),
					},
				}
				return mustMarshal(t, chain), serverStatic.Pub[:], rootMont[:]
			},
			wantStage: "serial-chain",
		},
		{
			name: "certificate chain has no leaf",
			build: func(t *testing.T) ([]byte, []byte, []byte) {
				intDetails := marshalTestDetails(t, 1, 0, intMont[:], now-86400, now+86400)
				chain := &protobuf.CertChain{
					Intermediate: &protobuf.CertChain_NoiseCertificate{
						Details:   intDetails,
						Signature: ed25519.Sign(rootEd, intDetails),
					},
				}
				return mustMarshal(t, chain), serverStatic.Pub[:], rootMont[:]
			},
			wantStage: "shape",
		},
		{
			name: "unparseable certificate bytes",
			build: func(_ *testing.T) ([]byte, []byte, []byte) {
				return []byte{0xff, 0xff, 0xff}, serverStatic.Pub[:], rootMont[:]
			},
			wantStage: "", // ErrBadPayload, not a *CertError
		},
		{
			name: "wrong root length",
			build: func(_ *testing.T) ([]byte, []byte, []byte) {
				return []byte{}, serverStatic.Pub[:], rootMont[:16]
			},
			wantStage: "root",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certBytes, serverStaticBytes, rootPub := tc.build(t)
			err := VerifyServerCert(certBytes, serverStaticBytes, rootPub)
			if tc.wantStage == "" {
				if !errors.Is(err, ErrBadPayload) {
					t.Fatalf("want ErrBadPayload, got %v", err)
				}
				return
			}
			expectCertErr(t, err, tc.wantStage)
		})
	}

	// Sanity: the honest chain built for the table would have passed — the
	// wrong-root case proves the pinned root is actually load-bearing.
	otherRootChain := buildTestCertChain(t, buildTestCertChainOpts{
		rootEd: otherRootEd, intEd: intEd, intMont: intMont,
		leafKey: serverStatic.Pub[:], notBefore: now - 86400, notAfter: now + 86400,
	})
	if err := VerifyServerCert(otherRootChain, serverStatic.Pub[:], otherRootMont[:]); err != nil {
		t.Fatalf("honest chain under its own root must verify: %v", err)
	}
}
