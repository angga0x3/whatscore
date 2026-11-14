package noise

import (
	"crypto/ed25519"
	"crypto/hmac"
	"fmt"
	"math/big"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// p25519 is the field prime of Curve25519/Ed25519: 2^255 - 19 (PF-009).
var p25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// CertError is the typed error for server certificate chain verification
// failures (PF-009). Stage names the PF-009 validation step that failed;
// Err carries the specific cause. errors.Is matches both
// ErrCertificateInvalid and the wrapped cause.
type CertError struct {
	// Stage is the failed PF-009 validation step, e.g. "root-signature",
	// "intermediate-issuer", "serial-chain", "leaf-key", "validity".
	Stage string

	// Err is the specific cause.
	Err error
}

// Error implements the error interface.
func (e *CertError) Error() string {
	return fmt.Sprintf("noise: server certificate verification failed at %q: %v", e.Stage, e.Err)
}

// Unwrap makes errors.Is match both ErrCertificateInvalid and the
// underlying cause.
func (e *CertError) Unwrap() []error {
	return []error{ErrCertificateInvalid, e.Err}
}

// certErrf builds a *CertError for the given PF-009 stage.
func certErrf(stage, format string, args ...any) *CertError {
	return &CertError{Stage: stage, Err: fmt.Errorf(format, args...)}
}

// VerifyServerCert validates the decrypted serverHello.payload (PF-009):
// a protobuf CertChain whose leaf binds the decrypted server static key.
//
// Validation chain:
//  1. shape: intermediate and leaf certificates present, each with
//     Details and a 64-byte Signature;
//  2. root-signature: XEdDSA verification of intermediate.details under
//     the pinned 32-byte root public key;
//  3. intermediate-issuer: intermediate.issuerSerial == 0 and
//     intermediate key is a 32-byte Curve25519 key;
//  4. intermediate-signature: XEdDSA verification of leaf.details under
//     intermediate.key;
//  5. serial-chain: leaf.issuerSerial == intermediate.serial;
//  6. leaf-key: leaf.key equals serverStatic (constant-time compare —
//     the binding between the certificate and the decrypted server
//     static key);
//  7. validity: leaf validity window in Unix seconds covers now.
//
// serverStatic is the decrypted serverHello.static from PF-007; rootPub
// is the pinned 32-byte root public key (public constant, PF-009 notes).
// A nil return means the chain is valid.
func VerifyServerCert(certBytes, serverStatic, rootPub []byte) error {
	if len(rootPub) != 32 {
		return certErrf("root", "root public key must be 32 bytes, got %d", len(rootPub))
	}
	if len(serverStatic) != 32 {
		return certErrf("server-static", "server static key must be 32 bytes, got %d", len(serverStatic))
	}

	var chain protobuf.CertChain
	if err := proto.Unmarshal(certBytes, &chain); err != nil {
		return fmt.Errorf("%w: unmarshaling certificate chain: %w", ErrBadPayload, err)
	}
	intermediate, leaf := chain.GetIntermediate(), chain.GetLeaf()
	switch {
	case intermediate == nil:
		return certErrf("shape", "certificate chain has no intermediate")
	case leaf == nil:
		return certErrf("shape", "certificate chain has no leaf")
	case len(intermediate.GetDetails()) == 0:
		return certErrf("shape", "intermediate has no details")
	case len(leaf.GetDetails()) == 0:
		return certErrf("shape", "leaf has no details")
	case len(intermediate.GetSignature()) != 64:
		return certErrf("shape", "intermediate signature must be 64 bytes, got %d", len(intermediate.GetSignature()))
	case len(leaf.GetSignature()) != 64:
		return certErrf("shape", "leaf signature must be 64 bytes, got %d", len(leaf.GetSignature()))
	}

	var root [32]byte
	copy(root[:], rootPub)
	if err := verifyXEdDSA(root, intermediate.GetDetails(), intermediate.GetSignature()); err != nil {
		return certErrf("root-signature", "intermediate not signed by pinned root: %w", err)
	}

	intDetails, err := parseCertDetails(intermediate.GetDetails())
	if err != nil {
		return certErrf("intermediate-details", "%w", err)
	}
	if intDetails.GetIssuerSerial() != 0 {
		return certErrf("intermediate-issuer", "intermediate.issuerSerial must be 0, got %d", intDetails.GetIssuerSerial())
	}
	if len(intDetails.GetKey()) != 32 {
		return certErrf("intermediate-issuer", "intermediate.key must be 32 bytes, got %d", len(intDetails.GetKey()))
	}
	var intermediateKey [32]byte
	copy(intermediateKey[:], intDetails.GetKey())

	if err := verifyXEdDSA(intermediateKey, leaf.GetDetails(), leaf.GetSignature()); err != nil {
		return certErrf("intermediate-signature", "leaf not signed by intermediate key: %w", err)
	}

	leafDetails, err := parseCertDetails(leaf.GetDetails())
	if err != nil {
		return certErrf("leaf-details", "%w", err)
	}
	if leafDetails.GetIssuerSerial() != intDetails.GetSerial() {
		return certErrf("serial-chain", "leaf.issuerSerial %d does not match intermediate.serial %d",
			leafDetails.GetIssuerSerial(), intDetails.GetSerial())
	}
	if !hmac.Equal(leafDetails.GetKey(), serverStatic) {
		return certErrf("leaf-key", "leaf.key does not match the decrypted server static key")
	}

	now := uint64(time.Now().Unix())
	if nb, na := leafDetails.GetNotBefore(), leafDetails.GetNotAfter(); now < nb || now > na {
		return certErrf("validity", "now %d outside leaf validity window [%d, %d]", now, nb, na)
	}
	return nil
}

// parseCertDetails decodes a protobuf NoiseCertificate.Details blob
// (PF-009). Malformed bytes yield ErrBadPayload.
func parseCertDetails(details []byte) (*protobuf.CertChain_NoiseCertificate_Details, error) {
	var d protobuf.CertChain_NoiseCertificate_Details
	if err := proto.Unmarshal(details, &d); err != nil {
		return nil, fmt.Errorf("%w: unmarshaling certificate details: %w", ErrBadPayload, err)
	}
	return &d, nil
}

// verifyXEdDSA verifies a 64-byte XEdDSA signature (PF-009): Curve25519
// public keys are Montgomery u coordinates, while the signatures are
// standard Ed25519. Verification therefore converts the Montgomery key to
// its Edwards y coordinate (y = (u−1)/(u+1) mod p), encodes y as a
// 32-byte little-endian value with the sign bit cleared, and verifies
// with crypto/ed25519. This mirrors the reference implementations' use of
// a public-domain Montgomery→Edwards conversion.
//
// This is a public-key operation; constant-time guarantees are not
// required and are not provided (documented deviation from general
// crypto-code review policy, per PF-009).
func verifyXEdDSA(pub [32]byte, msg, sig []byte) error {
	y, err := edwardsYFromMontgomeryU(pub)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(y), msg, sig) {
		return fmt.Errorf("noise: ed25519 signature verification failed")
	}
	return nil
}

// edwardsYFromMontgomeryU converts a Curve25519 Montgomery u coordinate
// to the corresponding Edwards y coordinate (PF-009):
//
//	y = (u − 1) · (u + 1)⁻¹ mod p,  p = 2^255 − 19
//
// u is decoded little-endian; the result is encoded little-endian with
// the Ed25519 sign bit (high bit of byte 31) cleared, i.e. it assumes the
// Edwards x coordinate is even, as it is for the WhatsApp server keys
// this conversion targets. An error is returned when u ≡ −1 (mod p),
// where u + 1 is not invertible.
func edwardsYFromMontgomeryU(pub [32]byte) ([]byte, error) {
	uLE := make([]byte, 32)
	for i := range pub {
		uLE[i] = pub[31-i] // decode little-endian into big.Int
	}
	u := new(big.Int).SetBytes(uLE)

	uPlus1 := new(big.Int).Add(u, big.NewInt(1))
	uPlus1.Mod(uPlus1, p25519)
	if uPlus1.Sign() == 0 {
		return nil, fmt.Errorf("noise: montgomery u + 1 is not invertible mod p")
	}
	inv := new(big.Int).ModInverse(uPlus1, p25519)
	if inv == nil {
		return nil, fmt.Errorf("noise: montgomery u + 1 is not invertible mod p")
	}

	uMinus1 := new(big.Int).Sub(u, big.NewInt(1))
	y := new(big.Int).Mul(uMinus1, inv)
	y.Mod(y, p25519)

	// Encode y as 32-byte little-endian and clear the Ed25519 sign bit.
	be := y.FillBytes(make([]byte, 32))
	yBytes := make([]byte, 32)
	for i := range be {
		yBytes[i] = be[31-i]
	}
	yBytes[31] &= 0x7f
	return yBytes, nil
}
