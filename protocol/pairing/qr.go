// Package pairing implements the device-pairing payloads of the WhatsApp
// multi-device flow. QR rendering is a caller concern.
//
// Status: Phase 3 start — QR payload construction/parsing only. The
// pair-device/pair-success exchange is not implemented yet.
package pairing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// QRURLPrefix is the fixed URL prefix of a pairing QR code (PF-015).
const QRURLPrefix = "https://wa.me/settings/linked_devices#"

// ErrInvalidQR is returned for malformed pairing payloads.
var ErrInvalidQR = errors.New("pairing: invalid QR payload")

// QRPayload is one pairing QR code.
type QRPayload struct {
	// Ref is the opaque reference from the server's <ref> child (ASCII).
	Ref string
	// NoisePublicKey is the client's Noise static public key.
	NoisePublicKey [32]byte
	// IdentityPublicKey is the client's Signal identity public key.
	IdentityPublicKey [32]byte
	// AdvSecret is the 32-byte companion advertising secret.
	AdvSecret [32]byte
	// ClientType is the opaque client-type field (empty when unknown).
	ClientType string
}

// Encode renders the payload as a QR string.
func (p QRPayload) Encode() (string, error) {
	if err := validateRef(p.Ref); err != nil {
		return "", err
	}
	if err := validateClientType(p.ClientType); err != nil {
		return "", err
	}
	return QRURLPrefix +
		p.Ref + "," +
		base64.StdEncoding.EncodeToString(p.NoisePublicKey[:]) + "," +
		base64.StdEncoding.EncodeToString(p.IdentityPublicKey[:]) + "," +
		base64.StdEncoding.EncodeToString(p.AdvSecret[:]) + "," +
		p.ClientType, nil
}

// ParseQR parses a QR string produced by Encode.
func ParseQR(code string) (QRPayload, error) {
	var payload QRPayload
	if !strings.HasPrefix(code, QRURLPrefix) {
		return payload, fmt.Errorf("%w: missing %q prefix", ErrInvalidQR, QRURLPrefix)
	}
	fields := strings.Split(strings.TrimPrefix(code, QRURLPrefix), ",")
	if len(fields) != 5 {
		return payload, fmt.Errorf("%w: got %d fields, want 5", ErrInvalidQR, len(fields))
	}

	payload.Ref = fields[0]
	if err := validateRef(payload.Ref); err != nil {
		return QRPayload{}, err
	}
	payload.ClientType = fields[4]
	if err := validateClientType(payload.ClientType); err != nil {
		return QRPayload{}, err
	}

	keys := []struct {
		name  string
		value string
		dst   *[32]byte
	}{
		{"noise key", fields[1], &payload.NoisePublicKey},
		{"identity key", fields[2], &payload.IdentityPublicKey},
		{"adv secret", fields[3], &payload.AdvSecret},
	}
	for _, key := range keys {
		raw, err := base64.StdEncoding.DecodeString(key.value)
		if err != nil {
			return QRPayload{}, fmt.Errorf("%w: %s: %w", ErrInvalidQR, key.name, err)
		}
		if len(raw) != 32 {
			return QRPayload{}, fmt.Errorf("%w: %s is %d bytes, want 32", ErrInvalidQR, key.name, len(raw))
		}
		copy(key.dst[:], raw)
	}
	return payload, nil
}

func validateRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("%w: empty ref", ErrInvalidQR)
	}
	if len(ref) > 64 {
		return fmt.Errorf("%w: ref longer than 64 bytes", ErrInvalidQR)
	}
	if strings.ContainsAny(ref, ",\t\r\n ") {
		return fmt.Errorf("%w: ref contains a separator or whitespace", ErrInvalidQR)
	}
	return nil
}

func validateClientType(clientType string) error {
	if len(clientType) > 32 {
		return fmt.Errorf("%w: client type longer than 32 bytes", ErrInvalidQR)
	}
	if strings.ContainsAny(clientType, ",\t\r\n") {
		return fmt.Errorf("%w: client type contains a separator", ErrInvalidQR)
	}
	return nil
}
