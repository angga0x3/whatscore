package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// newSessionID returns a random RFC 4122 version 4 UUID.
func newSessionID() (string, error) { return newUUID() }

// newUUID returns a random RFC 4122 version 4 UUID. Session and webhook ids
// share the format so one column type serves both.
func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("api: random id: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], raw[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], raw[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], raw[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], raw[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], raw[10:16])
	return string(buf), nil
}
