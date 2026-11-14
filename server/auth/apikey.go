// Package auth implements API key handling per the security specification:
// keys look like wc_live_<secret>, are generated with a CSPRNG, and are only
// ever persisted as SHA-256 hashes.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// KeyPrefix is the fixed prefix of every WhatsCore API key.
const KeyPrefix = "wc_live_"

// secretBytes is the entropy of the random secret: 32 bytes -> 43 base64url
// characters before the prefix is added.
const secretBytes = 32

// GenerateKey returns a fresh API key. The plaintext value is shown exactly
// once, at creation time; callers must persist only HashKey(plaintext).
func GenerateKey() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	return KeyPrefix + secret, nil
}

// HashKey returns the SHA-256 hash that is stored in api_keys.key_hash.
func HashKey(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

// VerifyKey compares a presented key against a stored hash in constant time.
func VerifyKey(plaintext string, storedHash []byte) bool {
	presented := HashKey(plaintext)
	return subtle.ConstantTimeCompare(presented, storedHash) == 1
}

// SplitKey validates the key shape and returns the prefix stored in
// api_keys.key_prefix (used for cheap lookups before full verification).
func SplitKey(plaintext string) (prefix string, ok bool) {
	if len(plaintext) <= len(KeyPrefix) {
		return "", false
	}
	return plaintext[:len(KeyPrefix)], true
}
