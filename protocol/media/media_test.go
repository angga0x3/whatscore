package media

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// Synthetic vector material, generated once with an independent Python
// implementation (hmac/hashlib for HKDF-SHA256, pycryptodome for AES-CBC)
// from the finding text in docs/protocol/media.md. No real media, keys or
// account data are involved.
const (
	// testMediaKey is bytes 0x00..0x1f.
	testMediaKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	// Image key set (PF-040): expansion of testMediaKey with
	// info="WhatsApp Image Keys".
	imageIVHex     = "aa6a127218397cbd2383e4ccf7176a79"
	imageCipherHex = "008c9aea9b7c5d81eb56b3f530f87d42dcc92d27b11ad6b5bd66f0560d0d8c46"
	imageMACHex    = "91d09ffec108833c1699574c52657923fb6e3e161d9698bc6b3a05fbc508a515"

	// Video key set (PF-041): same media key, info="WhatsApp Video Keys".
	videoIVHex  = "f1dee5782cc4e2e7b07233b1e25de59b"
	videoMACHex = "259ad46118adcf3cd134ae881831c6865db31a8fa0bbce7bc3bcb9fcf369fcda"

	// Full encryption vector (PF-042, PF-043): 36-byte ASCII plaintext,
	// image keys. 36 bytes pad to 48, so the blob is 48+10 bytes.
	testPlaintextHex  = "7768617473636f72652073796e746865746963206d6564696120766563746f7220303031"
	testCiphertextHex = "a8863597c5c33664da1b08e2e41523c75f271a17822dd614d329ee3e05e2da49ba76857bb24583f24eda02a11f2ad4ca"
	testMACHex        = "2a7895b614c8a1290be8"
	testBlobHex       = testCiphertextHex + testMACHex

	// Empty plaintext (PF-042): always padded, so one block plus the MAC.
	emptyCiphertextHex = "d86dbcfed371684274c26215fc53dc72"
	emptyBlobHex       = emptyCiphertextHex + "cb480389e6f95d2b38d9"
)

// mustHex decodes a synthetic vector or fails the test.
func mustHex(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("vector %s: invalid hex: %v", name, err)
	}
	return b
}

// fixedMediaKey returns the synthetic 32-byte media key as an array.
func fixedMediaKey(t *testing.T) [MediaKeySize]byte {
	t.Helper()
	var key [MediaKeySize]byte
	copy(key[:], mustHex(t, "media key", testMediaKeyHex))
	return key
}

// mustDerive derives a key set for mediaType from the fixed media key.
func mustDerive(t *testing.T, mediaType string) Keys {
	t.Helper()
	keys, err := DeriveKeys(fixedMediaKey(t), mediaType, 0)
	if err != nil {
		t.Fatalf("DeriveKeys(%q): %v", mediaType, err)
	}
	return keys
}

// encryptBlock encrypts exactly one manually built block and appends its
// MAC, so tests can craft padding the Encrypt path would never produce.
func encryptBlock(t *testing.T, block []byte, keys Keys) []byte {
	t.Helper()
	if len(block) != aes.BlockSize {
		t.Fatalf("encryptBlock: %d bytes, want %d", len(block), aes.BlockSize)
	}
	blockCipher, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	body := make([]byte, aes.BlockSize)
	cipher.NewCBCEncrypter(blockCipher, keys.IV[:]).CryptBlocks(body, block)
	return append(body, mac(keys, body)...)
}

// TestDeriveKeysVectors pins the HKDF-SHA256 expansion, info strings and
// slice layout against independently generated values (PF-040, PF-041).
func TestDeriveKeysVectors(t *testing.T) {
	tests := []struct {
		name      string
		mediaType string
		wantIV    string
		wantKey   string
		wantMAC   string
	}{
		{
			name:      "image",
			mediaType: TypeImage,
			wantIV:    imageIVHex,
			wantKey:   imageCipherHex,
			wantMAC:   imageMACHex,
		},
		{
			name:      "video",
			mediaType: TypeVideo,
			wantIV:    videoIVHex,
			wantKey:   "8564567ee06fa7006edab56a13c2b0a1431beb8efe698efad0f258e65feb5395",
			wantMAC:   videoMACHex,
		},
		{
			name:      "document",
			mediaType: TypeDocument,
			wantIV:    "25e9d370804de0bb33ea5db79453db66",
			wantKey:   "b75c2bed8e162ad63dd02b6b9fbda46b8ad2692e99ed0f877d0ab48a86fff790",
			wantMAC:   "94a393dafdca1265c99e197425de98f15f7d87d34714ea901f7eefc29c99e5ac",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := mustDerive(t, tc.mediaType)
			if got, want := hex.EncodeToString(keys.IV[:]), tc.wantIV; got != want {
				t.Errorf("IV = %s, want %s", got, want)
			}
			if got, want := hex.EncodeToString(keys.CipherKey[:]), tc.wantKey; got != want {
				t.Errorf("cipher key = %s, want %s", got, want)
			}
			if got, want := hex.EncodeToString(keys.MACKey[:]), tc.wantMAC; got != want {
				t.Errorf("MAC key = %s, want %s", got, want)
			}

			// The first 80 expansion bytes do not depend on the requested
			// length, so 80 and 112 must yield the same key set. Bytes
			// 80..112 are unused (PF-045).
			short, err := DeriveKeys(fixedMediaKey(t), tc.mediaType, IVSize+CipherKeySize+MACKeySize)
			if err != nil {
				t.Fatalf("DeriveKeys(length=80): %v", err)
			}
			if short != keys {
				t.Errorf("length=80 key set differs from length=112")
			}
		})
	}
}

// TestDeriveKeysErrors covers rejected derivation parameters
// (PF-041, PF-045).
func TestDeriveKeysErrors(t *testing.T) {
	tests := []struct {
		name      string
		mediaType string
		length    int
		wantErr   error
	}{
		{"empty media type", "", 0, ErrUnknownMediaType},
		{"missing WhatsApp prefix", "Image Keys", 0, ErrUnknownMediaType},
		{"trailing space", TypeImage + " ", 0, ErrUnknownMediaType},
		{"case mismatch", "whatsapp image keys", 0, ErrUnknownMediaType},
		{"length below key set", TypeImage, IVSize + CipherKeySize + MACKeySize - 1, ErrInvalidKey},
		{"negative length", TypeImage, -1, ErrInvalidKey},
		{"length above hkdf limit", TypeImage, 255*sha256.Size + 1, ErrInvalidKey},
		{"default length", TypeImage, 0, nil},
		{"minimum length", TypeImage, IVSize + CipherKeySize + MACKeySize, nil},
		{"reference length", TypeImage, ExpandedKeySize, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeriveKeys(fixedMediaKey(t), tc.mediaType, tc.length)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DeriveKeys(%q, %d) error = %v, want %v", tc.mediaType, tc.length, err, tc.wantErr)
			}
		})
	}
}

// TestEncryptVectors pins the padding, CBC output and MAC placement against
// independently generated ciphertexts (PF-042, PF-043).
func TestEncryptVectors(t *testing.T) {
	tests := []struct {
		name          string
		plaintextHex  string
		wantBlobHex   string
		wantBodyHex   string
		wantMACHex    string
		wantBlobBytes int
	}{
		{
			name:          "partial final block",
			plaintextHex:  testPlaintextHex,
			wantBlobHex:   testBlobHex,
			wantBodyHex:   testCiphertextHex,
			wantMACHex:    testMACHex,
			wantBlobBytes: 58,
		},
		{
			name:          "empty plaintext",
			plaintextHex:  "",
			wantBlobHex:   emptyBlobHex,
			wantBodyHex:   emptyCiphertextHex,
			wantMACHex:    "cb480389e6f95d2b38d9",
			wantBlobBytes: 26,
		},
	}
	keys := mustDerive(t, TypeImage)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := mustHex(t, "plaintext", tc.plaintextHex)
			unaltered := append([]byte(nil), plaintext...)

			blob, err := Encrypt(plaintext, keys)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if len(blob) != tc.wantBlobBytes {
				t.Fatalf("blob length = %d, want %d", len(blob), tc.wantBlobBytes)
			}
			if got := hex.EncodeToString(blob); got != tc.wantBlobHex {
				t.Fatalf("blob = %s, want %s", got, tc.wantBlobHex)
			}
			body := blob[:len(blob)-MACSize]
			if got := hex.EncodeToString(body); got != tc.wantBodyHex {
				t.Errorf("ciphertext body = %s, want %s", got, tc.wantBodyHex)
			}
			if got := hex.EncodeToString(blob[len(blob)-MACSize:]); got != tc.wantMACHex {
				t.Errorf("MAC = %s, want %s", got, tc.wantMACHex)
			}
			// Encrypt must not touch its input.
			if !bytes.Equal(plaintext, unaltered) {
				t.Errorf("Encrypt modified its plaintext argument")
			}
			// The IV is derived, never prepended.
			if bytes.Equal(blob[:IVSize], keys.IV[:]) {
				t.Errorf("blob starts with the IV; the reference layout does not prefix it")
			}
		})
	}
}

// TestMACLayout recomputes the tag with the stdlib directly to pin the MAC
// input order (iv ‖ ciphertext) and the 10-byte truncation (PF-043).
func TestMACLayout(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	plaintext := bytes.Repeat([]byte{0xa5}, 100)

	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	body := blob[:len(blob)-MACSize]

	blockCipher, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	padded := pad(plaintext)
	wantBody := make([]byte, len(padded))
	cipher.NewCBCEncrypter(blockCipher, keys.IV[:]).CryptBlocks(wantBody, padded)
	if !bytes.Equal(body, wantBody) {
		t.Fatalf("ciphertext mismatch against plain AES-256-CBC")
	}

	h := hmac.New(sha256.New, keys.MACKey[:])
	h.Write(keys.IV[:])
	h.Write(body)
	wantTag := h.Sum(nil)[:MACSize]
	if !bytes.Equal(blob[len(blob)-MACSize:], wantTag) {
		t.Fatalf("MAC = %x, want %x", blob[len(blob)-MACSize:], wantTag)
	}
	// The tag covers the IV and ciphertext only: dropping the IV from the
	// input yields a different tag.
	h = hmac.New(sha256.New, keys.MACKey[:])
	h.Write(body)
	if bytes.Equal(h.Sum(nil)[:MACSize], wantTag) {
		t.Fatal("MAC does not depend on the IV")
	}
}

// TestRoundTrip covers the padding boundaries and verifies Decrypt is the
// inverse of Encrypt (PF-042, PF-044).
func TestRoundTrip(t *testing.T) {
	keys := mustDerive(t, TypeAudio)
	tests := []struct {
		name       string
		size       int
		wantCipher int
	}{
		{"empty", 0, 16},
		{"one byte", 1, 16},
		{"one byte short of block", 15, 16},
		{"full block", 16, 32},
		{"one byte over block", 17, 32},
		{"two blocks minus one", 31, 32},
		{"two blocks", 32, 48},
		{"two blocks plus one", 33, 48},
		{"odd size", 1001, 1008},
		{"large", 100000, 100000 + aes.BlockSize},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := make([]byte, tc.size)
			for i := range plaintext {
				plaintext[i] = byte(i*7 + 3)
			}

			blob, err := Encrypt(plaintext, keys)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if got := len(blob) - MACSize; got != tc.wantCipher {
				t.Fatalf("ciphertext length = %d, want %d", got, tc.wantCipher)
			}

			unaltered := append([]byte(nil), blob...)
			got, err := Decrypt(blob, keys)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
			}
			if !bytes.Equal(blob, unaltered) {
				t.Fatal("Decrypt modified its input")
			}
		})
	}
}

// TestTamperAllPositions flips every bit of every byte of a valid blob and
// requires ErrBadMAC: the tag covers iv ‖ ciphertext and is checked before
// decryption (PF-043, PF-044).
func TestTamperAllPositions(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	plaintext := bytes.Repeat([]byte("tamper"), 4) // 24 bytes -> 32-byte body
	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(blob) != 42 {
		t.Fatalf("expected a 42-byte blob, got %d", len(blob))
	}

	for pos := range blob {
		for bit := 0; bit < 8; bit++ {
			tampered := append([]byte(nil), blob...)
			tampered[pos] ^= 1 << bit
			if _, err := Decrypt(tampered, keys); !errors.Is(err, ErrBadMAC) {
				t.Fatalf("byte %d bit %d: error = %v, want ErrBadMAC", pos, bit, err)
			}
		}
	}
}

// TestWrongKeyAndMediaType shows that a wrong media key or media type
// derives a different key set and fails authentication (PF-040, PF-041).
func TestWrongKeyAndMediaType(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	blob, err := Encrypt([]byte("media payload"), keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	otherMediaKey := fixedMediaKey(t)
	otherMediaKey[0] ^= 0xff
	wrongKey, err := DeriveKeys(otherMediaKey, TypeImage, 0)
	if err != nil {
		t.Fatalf("DeriveKeys(other media key): %v", err)
	}

	wrongType := mustDerive(t, TypeVideo)

	badMACKey := keys
	badMACKey.MACKey[0] ^= 0x01

	badIV := keys
	badIV.IV[0] ^= 0x01

	tests := []struct {
		name string
		keys Keys
	}{
		{"different media key", wrongKey},
		{"different media type", wrongType},
		{"flipped MAC key", badMACKey},
		{"flipped IV", badIV},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decrypt(blob, tc.keys); !errors.Is(err, ErrBadMAC) {
				t.Fatalf("Decrypt error = %v, want ErrBadMAC", err)
			}
		})
	}

	// Control: the same plaintext under the wrong key set does not produce
	// the same blob.
	other, err := Encrypt([]byte("media payload"), wrongType)
	if err != nil {
		t.Fatalf("Encrypt(wrong type): %v", err)
	}
	if bytes.Equal(other, blob) {
		t.Fatal("distinct key sets produced identical ciphertext")
	}
}

// TestPaddingEdges checks the always-pad rule and rejects every non-canonical
// final block, including blobs whose tag is valid (PF-042).
func TestPaddingEdges(t *testing.T) {
	keys := mustDerive(t, TypeDocument)

	t.Run("empty plaintext pads one full block", func(t *testing.T) {
		blob, err := Encrypt(nil, keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if len(blob) != MACSize+aes.BlockSize {
			t.Fatalf("blob length = %d, want %d", len(blob), MACSize+aes.BlockSize)
		}
		body := blob[:len(blob)-MACSize]
		blockCipher, err := aes.NewCipher(keys.CipherKey[:])
		if err != nil {
			t.Fatalf("aes.NewCipher: %v", err)
		}
		block := make([]byte, aes.BlockSize)
		cipher.NewCBCDecrypter(blockCipher, keys.IV[:]).CryptBlocks(block, body)
		if !bytes.Equal(block, bytes.Repeat([]byte{aes.BlockSize}, aes.BlockSize)) {
			t.Fatalf("padding block = %x, want sixteen 0x10 bytes", block)
		}
	})

	t.Run("full block gets a whole padding block", func(t *testing.T) {
		blob, err := Encrypt(make([]byte, aes.BlockSize), keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if got := len(blob) - MACSize; got != 2*aes.BlockSize {
			t.Fatalf("ciphertext length = %d, want %d", got, 2*aes.BlockSize)
		}
	})

	tests := []struct {
		name      string
		block     []byte
		wantPlain int
		wantErr   error
	}{
		{
			name:    "zero padding length",
			block:   bytes.Repeat([]byte{0}, aes.BlockSize),
			wantErr: ErrInvalidCiphertext,
		},
		{
			name:    "padding length 17",
			block:   append(bytes.Repeat([]byte{0}, aes.BlockSize-1), 17),
			wantErr: ErrInvalidCiphertext,
		},
		{
			name:    "padding length 0xff",
			block:   append(bytes.Repeat([]byte{0}, aes.BlockSize-1), 0xff),
			wantErr: ErrInvalidCiphertext,
		},
		{
			name:    "inconsistent padding bytes",
			block:   append(bytes.Repeat([]byte{0}, aes.BlockSize-2), 0x03, 0x02),
			wantErr: ErrInvalidCiphertext,
		},
		{
			// Canonical PKCS#7 for 15 data bytes: a single 0x01.
			name:      "minimal one byte padding",
			block:     append(bytes.Repeat([]byte{0x5a}, aes.BlockSize-1), 0x01),
			wantPlain: aes.BlockSize - 1,
		},
		{
			name:      "full block padding",
			block:     bytes.Repeat([]byte{aes.BlockSize}, aes.BlockSize),
			wantPlain: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blob := encryptBlock(t, tc.block, keys)
			got, err := Decrypt(blob, keys)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Decrypt error = %v, want %v", err, tc.wantErr)
			}
			if err == nil && len(got) != tc.wantPlain {
				t.Fatalf("plaintext length = %d, want %d", len(got), tc.wantPlain)
			}
		})
	}
}

// TestSizeMismatches rejects structurally impossible blobs
// (PF-043, PF-044).
func TestSizeMismatches(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	valid, err := Encrypt([]byte("1234567890123456"), keys) // 32-byte body
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		name    string
		blob    []byte
		wantErr error
	}{
		{"nil", nil, ErrInvalidCiphertext},
		{"empty", []byte{}, ErrInvalidCiphertext},
		{"MAC only", make([]byte, MACSize), ErrInvalidCiphertext},
		{"one byte short of minimum", make([]byte, MACSize+aes.BlockSize-1), ErrInvalidCiphertext},
		{"minimum length, zero tag", make([]byte, MACSize+aes.BlockSize), ErrBadMAC},
		{"ciphertext without MAC", valid[:len(valid)-MACSize], ErrInvalidCiphertext},
		{"truncated by one byte", valid[:len(valid)-1], ErrInvalidCiphertext},
		{"one byte appended", append(append([]byte(nil), valid...), 0x00), ErrInvalidCiphertext},
		{"zeroed MAC", append(append([]byte(nil), valid[:len(valid)-MACSize]...), make([]byte, MACSize)...), ErrBadMAC},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decrypt(tc.blob, keys); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Decrypt error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestKeySetsDiffer ensures no two media types share key material
// (PF-041), the same domain-separation invariant the spec requires of the
// Noise and Signal layers.
func TestKeySetsDiffer(t *testing.T) {
	types := []string{
		TypeImage, TypeVideo, TypeAudio, TypeDocument, TypeHistory, TypeAppState,
		TypeStickerPack, TypeLinkThumbnail, TypeImageThumbnail,
		TypeVideoThumbnail, TypeDocumentThumbnail, TypePaymentBackground,
	}
	seen := make(map[Keys]string, len(types))
	for _, mediaType := range types {
		keys := mustDerive(t, mediaType)
		if prev, ok := seen[keys]; ok {
			t.Fatalf("media types %q and %q derive identical key sets", prev, mediaType)
		}
		seen[keys] = mediaType
	}
}

// FuzzDecrypt asserts Decrypt never panics on hostile input and that a
// successfully authenticated blob re-encrypts byte-identically (the padding
// was canonical, so Encrypt reproduces it).
func FuzzDecrypt(f *testing.F) {
	keys := Keys{}
	for i := range keys.IV {
		keys.IV[i] = byte(i)
	}
	for i := range keys.CipherKey {
		keys.CipherKey[i] = byte(i + 1)
	}
	for i := range keys.MACKey {
		keys.MACKey[i] = byte(i + 2)
	}
	seeds := [][]byte{
		nil,
		make([]byte, MACSize+aes.BlockSize),
		bytes.Repeat([]byte{0xff}, 58),
	}
	valid, err := Encrypt([]byte("fuzz seed"), keys)
	if err != nil {
		f.Fatalf("Encrypt seed: %v", err)
	}
	seeds = append(seeds, valid)
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, blob []byte) {
		plaintext, err := Decrypt(blob, keys)
		if err != nil {
			return
		}
		body := len(blob) - MACSize
		if len(plaintext) < body-aes.BlockSize || len(plaintext) > body-1 {
			t.Fatalf("authenticated plaintext length %d outside [%d, %d]", len(plaintext), body-aes.BlockSize, body-1)
		}
		again, err := Encrypt(plaintext, keys)
		if err != nil {
			t.Fatalf("Encrypt(authenticated plaintext): %v", err)
		}
		if !bytes.Equal(again, blob) {
			t.Fatalf("re-encryption differs from the authenticated blob")
		}
	})
}
