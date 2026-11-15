package media

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	protocolmedia "github.com/angga0x3/whatscore/protocol/media"
)

// syntheticPayload returns deterministic filler bytes, so a failure is
// reproducible without fixtures. No real media is used anywhere in this file.
func syntheticPayload(size int, seed byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i*31) ^ seed
	}
	return out
}

// mustEncrypt encrypts a synthetic payload and fails the test on error.
func mustEncrypt(t *testing.T, size int, mediaType string) ([]byte, *Descriptor, []byte) {
	t.Helper()
	plaintext := syntheticPayload(size, 0x5a)
	d, encrypted, err := Encrypt(plaintext, mediaType, "synthetic.bin")
	if err != nil {
		t.Fatalf("Encrypt(%d, %q): %v", size, mediaType, err)
	}
	return plaintext, d, encrypted
}

// TestEncryptDescriptor checks the fields Encrypt owns and leaves the
// transport-owned fields untouched (PF-045).
func TestEncryptDescriptor(t *testing.T) {
	plaintext := syntheticPayload(100, 0x11)
	d, encrypted, err := Encrypt(plaintext, protocolmedia.TypeImage, "photo.jpg")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if d == nil {
		t.Fatal("Encrypt returned a nil descriptor")
	}
	if d.MediaType != protocolmedia.TypeImage {
		t.Errorf("MediaType = %q, want %q", d.MediaType, protocolmedia.TypeImage)
	}
	if d.FileName != "photo.jpg" {
		t.Errorf("FileName = %q, want photo.jpg", d.FileName)
	}
	if d.Size != len(plaintext) {
		t.Errorf("Size = %d, want %d", d.Size, len(plaintext))
	}
	if got, want := d.SHA256, sha256.Sum256(plaintext); got != want {
		t.Errorf("SHA256 = %x, want %x", got, want)
	}
	if got, want := d.EncSHA256, sha256.Sum256(encrypted); got != want {
		t.Errorf("EncSHA256 = %x, want %x", got, want)
	}
	// PKCS#7 always pads, so a partial final block grows to the next
	// 16-byte boundary and a full block gains a whole block (PF-042).
	wantLen := (len(plaintext)/16+1)*16 + protocolmedia.MACSize
	if len(encrypted) != wantLen {
		t.Errorf("encrypted length = %d, want %d", len(encrypted), wantLen)
	}
	if d.MimeType != "" || d.Width != 0 || d.Height != 0 || d.Seconds != 0 || d.DirectPath != "" || d.URL != "" {
		t.Errorf("Encrypt filled transport-owned fields: %#v", d)
	}
	if d.MediaKey == ([32]byte{}) {
		t.Error("MediaKey is all zeroes")
	}
}

// TestEncryptRandomness ensures each call picks a fresh media key, so equal
// plaintext never repeats a blob (PF-041, PF-045).
func TestEncryptRandomness(t *testing.T) {
	plaintext := []byte("same plaintext, different keys")
	first, firstBlob, err := Encrypt(plaintext, protocolmedia.TypeDocument, "a.pdf")
	if err != nil {
		t.Fatalf("Encrypt first: %v", err)
	}
	second, secondBlob, err := Encrypt(plaintext, protocolmedia.TypeDocument, "a.pdf")
	if err != nil {
		t.Fatalf("Encrypt second: %v", err)
	}
	if first.MediaKey == second.MediaKey {
		t.Fatal("two Encrypt calls reused the media key")
	}
	if bytes.Equal(firstBlob, secondBlob) {
		t.Fatal("two Encrypt calls produced identical ciphertext")
	}
	if first.EncSHA256 == second.EncSHA256 {
		t.Fatal("two Encrypt calls produced identical EncSHA256")
	}
	if first.SHA256 != second.SHA256 {
		t.Fatal("equal plaintext produced different SHA256")
	}
}

// TestRoundTrip covers the padding boundaries, a 1 MiB payload and every
// media class that carries ordinary file bytes (PF-042, PF-044).
func TestRoundTrip(t *testing.T) {
	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one byte", 1},
		{"one byte short of block", 15},
		{"full block", 16},
		{"one byte over block", 17},
		{"one MiB", 1 << 20},
	}
	types := []struct {
		name      string
		mediaType string
	}{
		{"image", protocolmedia.TypeImage},
		{"video", protocolmedia.TypeVideo},
		{"audio", protocolmedia.TypeAudio},
		{"document", protocolmedia.TypeDocument},
		{"history", protocolmedia.TypeHistory},
		{"app state", protocolmedia.TypeAppState},
	}

	for _, mt := range types {
		for _, sz := range sizes {
			t.Run(mt.name+"/"+sz.name, func(t *testing.T) {
				plaintext := syntheticPayload(sz.size, 0x33)
				unaltered := append([]byte(nil), plaintext...)

				d, encrypted, err := Encrypt(plaintext, mt.mediaType, "file.bin")
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				if !bytes.Equal(plaintext, unaltered) {
					t.Fatal("Encrypt modified its plaintext argument")
				}

				blobCopy := append([]byte(nil), encrypted...)
				got, err := Decrypt(encrypted, d)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
				}
				if !bytes.Equal(encrypted, blobCopy) {
					t.Fatal("Decrypt modified its encrypted argument")
				}
			})
		}
	}
}

// TestDecryptTamper proves each tamper class fails closed: a changed blob, a
// changed MAC, a changed sidecar hash, a changed media key or a changed media
// type (PF-043, PF-044).
func TestDecryptTamper(t *testing.T) {
	plaintext, d, encrypted := mustEncrypt(t, 64, protocolmedia.TypeImage)

	// clone returns a descriptor copy so mutations never leak between cases.
	clone := func() *Descriptor {
		copied := *d
		return &copied
	}
	// withEncHash recomputes the sidecar ciphertext hash so the MAC, not the
	// sidecar check, decides the outcome.
	withEncHash := func(blob []byte) *Descriptor {
		copied := *d
		copied.EncSHA256 = sha256.Sum256(blob)
		return &copied
	}

	cipherFlip := append([]byte(nil), encrypted...)
	cipherFlip[0] ^= 0x01
	macFlip := append([]byte(nil), encrypted...)
	macFlip[len(macFlip)-1] ^= 0x80

	dHash := clone()
	dHash.SHA256[0] ^= 0x01
	dEncHash := clone()
	dEncHash.EncSHA256[0] ^= 0x01
	dKey := clone()
	dKey.MediaKey[0] ^= 0x01
	dType := clone()
	dType.MediaType = protocolmedia.TypeVideo
	dUnknownType := clone()
	dUnknownType.MediaType = "WhatsApp Synthetic Keys"

	tests := []struct {
		name string
		blob []byte
		d    *Descriptor
		want error
	}{
		// The sidecar hash catches a mangled blob before any crypto runs.
		{"ciphertext byte with stale EncSHA256", cipherFlip, d, ErrHashMismatch},
		{"MAC byte with stale EncSHA256", macFlip, d, ErrHashMismatch},
		// With a consistent sidecar hash only the envelope MAC can object.
		{"ciphertext byte with fresh EncSHA256", cipherFlip, withEncHash(cipherFlip), ErrHashMismatch},
		{"MAC byte with fresh EncSHA256", macFlip, withEncHash(macFlip), ErrHashMismatch},
		// Descriptor-side tampering.
		{"descriptor SHA256", encrypted, dHash, ErrHashMismatch},
		{"descriptor EncSHA256", encrypted, dEncHash, ErrHashMismatch},
		{"media key", encrypted, dKey, ErrHashMismatch},
		{"media type", encrypted, dType, ErrHashMismatch},
		{"unknown media type", encrypted, dUnknownType, ErrInvalidDescriptor},
		// Control: the untouched pair still decrypts.
		{"unmodified", encrypted, d, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decrypt(tc.blob, tc.d)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Decrypt error = %v, want %v", err, tc.want)
			}
			if tc.want == nil {
				if !bytes.Equal(got, plaintext) {
					t.Fatal("control case did not round-trip")
				}
				return
			}
			if got != nil {
				t.Fatal("failed Decrypt returned plaintext")
			}
		})
	}
}

// TestDecryptStructuralRejects covers blobs that are self-consistent with the
// descriptor hashes but structurally unusable, plus descriptor size
// disagreements (PF-044).
func TestDecryptStructuralRejects(t *testing.T) {
	plaintext, d, encrypted := mustEncrypt(t, 32, protocolmedia.TypeAudio)

	// descriptorWith returns a copy whose hashes describe blob and whose
	// plaintext size matches wantSize.
	descriptorWith := func(blob []byte, wantSize int) *Descriptor {
		copied := *d
		copied.EncSHA256 = sha256.Sum256(blob)
		copied.SHA256 = sha256.Sum256(plaintext)
		copied.Size = wantSize
		return &copied
	}

	empty := []byte{}
	tooShort := encrypted[:protocolmedia.MACSize+15] // 25 bytes: below 26
	unaligned := encrypted[:len(encrypted)-protocolmedia.MACSize-1]

	tests := []struct {
		name string
		blob []byte
		d    *Descriptor
		want error
	}{
		{"empty blob", empty, descriptorWith(empty, 0), protocolmedia.ErrInvalidCiphertext},
		{"below minimum length", tooShort, descriptorWith(tooShort, 0), protocolmedia.ErrInvalidCiphertext},
		{"body not block aligned", unaligned, descriptorWith(unaligned, 0), protocolmedia.ErrInvalidCiphertext},
		{"descriptor size too small", encrypted, descriptorWith(encrypted, len(plaintext)-1), ErrInvalidDescriptor},
		{"descriptor size too large", encrypted, descriptorWith(encrypted, len(plaintext)+16), ErrInvalidDescriptor},
		{"control", encrypted, descriptorWith(encrypted, len(plaintext)), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decrypt(tc.blob, tc.d)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Decrypt error = %v, want %v", err, tc.want)
			}
			if tc.want == nil && !bytes.Equal(got, plaintext) {
				t.Fatal("control case did not round-trip")
			}
		})
	}
}

// TestDecryptMalformedDescriptor covers unusable descriptors, all rejected
// before any crypto work.
func TestDecryptMalformedDescriptor(t *testing.T) {
	_, d, encrypted := mustEncrypt(t, 32, protocolmedia.TypeDocument)
	clone := func() *Descriptor {
		copied := *d
		return &copied
	}

	negative := clone()
	negative.Size = -1
	oversize := clone()
	oversize.Size = MaxMediaSize + 1
	emptyType := clone()
	emptyType.MediaType = ""

	tests := []struct {
		name string
		d    *Descriptor
		want error
	}{
		{"nil descriptor", nil, ErrInvalidDescriptor},
		{"negative size", negative, ErrInvalidDescriptor},
		{"size above cap", oversize, ErrPayloadTooLarge},
		{"empty media type", emptyType, ErrInvalidDescriptor},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decrypt(encrypted, tc.d); !errors.Is(err, tc.want) {
				t.Fatalf("Decrypt error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestSizeCap checks the 64 MiB ceiling on both directions, including the
// envelope's padding and MAC overhead.
func TestSizeCap(t *testing.T) {
	// One allocation at the cap: the boundary payload must still work.
	atCap := syntheticPayload(MaxMediaSize, 0x01)
	d, encrypted, err := Encrypt(atCap, protocolmedia.TypeDocument, "cap.bin")
	if err != nil {
		t.Fatalf("Encrypt(at cap): %v", err)
	}
	if len(encrypted) != MaxMediaSize+16+protocolmedia.MACSize {
		t.Fatalf("encrypted length = %d at the cap", len(encrypted))
	}
	got, err := Decrypt(encrypted, d)
	if err != nil {
		t.Fatalf("Decrypt(at cap): %v", err)
	}
	if !bytes.Equal(got, atCap) {
		t.Fatal("payload at the cap did not round-trip")
	}

	t.Run("plaintext one byte over cap", func(t *testing.T) {
		plaintext := make([]byte, MaxMediaSize+1)
		if _, _, err := Encrypt(plaintext, protocolmedia.TypeDocument, "over.bin"); !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("Encrypt error = %v, want ErrPayloadTooLarge", err)
		}
	})

	t.Run("blob above envelope ceiling", func(t *testing.T) {
		blob := make([]byte, MaxMediaSize+maxEnvelopeOverhead+1)
		if _, err := Decrypt(blob, d); !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("Decrypt error = %v, want ErrPayloadTooLarge", err)
		}
	})
}

// TestEncryptRejectsUnknownMediaType shows Encrypt fails closed on a type
// outside the PF-041 table and leaks no key material on the error path.
func TestEncryptRejectsUnknownMediaType(t *testing.T) {
	tests := []struct {
		name      string
		mediaType string
	}{
		{"empty", ""},
		{"missing prefix", "Image Keys"},
		{"case mismatch", "whatsapp image keys"},
		{"trailing space", protocolmedia.TypeImage + " "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, blob, err := Encrypt([]byte("payload"), tc.mediaType, "x.bin")
			if !errors.Is(err, protocolmedia.ErrUnknownMediaType) {
				t.Fatalf("Encrypt error = %v, want ErrUnknownMediaType", err)
			}
			if d != nil || blob != nil {
				t.Fatal("failed Encrypt returned a descriptor or blob")
			}
		})
	}
}
