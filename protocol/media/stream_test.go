package media

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/angga0x3/whatscore/internal/cbc"
)

// initialMaxStreamBytes records the package default before any test mutates
// MaxStreamBytes, so the default can be pinned regardless of test order.
var initialMaxStreamBytes = MaxStreamBytes

// plaintextPattern returns size deterministic bytes. It is the same generator
// the sidecar vectors below were computed from with python3 hashlib.
func plaintextPattern(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i*31 + 7)
	}
	return out
}

// countWriter records how many bytes reached it, keeps a copy, and optionally
// snapshots the source offset at the first write, so a test can assert both
// that a rejected blob wrote nothing and that output started early.
type countWriter struct {
	n      int64
	buf    bytes.Buffer
	offset *int
	first  int
	writes int
	max    int
}

func (w *countWriter) Write(p []byte) (int, error) {
	if w.writes == 0 && w.offset != nil {
		w.first = *w.offset
	}
	w.writes++
	if len(p) > w.max {
		w.max = len(p)
	}
	w.n += int64(len(p))
	return w.buf.Write(p)
}

// chunkedReaderAt serves data in at most max bytes per call and always
// returns a nil error, including on a short read. That violates the
// io.ReaderAt contract, which readAtFull must survive rather than trust.
type chunkedReaderAt struct {
	data []byte
	max  int
}

func (r *chunkedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.max {
		n = r.max
	}
	if rem := len(r.data) - int(off); n > rem {
		n = rem
	}
	copy(p, r.data[off:off+int64(n)])
	return n, nil
}

// tinyWriter accepts at most max bytes per call and reports no error, forcing
// writeFull to loop.
type tinyWriter struct {
	dst bytes.Buffer
	max int
}

func (w *tinyWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.dst.Write(p)
}

// stalledWriter reports progress-free success, which writeFull must turn into
// io.ErrShortWrite instead of spinning.
type stalledWriter struct{}

func (stalledWriter) Write([]byte) (int, error) { return 0, nil }

// stalledReaderAt reports progress-free success, which readAtFull must turn
// into io.ErrUnexpectedEOF instead of spinning.
type stalledReaderAt struct{}

func (stalledReaderAt) ReadAt([]byte, int64) (int, error) { return 0, nil }

// stalledReader reports progress-free success, which EncryptStream must turn
// into io.ErrNoProgress instead of spinning.
type stalledReader struct{ calls int }

func (r *stalledReader) Read([]byte) (int, error) {
	r.calls++
	if r.calls > maxEmptyReads+10 {
		panic("EncryptStream did not stop on a stalled reader")
	}
	return 0, nil
}

// eofReaderAt always reports io.EOF alongside the requested bytes, which
// readAtFull must accept when p is satisfied.
type eofReaderAt struct{ data []byte }

func (r eofReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	return n, io.EOF
}

// failAfterReaderAt serves data normally, then fails on the call numbered
// skip (zero-based), so a test can aim a failure at one specific pass.
type failAfterReaderAt struct {
	data  []byte
	skip  int
	calls int
	err   error
}

func (r *failAfterReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if r.calls == r.skip {
		r.calls++
		return 0, r.err
	}
	r.calls++
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// errWriter fails once limit bytes have been accepted, truncating the write
// that crosses the limit.
type errWriter struct {
	limit int
	n     int
	err   error
}

func (w *errWriter) Write(p []byte) (int, error) {
	if w.n >= w.limit {
		return 0, w.err
	}
	truncated := false
	if w.n+len(p) > w.limit {
		p = p[:w.limit-w.n]
		truncated = true
	}
	w.n += len(p)
	if truncated {
		return len(p), w.err
	}
	return len(p), nil
}

// errReader yields data, then fails with err.
type errReader struct {
	data []byte
	off  int
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// failingReaderAt serves data up to limit, then fails with err.
type failingReaderAt struct {
	data  []byte
	limit int64
	err   error
}

func (r *failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.limit {
		return 0, r.err
	}
	if rem := r.limit - off; int64(len(p)) > rem {
		p = p[:rem]
	}
	if rem := int64(len(r.data)) - off; int64(len(p)) > rem {
		p = p[:rem]
	}
	n := copy(p, r.data[off:])
	return n, nil
}

// counterReader counts bytes handed to the consumer.
type counterReader struct {
	data []byte
	off  int
}

func (r *counterReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// TestMaxStreamBytesDefault pins the documented default cap.
func TestMaxStreamBytesDefault(t *testing.T) {
	if initialMaxStreamBytes != 512<<20 {
		t.Fatalf("default MaxStreamBytes = %d, want %d", initialMaxStreamBytes, int64(512<<20))
	}
}

// encodeBlocks CBC-encrypts whole blocks in order and appends their MAC, so
// tests can craft multi-block blobs with padding Encrypt would never produce.
func encodeBlocks(t *testing.T, blocks [][]byte, keys Keys) []byte {
	t.Helper()
	var plain []byte
	for i, b := range blocks {
		if len(b) != aes.BlockSize {
			t.Fatalf("encodeBlocks block %d: %d bytes, want %d", i, len(b), aes.BlockSize)
		}
		plain = append(plain, b...)
	}
	blockCipher, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	body := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blockCipher, keys.IV[:]).CryptBlocks(body, plain)
	return append(body, mac(keys, body)...)
}

// TestStreamRoundTrip encrypts and decrypts a stream across the padding
// boundaries and requires the streamed blob to be byte-identical to Encrypt,
// so the streaming path cannot drift from the buffered envelope (PF-046).
func TestStreamRoundTrip(t *testing.T) {
	keys := mustDerive(t, TypeVideo)
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one byte", 1},
		{"full block", 16},
		{"one byte over block", 17},
		{"one MiB", 1 << 20},
		{"eight MiB", 8 << 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := plaintextPattern(tc.size)

			want, err := Encrypt(plaintext, keys)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			var streamed bytes.Buffer
			n, err := EncryptStream(&streamed, bytes.NewReader(plaintext), keys)
			if err != nil {
				t.Fatalf("EncryptStream: %v", err)
			}
			if n != int64(len(want)) {
				t.Fatalf("ciphertextLen = %d, want %d", n, len(want))
			}
			if !bytes.Equal(streamed.Bytes(), want) {
				t.Fatalf("streamed blob differs from Encrypt for a %d-byte payload", tc.size)
			}

			var decrypted bytes.Buffer
			if err := DecryptStream(&decrypted, bytes.NewReader(streamed.Bytes()), int64(streamed.Len()), keys); err != nil {
				t.Fatalf("DecryptStream: %v", err)
			}
			if !bytes.Equal(decrypted.Bytes(), plaintext) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", decrypted.Len(), len(plaintext))
			}

			// Interop in both directions: the buffered decoder accepts the
			// streamed blob and the streaming decoder accepts Encrypt's blob.
			if got, err := Decrypt(streamed.Bytes(), keys); err != nil {
				t.Fatalf("Decrypt(streamed blob): %v", err)
			} else if !bytes.Equal(got, plaintext) {
				t.Fatalf("Decrypt(streamed blob) mismatch")
			}
			decrypted.Reset()
			if err := DecryptStream(&decrypted, bytes.NewReader(want), int64(len(want)), keys); err != nil {
				t.Fatalf("DecryptStream(Encrypt blob): %v", err)
			}
			if !bytes.Equal(decrypted.Bytes(), plaintext) {
				t.Fatalf("DecryptStream(Encrypt blob) mismatch")
			}
		})
	}
}

// TestEncryptStreamIsIncremental proves the payload is never buffered whole:
// output starts before the source is exhausted and no single write exceeds a
// chunk plus one block (PF-046).
func TestEncryptStreamIsIncremental(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	const size = 1 << 20
	src := &counterReader{data: plaintextPattern(size)}
	dst := &countWriter{offset: &src.off}

	n, err := EncryptStream(dst, src, keys)
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	if n != dst.n {
		t.Fatalf("ciphertextLen = %d, reported bytes written = %d", n, dst.n)
	}
	if dst.first == 0 || dst.first >= size {
		t.Fatalf("first write happened after %d of %d source bytes; the stream was buffered", dst.first, size)
	}
	if maxWrite := streamChunkSize + cbc.BlockSize; dst.max > maxWrite {
		t.Fatalf("largest write = %d bytes, above the %d-byte chunk bound", dst.max, maxWrite)
	}
}

// TestStreamTamperFailsBeforeWrite flips bytes at the start, middle and MAC of
// a valid blob, plus authentic-but-malformed padding, and requires the failure
// before a single plaintext byte reaches dst (PF-044, PF-046).
func TestStreamTamperFailsBeforeWrite(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	plaintext := plaintextPattern(64)
	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wrongKey := keys
	wrongKey.MACKey[0] ^= 0x01

	tests := []struct {
		name    string
		blob    []byte
		keys    Keys
		wantErr error
	}{
		{
			name:    "first byte",
			blob:    flip(blob, 0),
			keys:    keys,
			wantErr: ErrBadMAC,
		},
		{
			name:    "middle byte",
			blob:    flip(blob, len(blob)/2),
			keys:    keys,
			wantErr: ErrBadMAC,
		},
		{
			name:    "last ciphertext byte",
			blob:    flip(blob, len(blob)-MACSize-1),
			keys:    keys,
			wantErr: ErrBadMAC,
		},
		{
			name:    "MAC byte",
			blob:    flip(blob, len(blob)-1),
			keys:    keys,
			wantErr: ErrBadMAC,
		},
		{
			name:    "zeroed MAC",
			blob:    append(append([]byte(nil), blob[:len(blob)-MACSize]...), make([]byte, MACSize)...),
			keys:    keys,
			wantErr: ErrBadMAC,
		},
		{
			name:    "wrong MAC key",
			blob:    blob,
			keys:    wrongKey,
			wantErr: ErrBadMAC,
		},
		{
			// Authentic tag over a block whose PKCS#7 padding is invalid:
			// the MAC passes and only the padding check can reject it, so
			// this row proves dst stays untouched on that path too.
			name:    "authentic bad padding",
			blob:    encryptBlock(t, bytes.Repeat([]byte{0}, 16), keys),
			keys:    keys,
			wantErr: ErrInvalidCiphertext,
		},
		{
			// Authentic block whose padding length byte is 0xff.
			name:    "authentic padding length 0xff",
			blob:    encryptBlock(t, append(bytes.Repeat([]byte{0}, 15), 0xff), keys),
			keys:    keys,
			wantErr: ErrInvalidCiphertext,
		},
		{
			// Two authentic blocks whose final block claims padding length
			// 3 without three 0x03 bytes: the MAC passes, so only the strict
			// per-byte padding check can reject it.
			name:    "authentic inconsistent padding",
			blob:    encodeBlocks(t, [][]byte{bytes.Repeat([]byte{0x11}, 16), append(bytes.Repeat([]byte{0x22}, 13), 0x02, 0x02, 0x03)}, keys),
			keys:    keys,
			wantErr: ErrInvalidCiphertext,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := &countWriter{}
			err := DecryptStream(dst, bytes.NewReader(tc.blob), int64(len(tc.blob)), tc.keys)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecryptStream error = %v, want %v", err, tc.wantErr)
			}
			if dst.n != 0 {
				t.Fatalf("%d plaintext bytes reached dst before verification", dst.n)
			}
			if dst.writes != 0 {
				t.Fatalf("%d writes reached dst before verification", dst.writes)
			}
		})
	}
}

// TestStreamTamperLargeBlob repeats the middle-byte check on a 1 MiB blob so
// the guarantee covers the multi-chunk path, not just a single-block one.
func TestStreamTamperLargeBlob(t *testing.T) {
	keys := mustDerive(t, TypeAudio)
	blob, err := Encrypt(plaintextPattern(1<<20), keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := flip(blob, len(blob)/2)
	dst := &countWriter{}
	if err := DecryptStream(dst, bytes.NewReader(tampered), int64(len(tampered)), keys); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("DecryptStream error = %v, want ErrBadMAC", err)
	}
	if dst.n != 0 {
		t.Fatalf("%d plaintext bytes reached dst before verification", dst.n)
	}
}

// TestStreamTruncation covers structures that cannot be a valid envelope and
// a short source, each of which must fail without writing (PF-044).
func TestStreamTruncation(t *testing.T) {
	keys := mustDerive(t, TypeDocument)
	blob, err := Encrypt(plaintextPattern(32), keys) // 48-byte body + 10
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		name    string
		blob    []byte
		size    int64
		wantErr error
	}{
		{
			name:    "drop one byte",
			blob:    blob[:len(blob)-1],
			size:    int64(len(blob) - 1),
			wantErr: ErrInvalidCiphertext,
		},
		{
			name:    "drop ten bytes",
			blob:    blob[:len(blob)-10],
			size:    int64(len(blob) - 10),
			wantErr: ErrInvalidCiphertext,
		},
		{
			name:    "drop a whole ciphertext block",
			blob:    blob[:len(blob)-cbc.BlockSize],
			size:    int64(len(blob) - cbc.BlockSize),
			wantErr: ErrBadMAC,
		},
		{
			name:    "MAC only",
			blob:    blob[len(blob)-MACSize:],
			size:    MACSize,
			wantErr: ErrInvalidCiphertext,
		},
		{
			name:    "ciphertext only",
			blob:    blob[:len(blob)-MACSize],
			size:    int64(len(blob) - MACSize),
			wantErr: ErrInvalidCiphertext,
		},
		{
			name:    "one byte appended",
			blob:    append(append([]byte(nil), blob...), 0x00),
			size:    int64(len(blob) + 1),
			wantErr: ErrInvalidCiphertext,
		},
		{
			name:    "buffer shorter than size",
			blob:    blob[:len(blob)-20],
			size:    int64(len(blob)),
			wantErr: io.ErrUnexpectedEOF,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := &countWriter{}
			err := DecryptStream(dst, bytes.NewReader(tc.blob), tc.size, keys)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecryptStream error = %v, want %v", err, tc.wantErr)
			}
			if dst.n != 0 {
				t.Fatalf("%d plaintext bytes reached dst", dst.n)
			}
		})
	}
}

// TestStreamLimits checks the MaxStreamBytes policy on both directions,
// including the exact boundary and the typed error fields.
func TestStreamLimits(t *testing.T) {
	keys := mustDerive(t, TypeDocument)
	const limit = 4096
	defer func(old int64) { MaxStreamBytes = old }(MaxStreamBytes)
	MaxStreamBytes = limit

	t.Run("encrypt oversized", func(t *testing.T) {
		dst := &countWriter{}
		n, err := EncryptStream(dst, bytes.NewReader(plaintextPattern(limit+1)), keys)
		if !errors.Is(err, ErrStreamLimit) {
			t.Fatalf("EncryptStream error = %v, want ErrStreamLimit", err)
		}
		var limitErr *StreamLimitError
		if !errors.As(err, &limitErr) {
			t.Fatalf("error %v does not unwrap to *StreamLimitError", err)
		}
		if limitErr.Limit != limit || limitErr.Observed != limit+1 {
			t.Fatalf("StreamLimitError = {Limit:%d Observed:%d}, want {%d %d}",
				limitErr.Limit, limitErr.Observed, limit, limit+1)
		}
		if n != dst.n {
			t.Fatalf("ciphertextLen = %d, bytes written = %d", n, dst.n)
		}
		if dst.n != 0 {
			t.Fatalf("%d bytes written before the limit was detected", dst.n)
		}
	})

	t.Run("encrypt at limit", func(t *testing.T) {
		plaintext := plaintextPattern(limit)
		var dst bytes.Buffer
		if _, err := EncryptStream(&dst, bytes.NewReader(plaintext), keys); err != nil {
			t.Fatalf("EncryptStream: %v", err)
		}
		if got := dst.Len(); got != limit+cbc.BlockSize+MACSize {
			t.Fatalf("blob length = %d, want %d", got, limit+cbc.BlockSize+MACSize)
		}
	})

	t.Run("decrypt oversized", func(t *testing.T) {
		blob, err := Encrypt(plaintextPattern(limit), keys) // body = limit+16
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		smaller := int64(limit / 2)
		MaxStreamBytes = smaller
		defer func() { MaxStreamBytes = limit }()

		dst := &countWriter{}
		err = DecryptStream(dst, bytes.NewReader(blob), int64(len(blob)), keys)
		if !errors.Is(err, ErrStreamLimit) {
			t.Fatalf("DecryptStream error = %v, want ErrStreamLimit", err)
		}
		var limitErr *StreamLimitError
		if !errors.As(err, &limitErr) {
			t.Fatalf("error %v does not unwrap to *StreamLimitError", err)
		}
		if want := int64(len(blob) - MACSize); limitErr.Observed != want {
			t.Fatalf("StreamLimitError.Observed = %d, want the ciphertext body %d", limitErr.Observed, want)
		}
		if dst.n != 0 {
			t.Fatalf("%d plaintext bytes written despite the limit", dst.n)
		}
	})

	t.Run("decrypt plaintext just over the limit", func(t *testing.T) {
		// Body is exactly limit+16, so the cheap size pre-check cannot
		// reject it; the exact plaintext length after unpadding must.
		plaintext := plaintextPattern(limit + 1)
		blob, err := Encrypt(plaintext, keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		dst := &countWriter{}
		err = DecryptStream(dst, bytes.NewReader(blob), int64(len(blob)), keys)
		if !errors.Is(err, ErrStreamLimit) {
			t.Fatalf("DecryptStream error = %v, want ErrStreamLimit", err)
		}
		var limitErr *StreamLimitError
		if !errors.As(err, &limitErr) {
			t.Fatalf("error %v does not unwrap to *StreamLimitError", err)
		}
		if limitErr.Observed != int64(limit+1) {
			t.Fatalf("StreamLimitError.Observed = %d, want the plaintext length %d", limitErr.Observed, limit+1)
		}
		if dst.n != 0 {
			t.Fatalf("%d plaintext bytes written despite the limit", dst.n)
		}
	})

	t.Run("decrypt at limit", func(t *testing.T) {
		plaintext := plaintextPattern(limit)
		blob, err := Encrypt(plaintext, keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		var dst bytes.Buffer
		if err := DecryptStream(&dst, bytes.NewReader(blob), int64(len(blob)), keys); err != nil {
			t.Fatalf("DecryptStream: %v", err)
		}
		if !bytes.Equal(dst.Bytes(), plaintext) {
			t.Fatalf("plaintext mismatch at the limit boundary")
		}
	})

	t.Run("zero disables the cap", func(t *testing.T) {
		MaxStreamBytes = 0
		plaintext := plaintextPattern(1 << 16)
		var dst bytes.Buffer
		if _, err := EncryptStream(&dst, bytes.NewReader(plaintext), keys); err != nil {
			t.Fatalf("EncryptStream with the cap disabled: %v", err)
		}
		var back bytes.Buffer
		if err := DecryptStream(&back, bytes.NewReader(dst.Bytes()), int64(dst.Len()), keys); err != nil {
			t.Fatalf("DecryptStream with the cap disabled: %v", err)
		}
		if !bytes.Equal(back.Bytes(), plaintext) {
			t.Fatalf("round-trip mismatch with the cap disabled")
		}
	})
}

// TestStreamInvalidArgs rejects nil endpoints and negative sizes.
func TestStreamInvalidArgs(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	blob, err := Encrypt([]byte("payload"), keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("encrypt nil writer", func(t *testing.T) {
		if _, err := EncryptStream(nil, bytes.NewReader(blob), keys); !errors.Is(err, ErrInvalidStream) {
			t.Fatalf("error = %v, want ErrInvalidStream", err)
		}
	})
	t.Run("encrypt nil reader", func(t *testing.T) {
		var dst bytes.Buffer
		if _, err := EncryptStream(&dst, nil, keys); !errors.Is(err, ErrInvalidStream) {
			t.Fatalf("error = %v, want ErrInvalidStream", err)
		}
		if dst.Len() != 0 {
			t.Fatalf("%d bytes written for a nil reader", dst.Len())
		}
	})
	t.Run("decrypt nil writer", func(t *testing.T) {
		if err := DecryptStream(nil, bytes.NewReader(blob), int64(len(blob)), keys); !errors.Is(err, ErrInvalidStream) {
			t.Fatalf("error = %v, want ErrInvalidStream", err)
		}
	})
	t.Run("decrypt nil reader", func(t *testing.T) {
		var dst bytes.Buffer
		if err := DecryptStream(&dst, nil, int64(len(blob)), keys); !errors.Is(err, ErrInvalidStream) {
			t.Fatalf("error = %v, want ErrInvalidStream", err)
		}
	})
	t.Run("negative size", func(t *testing.T) {
		var dst bytes.Buffer
		if err := DecryptStream(&dst, bytes.NewReader(blob), -1, keys); !errors.Is(err, ErrInvalidStream) {
			t.Fatalf("error = %v, want ErrInvalidStream", err)
		}
	})
	t.Run("sidecar nil reader", func(t *testing.T) {
		if _, err := SidecarHash(nil); !errors.Is(err, ErrInvalidStream) {
			t.Fatalf("error = %v, want ErrInvalidStream", err)
		}
	})
	t.Run("sidecar read error", func(t *testing.T) {
		boom := errors.New("boom")
		if _, err := SidecarHash(&errReader{data: []byte("payload"), err: boom}); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want the reader's error", err)
		}
	})
}

// TestStreamLimitErrorMessage pins the sentinel's rendered form so callers can
// log it without unwrapping.
func TestStreamLimitErrorMessage(t *testing.T) {
	err := &StreamLimitError{Limit: 512 << 20, Observed: 600 << 20}
	want := "media: stream limit exceeded: 629145600 bytes exceeds 536870912"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}

// TestStreamIOFailures covers sources and destinations that misbehave: short
// reads with a nil error, one-byte writes, zero-progress writes, and a read
// error mid-payload.
func TestStreamIOFailures(t *testing.T) {
	keys := mustDerive(t, TypeVideo)

	t.Run("short reader at", func(t *testing.T) {
		plaintext := plaintextPattern(1000)
		want, err := Encrypt(plaintext, keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		var dst bytes.Buffer
		if err := DecryptStream(&dst, &chunkedReaderAt{data: want, max: 7}, int64(len(want)), keys); err != nil {
			t.Fatalf("DecryptStream through short ReaderAt: %v", err)
		}
		if !bytes.Equal(dst.Bytes(), plaintext) {
			t.Fatalf("plaintext mismatch through short ReaderAt")
		}
	})

	t.Run("one byte writes", func(t *testing.T) {
		plaintext := plaintextPattern(100)
		dst := &tinyWriter{max: 1}
		if _, err := EncryptStream(dst, bytes.NewReader(plaintext), keys); err != nil {
			t.Fatalf("EncryptStream: %v", err)
		}
		var back bytes.Buffer
		if err := DecryptStream(&back, bytes.NewReader(dst.dst.Bytes()), int64(dst.dst.Len()), keys); err != nil {
			t.Fatalf("DecryptStream: %v", err)
		}
		if !bytes.Equal(back.Bytes(), plaintext) {
			t.Fatalf("plaintext mismatch through one-byte writes")
		}
	})

	t.Run("zero progress write", func(t *testing.T) {
		if _, err := EncryptStream(stalledWriter{}, bytes.NewReader([]byte("x")), keys); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("error = %v, want io.ErrShortWrite", err)
		}
	})

	t.Run("zero progress read", func(t *testing.T) {
		if _, err := EncryptStream(&bytes.Buffer{}, &stalledReader{}, keys); !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("error = %v, want io.ErrNoProgress", err)
		}
	})

	t.Run("zero progress reader at", func(t *testing.T) {
		blob, err := Encrypt([]byte("payload"), keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		var dst bytes.Buffer
		if err := DecryptStream(&dst, stalledReaderAt{}, int64(len(blob)), keys); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("error = %v, want io.ErrUnexpectedEOF", err)
		}
		if dst.Len() != 0 {
			t.Fatalf("%d plaintext bytes written from a stalled source", dst.Len())
		}
	})

	t.Run("reader at returns data with EOF", func(t *testing.T) {
		plaintext := plaintextPattern(200)
		want, err := Encrypt(plaintext, keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		var dst bytes.Buffer
		if err := DecryptStream(&dst, eofReaderAt{data: want}, int64(len(want)), keys); err != nil {
			t.Fatalf("DecryptStream through data-plus-EOF ReaderAt: %v", err)
		}
		if !bytes.Equal(dst.Bytes(), plaintext) {
			t.Fatalf("plaintext mismatch through data-plus-EOF ReaderAt")
		}
	})

	t.Run("MAC write error", func(t *testing.T) {
		boom := errors.New("boom")
		keys := mustDerive(t, TypeAudio)
		plaintext := plaintextPattern(64)
		// Encrypt produces one ciphertext chunk of 80 bytes, then the MAC.
		dst := &errWriter{limit: len(plaintext) + cbc.BlockSize, err: boom}
		n, err := EncryptStream(dst, bytes.NewReader(plaintext), keys)
		if !errors.Is(err, boom) {
			t.Fatalf("error = %v, want the writer's error", err)
		}
		if n != int64(len(plaintext)+cbc.BlockSize) {
			t.Fatalf("ciphertextLen = %d, want %d", n, len(plaintext)+cbc.BlockSize)
		}
	})

	t.Run("decrypt read fails per pass", func(t *testing.T) {
		// A 64-byte payload yields a single 80-byte ciphertext body, so the
		// reads are: body (call 0), MAC (1), padding predecessor (2), final
		// block (3), decrypt (4). Failing at each one must abort with no
		// plaintext written, so every pass is covered.
		plaintext := plaintextPattern(64)
		blob, err := Encrypt(plaintext, keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		for _, skip := range []int{1, 2, 3, 4} {
			boom := errors.New("boom")
			var dst bytes.Buffer
			src := &failAfterReaderAt{data: blob, skip: skip, err: boom}
			if err := DecryptStream(&dst, src, int64(len(blob)), keys); !errors.Is(err, boom) {
				t.Fatalf("skip %d: error = %v, want the reader's error", skip, err)
			}
			if dst.Len() != 0 {
				t.Fatalf("skip %d: %d plaintext bytes written", skip, dst.Len())
			}
		}
	})

	t.Run("decrypt write error", func(t *testing.T) {
		boom := errors.New("boom")
		blob, err := Encrypt(plaintextPattern(128), keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if err := DecryptStream(&errWriter{limit: 16, err: boom}, bytes.NewReader(blob), int64(len(blob)), keys); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want the writer's error", err)
		}
	})

	t.Run("write error", func(t *testing.T) {
		boom := errors.New("boom")
		dst := &errWriter{limit: 10, err: boom}
		if _, err := EncryptStream(dst, bytes.NewReader(plaintextPattern(100)), keys); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want the writer's error", err)
		}
	})

	t.Run("read error", func(t *testing.T) {
		boom := errors.New("boom")
		src := &errReader{data: []byte("partial payload"), err: boom}
		var dst bytes.Buffer
		if _, err := EncryptStream(&dst, src, keys); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want the reader's error", err)
		}
	})

	t.Run("reader at fails mid-body", func(t *testing.T) {
		boom := errors.New("boom")
		blob, err := Encrypt(plaintextPattern(100), keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		src := &failingReaderAt{data: blob, limit: 40, err: boom}
		var dst bytes.Buffer
		if err := DecryptStream(&dst, src, int64(len(blob)), keys); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want the reader's error", err)
		}
		if dst.Len() != 0 {
			t.Fatalf("%d plaintext bytes written after a read error", dst.Len())
		}
	})
}

// TestSidecarHashVectors pins SHA-256 over the plaintext against digests
// computed independently with python3 hashlib in this session (PF-047).
func TestSidecarHashVectors(t *testing.T) {
	tests := []struct {
		name string
		// data is built by the generator unless literal is set.
		size    int
		literal []byte
		want    string
	}{
		{
			name: "empty",
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:    "one zero byte",
			literal: []byte{0x00},
			want:    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		},
		{
			name: "seventeen bytes",
			size: 17,
			want: "b6ff0191041cc77b1ef514adaed53fdd247fd43221a629d3d7c91d14e21038a3",
		},
		{
			name: "one MiB",
			size: 1 << 20,
			want: "06b7bbfb7824aa03382051691630eb26de85102d1b08a81e907ec0744cd8a286",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.literal
			if data == nil {
				data = plaintextPattern(tc.size)
			}
			want := mustHex(t, "sidecar", tc.want)

			got, err := SidecarHash(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("SidecarHash: %v", err)
			}
			if !bytes.Equal(got[:], want) {
				t.Fatalf("SidecarHash = %x, want %x", got, want)
			}
			// Independent cross-check against the stdlib one-shot digest.
			if oneShot := sha256.Sum256(data); got != oneShot {
				t.Fatalf("SidecarHash = %x, sha256.Sum256 = %x", got, oneShot)
			}

			if gotHex := hex.EncodeToString(got[:]); gotHex != tc.want {
				t.Fatalf("hex form = %s, want %s", gotHex, tc.want)
			}
		})
	}
}

// TestSidecarHashIndependentOfEncryption shows the sidecar digest covers the
// plaintext, not the envelope, and matches the SHA256 field core/media fills
// (PF-045, PF-047).
func TestSidecarHashIndependentOfEncryption(t *testing.T) {
	keys := mustDerive(t, TypeVideo)
	plaintext := plaintextPattern(4096)
	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(blob, plaintext) {
		t.Fatal("envelope equals the plaintext")
	}

	ofPlain, err := SidecarHash(bytes.NewReader(plaintext))
	if err != nil {
		t.Fatalf("SidecarHash(plaintext): %v", err)
	}
	ofBlob, err := SidecarHash(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("SidecarHash(blob): %v", err)
	}
	if ofPlain == ofBlob {
		t.Fatal("sidecar digest is identical for plaintext and ciphertext")
	}
	if want := sha256.Sum256(plaintext); ofPlain != want {
		t.Fatalf("sidecar digest of plaintext = %x, want %x", ofPlain, want)
	}
}

// flip returns blob with one bit flipped at pos, leaving blob untouched.
func flip(blob []byte, pos int) []byte {
	out := append([]byte(nil), blob...)
	out[pos] ^= 0x01
	return out
}
