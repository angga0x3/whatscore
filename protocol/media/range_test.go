package media

// Tests for partial decryption (PF-048). The round-trip table compares every
// range against the slice of the full Decrypt output, the window tests pin the
// ciphertext the reader is allowed to touch, and the tail tests cover requests
// that end inside or after the PKCS#7 padding.

import (
	"bytes"
	"errors"
	"io"
	"sort"
	"strconv"
	"testing"

	"github.com/angga0x3/whatscore/internal/cbc"
)

// readSpan is one ReadAt call as the source saw it.
type readSpan struct {
	off int64
	n   int64
}

// windowReaderAt serves data like bytes.Reader but records every span it was
// asked for, so a test can assert which part of the blob was read, not just
// what came out of the decryption.
type windowReaderAt struct {
	data  []byte
	reads []readSpan
	bytes int64
}

func (r *windowReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	r.reads = append(r.reads, readSpan{off: off, n: int64(n)})
	r.bytes += int64(n)
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// TestRangeWindowArithmetic pins the ciphertext window and the leading discard
// count for the boundary offsets the API documents (PF-048).
func TestRangeWindowArithmetic(t *testing.T) {
	tests := []struct {
		name                string
		offset, want        int64
		start, end, discard int64
	}{
		{"first byte", 0, 1, 0, 16, 0},
		{"first block", 0, 16, 0, 16, 0},
		{"second byte", 1, 1, 0, 16, 1},
		{"last byte of block zero", 15, 1, 0, 16, 15},
		{"aligned second block", 16, 1, 0, 32, 16},
		{"one byte into second block", 17, 1, 0, 32, 17},
		{"mid blob", 100, 1, 80, 112, 20},
		{"mid blob span", 100, 1000, 80, 1104, 20},
		{"tail block", 4096, 1, 4080, 4112, 16},
		{"last aligned block", 4000, 16, 3984, 4016, 16},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start, end, discard := rangeWindow(tc.offset, tc.want)
			if start != tc.start || end != tc.end || discard != tc.discard {
				t.Fatalf("rangeWindow(%d, %d) = (%d, %d, %d), want (%d, %d, %d)",
					tc.offset, tc.want, start, end, discard, tc.start, tc.end, tc.discard)
			}
		})
	}
}

// TestRangeWindowInvariants sweeps offsets and lengths and requires the window
// to be block aligned, to contain every block the range depends on, and to be
// no larger than necessary: one lead-in block when the offset is not block
// aligned, and exactly the blocks of the request plus that lead-in.
func TestRangeWindowInvariants(t *testing.T) {
	for offset := int64(0); offset < 300; offset++ {
		for want := int64(1); want <= 100; want++ {
			start, end, discard := rangeWindow(offset, want)

			if start%cbc.BlockSize != 0 || end%cbc.BlockSize != 0 {
				t.Fatalf("offset %d, want %d: window [%d, %d) is not block aligned", offset, want, start, end)
			}
			if start < 0 {
				t.Fatalf("offset %d, want %d: negative window start %d", offset, want, start)
			}
			// The window starts one block before the first requested block,
			// which is the ciphertext block that first block XORs against;
			// at offset 0 there is no predecessor to read.
			wantStart := offset / cbc.BlockSize * cbc.BlockSize
			if wantStart > 0 {
				wantStart -= cbc.BlockSize
			}
			if start != wantStart {
				t.Fatalf("offset %d, want %d: window start %d, want %d", offset, want, start, wantStart)
			}
			if end < offset+want {
				t.Fatalf("offset %d, want %d: window end %d excludes the last byte", offset, want, end)
			}
			if end-offset-want >= cbc.BlockSize+offset%cbc.BlockSize {
				t.Fatalf("offset %d, want %d: window [%d, %d) overreaches", offset, want, start, end)
			}
			// The window must leave at least the requested bytes after the
			// discard, and the only surplus is the unused tail of the last
			// block, so less than one block.
			if got := end - start - discard; got < want || got-want >= cbc.BlockSize {
				t.Fatalf("offset %d, want %d: window leaves %d bytes after discard", offset, want, got)
			}
		}
	}
}

// TestDecryptRangeRoundTrip decrypts every documented offset and length and
// compares the result byte for byte with the corresponding slice of the full
// Decrypt output (PF-048).
func TestDecryptRangeRoundTrip(t *testing.T) {
	keys := mustDerive(t, TypeVideo)
	plaintext := plaintextPattern(4096)
	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	full, err := Decrypt(blob, keys)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(full, plaintext) {
		t.Fatalf("full Decrypt mismatch")
	}

	offsets := []int64{0, 1, 15, 16, 17, 100}
	lengths := []struct {
		name string
		n    int64 // 0 means "everything left from offset"
	}{
		{"one byte", 1},
		{"one block", 16},
		{"block plus one", 17},
		{"one thousand", 1000},
		{"remainder", 0},
	}
	for _, offset := range offsets {
		for _, l := range lengths {
			t.Run(l.name+"/offset="+strconv.FormatInt(offset, 10), func(t *testing.T) {
				want := l.n
				if want == 0 {
					want = int64(len(full)) - offset
				}
				expect := full[offset : offset+want]

				var dst bytes.Buffer
				n, err := DecryptRange(&dst, bytes.NewReader(blob), int64(len(blob)), offset, want, keys, true)
				if err != nil {
					t.Fatalf("DecryptRange: %v", err)
				}
				if int64(n) != want {
					t.Fatalf("n = %d, want %d", n, want)
				}
				if !bytes.Equal(dst.Bytes(), expect) {
					t.Fatalf("range mismatch at offset %d, length %d", offset, want)
				}
			})
		}
	}
}

// TestDecryptRangeReadsOnlyItsWindow wraps the blob in a recording ReaderAt and
// requires every read to stay inside the computed window or the padding probe
// at the very end of the body, and the reads inside the window to cover exactly
// the window (PF-048).
func TestDecryptRangeReadsOnlyItsWindow(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	const plaintextSize = 4096
	plaintext := plaintextPattern(plaintextSize)
	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	body := int64(len(blob) - MACSize)
	tailStart := body - 2*int64(cbc.BlockSize)

	tests := []struct {
		name           string
		offset, length int64
	}{
		{"mid blob", 100, 1000},
		{"one mid block", 2048, 16},
		{"unaligned mid block", 2053, 3},
		{"head", 0, 100},
		{"tail block", plaintextSize - 16, 16},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := &windowReaderAt{data: blob}
			var dst bytes.Buffer
			n, err := DecryptRange(&dst, src, int64(len(blob)), tc.offset, tc.length, keys, true)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("DecryptRange: %v", err)
			}
			if n != len(dst.Bytes()) {
				t.Fatalf("n = %d, bytes in dst = %d", n, len(dst.Bytes()))
			}

			start, end, _ := rangeWindow(tc.offset, tc.length)
			for _, read := range src.reads {
				inWindow := read.off >= start && read.off+read.n <= end
				inTailProbe := read.off >= tailStart && read.off+read.n <= body
				if !inWindow && !inTailProbe {
					t.Fatalf("read [%d, %d) is outside the window [%d, %d) and the tail probe [%d, %d)",
						read.off, read.off+read.n, start, end, tailStart, body)
				}
			}

			// The window must be covered without gaps: the payload pass is
			// exactly as large as the window, no more and no less.
			spans := make([]readSpan, 0, len(src.reads))
			for _, read := range src.reads {
				lo, hi := max(read.off, start), min(read.off+read.n, end)
				if lo < hi {
					spans = append(spans, readSpan{off: lo, n: hi - lo})
				}
			}
			sort.Slice(spans, func(i, j int) bool { return spans[i].off < spans[j].off })
			covered := int64(0)
			next := start
			for _, span := range spans {
				if span.off > next {
					t.Fatalf("gap in the window: [%d, %d) was never read", next, span.off)
				}
				if span.off+span.n > next {
					covered += span.off + span.n - next
					next = span.off + span.n
				}
			}
			if next != end {
				t.Fatalf("window covered up to %d, want %d", next, end)
			}
			if covered != end-start {
				t.Fatalf("covered %d window bytes, want %d", covered, end-start)
			}

			// And the total read is the window plus at most the two probe
			// blocks, so a range cannot stream the blob.
			if src.bytes > end-start+2*int64(cbc.BlockSize) {
				t.Fatalf("read %d bytes for a %d-byte range", src.bytes, end-start)
			}
		})
	}
}

// TestDecryptRangeTail covers requests that end in, at, or past the PKCS#7
// padding: no padding byte may be emitted, and a truncated range reports
// io.EOF with the bytes that do exist (PF-042, PF-048).
func TestDecryptRangeTail(t *testing.T) {
	keys := mustDerive(t, TypeDocument)

	// 4096 bytes pad to a whole extra block of 0x10.
	aligned := plaintextPattern(4096)
	alignedBlob, err := Encrypt(aligned, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// 4090 bytes pad with six 0x06 bytes inside the last block.
	unaligned := plaintextPattern(4090)
	unalignedBlob, err := Encrypt(unaligned, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got := len(unalignedBlob) - MACSize; got != 4096 {
		t.Fatalf("unaligned body = %d, want 4096", got)
	}

	tests := []struct {
		name       string
		blob       []byte
		plaintext  []byte
		offset     int64
		length     int64
		want       int
		wantEOF    bool
		wantNoRead bool
	}{
		{name: "last byte", blob: alignedBlob, plaintext: aligned, offset: 4095, length: 1, want: 1},
		{name: "last two bytes", blob: alignedBlob, plaintext: aligned, offset: 4094, length: 2, want: 2},
		{name: "last sixteen bytes", blob: alignedBlob, plaintext: aligned, offset: 4080, length: 16, want: 16},
		{name: "last byte with a long length", blob: alignedBlob, plaintext: aligned, offset: 4095, length: 1000, want: 1, wantEOF: true},
		{name: "padding only", blob: alignedBlob, plaintext: aligned, offset: 4096, length: 16, want: 0, wantEOF: true},
		{name: "padding only zero length", blob: alignedBlob, plaintext: aligned, offset: 4096, length: 0, want: 0, wantNoRead: true},
		{name: "padding inside last block", blob: unalignedBlob, plaintext: unaligned, offset: 4088, length: 16, want: 2, wantEOF: true},
		{name: "padding starts mid block", blob: unalignedBlob, plaintext: unaligned, offset: 4090, length: 16, want: 0, wantEOF: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := &windowReaderAt{data: tc.blob}
			var dst bytes.Buffer
			n, err := DecryptRange(&dst, src, int64(len(tc.blob)), tc.offset, tc.length, keys, true)

			if tc.wantEOF {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("error = %v, want io.EOF", err)
				}
			} else if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if n != tc.want || dst.Len() != tc.want {
				t.Fatalf("n = %d, dst = %d bytes, want %d", n, dst.Len(), tc.want)
			}
			if tc.want > 0 {
				want := tc.plaintext[tc.offset : tc.offset+int64(tc.want)]
				if !bytes.Equal(dst.Bytes(), want) {
					t.Fatalf("range mismatch: got %x, want %x", dst.Bytes(), want)
				}
			}
			if tc.wantNoRead && len(src.reads) != 0 {
				t.Fatalf("%d reads happened for a zero-length request", len(src.reads))
			}
		})
	}
}

// TestDecryptRangeUnverified requires the pre-verification assertion, and
// proves the rejection happens before the source is read or dst is written
// (PF-048).
func TestDecryptRangeUnverified(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	blob, err := Encrypt(plaintextPattern(64), keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	src := &windowReaderAt{data: blob}
	var dst bytes.Buffer
	n, err := DecryptRange(&dst, src, int64(len(blob)), 0, 16, keys, false)
	if !errors.Is(err, ErrRangeUnverified) {
		t.Fatalf("error = %v, want ErrRangeUnverified", err)
	}
	if n != 0 || dst.Len() != 0 {
		t.Fatalf("n = %d, dst = %d bytes, want nothing written", n, dst.Len())
	}
	if len(src.reads) != 0 {
		t.Fatalf("%d reads happened before the verification check", len(src.reads))
	}

	// The flag is the only thing that changes: the same call verified runs.
	if _, err := DecryptRange(&dst, src, int64(len(blob)), 0, 16, keys, true); err != nil {
		t.Fatalf("DecryptRange verified: %v", err)
	}
	if dst.Len() != 16 {
		t.Fatalf("verified call wrote %d bytes, want 16", dst.Len())
	}
}

// TestDecryptRangeTrustsTheVerifiedFlag shows why authentication must cover the
// whole blob. With verified == true, a tampered ciphertext decrypts without an
// error and returns wrong plaintext: CBC spreads one changed ciphertext block
// into its own plaintext block and the next one, and the truncated MAC that
// would have caught it is never consulted here (PF-043, PF-048).
func TestDecryptRangeTrustsTheVerifiedFlag(t *testing.T) {
	keys := mustDerive(t, TypeAudio)
	plaintext := plaintextPattern(4096)
	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip one bit in ciphertext block 10. The blob itself is still
	// structurally valid: alignment and padding are untouched.
	const tamperedBlock = 10
	tampered := flip(blob, tamperedBlock*cbc.BlockSize)

	// The blocks the change reaches: 10 (its own decryption) and 11 (which
	// XORs against block 10's ciphertext).
	offset := int64(tamperedBlock * cbc.BlockSize)
	length := int64(2 * cbc.BlockSize)

	var dst bytes.Buffer
	n, err := DecryptRange(&dst, bytes.NewReader(tampered), int64(len(tampered)), offset, length, keys, true)
	if err != nil {
		t.Fatalf("DecryptRange on a tampered blob: %v (want silent wrong plaintext)", err)
	}
	if n != int(length) {
		t.Fatalf("n = %d, want %d", n, length)
	}
	if bytes.Equal(dst.Bytes(), plaintext[offset:offset+length]) {
		t.Fatal("tampered ciphertext produced the authentic plaintext")
	}

	// Blocks before the tampered one decrypt correctly, which is exactly why
	// per-range checks cannot substitute for whole-blob authentication: a
	// server answering one range sees no evidence of the change at all.
	dst.Reset()
	if _, err := DecryptRange(&dst, bytes.NewReader(tampered), int64(len(tampered)), 0, 32, keys, true); err != nil {
		t.Fatalf("DecryptRange before the tampered block: %v", err)
	}
	if !bytes.Equal(dst.Bytes(), plaintext[:32]) {
		t.Fatal("plaintext before the tampered block changed")
	}

	// The full-blob verifier rejects the same blob, and DecryptRange must only
	// be called after that check has passed.
	if _, err := Decrypt(blob, keys); err != nil {
		t.Fatalf("Decrypt(authentic): %v", err)
	}
	if _, err := Decrypt(tampered, keys); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("Decrypt(tampered) error = %v, want ErrBadMAC", err)
	}
}

// TestDecryptRangeBounds is the bounds table: impossible arguments, framing
// failures, clamping at the end of the plaintext, and the MaxStreamBytes policy
// (PF-044, PF-048).
func TestDecryptRangeBounds(t *testing.T) {
	keys := mustDerive(t, TypeDocument)
	const plaintextSize = 4096
	plaintext := plaintextPattern(plaintextSize)
	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	size := int64(len(blob))
	body := size - MACSize

	tests := []struct {
		name     string
		dst      io.Writer
		src      io.ReaderAt
		size     int64
		offset   int64
		length   int64
		verified bool
		wantN    int
		wantErr  error
	}{
		{
			name: "negative offset", dst: io.Discard, src: bytes.NewReader(blob), size: size,
			offset: -1, length: 1, verified: true, wantErr: ErrInvalidRange,
		},
		{
			name: "negative length", dst: io.Discard, src: bytes.NewReader(blob), size: size,
			offset: 0, length: -1, verified: true, wantErr: ErrInvalidRange,
		},
		{
			name: "offset one past the padded plaintext", dst: io.Discard, src: bytes.NewReader(blob), size: size,
			offset: body + 1, length: 1, verified: true, wantErr: ErrInvalidRange,
		},
		{
			name: "offset at the padded end", dst: io.Discard, src: bytes.NewReader(blob), size: size,
			offset: body, length: 1, verified: true, wantErr: io.EOF,
		},
		{
			name: "offset at the plaintext end", dst: io.Discard, src: bytes.NewReader(blob), size: size,
			offset: plaintextSize, length: 1, verified: true, wantErr: io.EOF,
		},
		{
			name: "length crossing the end", dst: io.Discard, src: bytes.NewReader(blob), size: size,
			offset: plaintextSize - 6, length: 100, verified: true, wantN: 6, wantErr: io.EOF,
		},
		{
			name: "length ending exactly at the end", dst: io.Discard, src: bytes.NewReader(blob), size: size,
			offset: plaintextSize - 1000, length: 1000, verified: true, wantN: 1000,
		},
		{
			name: "zero length", dst: io.Discard, src: bytes.NewReader(blob), size: size,
			offset: 100, length: 0, verified: true, wantN: 0,
		},
		{
			name: "blob shorter than one padded block", dst: io.Discard, src: bytes.NewReader(blob), size: MACSize,
			offset: 0, length: 1, verified: true, wantErr: ErrInvalidCiphertext,
		},
		{
			name: "body not block aligned", dst: io.Discard, src: bytes.NewReader(append(append([]byte(nil), blob...), 0x00)), size: size + 1,
			offset: 0, length: 1, verified: true, wantErr: ErrInvalidCiphertext,
		},
		{
			name: "nil destination", dst: nil, src: bytes.NewReader(blob), size: size,
			offset: 0, length: 1, verified: true, wantErr: ErrInvalidStream,
		},
		{
			name: "nil source", dst: io.Discard, src: nil, size: size,
			offset: 0, length: 1, verified: true, wantErr: ErrInvalidStream,
		},
		{
			name: "negative size", dst: io.Discard, src: bytes.NewReader(blob), size: -1,
			offset: 0, length: 1, verified: true, wantErr: ErrInvalidStream,
		},
		{
			name: "unverified", dst: io.Discard, src: bytes.NewReader(blob), size: size,
			offset: 0, length: 1, verified: false, wantErr: ErrRangeUnverified,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := DecryptRange(tc.dst, tc.src, tc.size, tc.offset, tc.length, keys, tc.verified)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if n != tc.wantN {
				t.Fatalf("n = %d, want %d", n, tc.wantN)
			}
		})
	}

	t.Run("MaxStreamBytes", func(t *testing.T) {
		defer func(old int64) { MaxStreamBytes = old }(MaxStreamBytes)
		MaxStreamBytes = 1000

		var dst bytes.Buffer
		_, err := DecryptRange(&dst, bytes.NewReader(blob), size, 0, 1001, keys, true)
		if !errors.Is(err, ErrStreamLimit) {
			t.Fatalf("error = %v, want ErrStreamLimit", err)
		}
		var limitErr *StreamLimitError
		if !errors.As(err, &limitErr) {
			t.Fatalf("error %v does not unwrap to *StreamLimitError", err)
		}
		if limitErr.Limit != 1000 || limitErr.Observed != 1001 {
			t.Fatalf("StreamLimitError = {Limit:%d Observed:%d}, want {1000 1001}", limitErr.Limit, limitErr.Observed)
		}
		if dst.Len() != 0 {
			t.Fatalf("%d bytes written despite the limit", dst.Len())
		}

		// The cap applies after clamping, so "everything from here" is not
		// rejected when the remainder fits.
		dst.Reset()
		n, err := DecryptRange(&dst, bytes.NewReader(blob), size, plaintextSize-1000, 1<<20, keys, true)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("clamped range error = %v, want io.EOF", err)
		}
		if n != 1000 || dst.Len() != 1000 {
			t.Fatalf("n = %d, dst = %d bytes, want 1000", n, dst.Len())
		}
		if !bytes.Equal(dst.Bytes(), plaintext[plaintextSize-1000:]) {
			t.Fatal("clamped range mismatch")
		}
	})
}

// TestDecryptRangeMalformedPadding rejects an authentic-but-malformed blob the
// same way DecryptStream does, before any plaintext is written (PF-044).
func TestDecryptRangeMalformedPadding(t *testing.T) {
	keys := mustDerive(t, TypeImage)
	// Authentic tag over a single block whose padding is invalid.
	blob := encryptBlock(t, bytes.Repeat([]byte{0x00}, cbc.BlockSize), keys)

	var dst bytes.Buffer
	n, err := DecryptRange(&dst, bytes.NewReader(blob), int64(len(blob)), 0, 1, keys, true)
	if !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("error = %v, want ErrInvalidCiphertext", err)
	}
	if n != 0 || dst.Len() != 0 {
		t.Fatalf("n = %d, dst = %d bytes, want nothing written", n, dst.Len())
	}
}

// TestDecryptRangeIOFailures covers a source that fails mid-window: the call
// must surface the reader's error and report only the bytes it actually wrote.
func TestDecryptRangeIOFailures(t *testing.T) {
	keys := mustDerive(t, TypeVideo)
	plaintext := plaintextPattern(1 << 16)
	blob, err := Encrypt(plaintext, keys)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	boom := errors.New("boom")
	// The padding probe reads two blocks at the end of the body (calls 0 and
	// 1); failing call 3 lets the first 32 KiB payload chunk through and
	// aims the error at the second, so the count is a real partial prefix.
	src := &failAfterReaderAt{data: blob, skip: 3, err: boom}
	var dst bytes.Buffer
	n, err := DecryptRange(&dst, src, int64(len(blob)), 0, 1<<16, keys, true)
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the reader's error", err)
	}
	if n != dst.Len() {
		t.Fatalf("n = %d, bytes in dst = %d", n, dst.Len())
	}
	if n == 0 || n >= 1<<16 {
		t.Fatalf("n = %d, want a partial count", n)
	}

	t.Run("short reader at", func(t *testing.T) {
		want, err := Encrypt(plaintextPattern(1000), keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		var dst bytes.Buffer
		n, err := DecryptRange(&dst, &chunkedReaderAt{data: want, max: 7}, int64(len(want)), 3, 900, keys, true)
		if err != nil {
			t.Fatalf("DecryptRange through short ReaderAt: %v", err)
		}
		if n != 900 || !bytes.Equal(dst.Bytes(), plaintextPattern(1000)[3:903]) {
			t.Fatalf("range through a short ReaderAt mismatch (n = %d)", n)
		}
	})

	t.Run("write error", func(t *testing.T) {
		boom := errors.New("boom")
		blob, err := Encrypt(plaintextPattern(512), keys)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		n, err := DecryptRange(&errWriter{limit: 100, err: boom}, bytes.NewReader(blob), int64(len(blob)), 0, 512, keys, true)
		if !errors.Is(err, boom) {
			t.Fatalf("error = %v, want the writer's error", err)
		}
		if n != 100 {
			t.Fatalf("n = %d, want the 100 bytes the writer accepted", n)
		}
	})
}
