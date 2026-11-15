package media

// Partial (range) decryption of the media envelope (PF-048). A caller that
// only needs a slice of a media object — a resumed download, a byte-serving
// HTTP handler, a seek — decrypts it straight from the blob through
// io.ReaderAt instead of materialising the whole payload. The truncated MAC
// still covers the whole blob, which is why DecryptRange refuses to run
// without the caller's proof that it has already authenticated it.

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/angga0x3/whatscore/internal/cbc"
)

// maxRangeCount is the largest byte count DecryptRange can report through its
// int return value.
const maxRangeCount = int(^uint(0) >> 1)

// Sentinel errors for the range entry point
// (docs/architecture/technical-specification.md §8.1). Callers match with
// errors.Is; every returned error wraps one of these with %w, or the sentinel
// of the streaming path it originates from.
var (
	// ErrInvalidRange is returned when the requested plaintext range cannot
	// exist: a negative offset or length, an offset past the end of the
	// padded plaintext, or a length that cannot be reported through the int
	// return value.
	ErrInvalidRange = errors.New("media: invalid range")

	// ErrRangeUnverified is returned by DecryptRange when the caller does
	// not assert that the full blob MAC has already been verified. A byte
	// range cannot be authenticated on its own: the tag covers iv ‖
	// ciphertext as a whole (PF-043, PF-048).
	ErrRangeUnverified = errors.New("media: range decryption not pre-verified")
)

// DecryptRange decrypts the plaintext bytes [offset, offset+length) of a blob
// whose ciphertext is readable through src at [0, size) and writes them to dst
// (PF-042, PF-043, PF-048). At most the blocks the requested plaintext depends
// on are read; the ciphertext is never streamed in full.
//
// # Ciphertext window
//
// CBC makes each plaintext block depend on its own ciphertext block and the
// one before it:
//
//	P_N = AES⁻¹(C_N) XOR C_{N-1},  C_{-1} = keys.IV
//
// so a request of n > 0 bytes at offset o needs:
//
//	firstBlock  = o / 16
//	lastBlock   = (o+n-1) / 16
//	windowStart = (firstBlock-1)*16   (0 when firstBlock == 0)
//	windowEnd   = (lastBlock+1)*16
//	discard     = 16*(firstBlock > 0) + o%16
//
// DecryptRange reads exactly [windowStart, windowEnd) in block-aligned chunks
// and decrypts it as a single CBC chain seeded with keys.IV. When firstBlock
// is above zero, the first decrypted block of the window is C_{firstBlock-1}
// decrypted against the IV instead of against its own predecessor, so its
// plaintext is meaningless; it is one of the discarded bytes. The blocks that
// follow are correct regardless, because each one XORs against the preceding
// ciphertext block, which is present in the window. The final `discard` count
// is then dropped: 16 bytes of predecessor block plus o%16 bytes of the first
// requested block when firstBlock is above zero, or just o%16 bytes when the
// range starts inside the first block. That is the "align the offset down to a
// 16-byte boundary, then discard the leading partial block" step, applied to
// the plaintext rather than to the ciphertext.
//
// The requested bytes therefore never require a block before windowStart or at
// or after windowEnd, and the reader sees no other window. To learn the exact
// plaintext length, and to reject a malformed blob the same way DecryptStream
// does, DecryptRange also decrypts the body's final ciphertext block (its
// predecessor too when the body is longer than one block) and validates every
// PKCS#7 byte: at most 32 extra bytes of reads.
//
// # Authentication contract
//
// The MAC is HMAC-SHA256(macKey, iv ‖ ciphertext) truncated to 10 bytes
// (PF-043), so it authenticates the blob as a whole. No prefix, suffix or
// interior slice of the ciphertext can be checked on its own, and a range
// response cannot carry its own tag. DecryptRange therefore does not verify
// the MAC. The verified argument is the caller's assertion that it has already
// authenticated the entire blob, for example with a successful DecryptStream
// call or by recomputing the tag over all of ciphertext and comparing it to
// the trailing MACSize bytes with hmac.Equal. A request made with
// verified == false is rejected with ErrRangeUnverified before src is read or
// dst is touched.
//
// Re-verifying the MAC here was rejected on purpose: the tag cannot be
// computed over a prefix, so every range call would have to hash every
// ciphertext byte and read the trailing tag — O(size) I/O and CPU per ranged
// request, turning a 64 KiB resumed download into a full-blob read. A caller
// that has not already paid that cost must pay it once per blob and remember
// the result for that blob's ranges; per-call verification is the alternative
// this API deliberately does not take.
//
// Because the flag is an assertion, a tampered blob decrypted with
// verified == true yields wrong plaintext for every block touched by the
// change instead of an error. That is not a hole in DecryptRange, it is why
// authentication must cover the whole blob before the first range is served;
// see TestDecryptRangeTrustsTheVerifiedFlag.
//
// # Bounds, padding and results
//
// body is size-MACSize, the padded plaintext length. Framing is checked as in
// DecryptStream: a nil dst or src, or a negative size, returns ErrInvalidStream;
// a size below 26 bytes, a body that is not a positive multiple of the AES
// block size, or non-canonical padding returns ErrInvalidCiphertext.
//
// A negative offset or length returns ErrInvalidRange. An offset above body is
// outside the padded plaintext and returns ErrInvalidRange. An offset in
// [plaintextLen, body] lands inside or at the end of the PKCS#7 padding: no
// byte is decrypted into dst, no padding byte is ever emitted, and the call
// returns (0, io.EOF), which a byte server can treat as end of file. A length
// that runs past plaintextLen is clamped to the bytes that exist; those bytes
// are written and the call returns (n, io.EOF). A range ending exactly at
// plaintextLen returns (n, nil), a zero length at a valid offset returns
// (0, nil), and a range whose effective size exceeds MaxStreamBytes returns a
// *StreamLimitError wrapping ErrStreamLimit. The cap applies after clamping, so
// length may name "everything from offset" without tripping it.
//
// The count is the number of plaintext bytes written, which is also the number
// of bytes in dst: on a write or read error it is a lower bound, because the
// bytes already written stay written. dst is not transactional; callers that
// need all-or-nothing buffering should decrypt into a buffer they can discard.
func DecryptRange(dst io.Writer, src io.ReaderAt, size int64, offset, length int64, keys Keys, verified bool) (int, error) {
	if dst == nil {
		return 0, fmt.Errorf("%w: nil destination writer", ErrInvalidStream)
	}
	if src == nil {
		return 0, fmt.Errorf("%w: nil source reader", ErrInvalidStream)
	}
	if size < 0 {
		return 0, fmt.Errorf("%w: negative size %d", ErrInvalidStream, size)
	}
	if offset < 0 || length < 0 {
		return 0, fmt.Errorf("%w: offset %d, length %d", ErrInvalidRange, offset, length)
	}
	if !verified {
		return 0, fmt.Errorf("%w: authenticate the full blob before requesting a range", ErrRangeUnverified)
	}
	if size < int64(MACSize+cbc.BlockSize) {
		return 0, fmt.Errorf("%w: %d bytes, need at least %d", ErrInvalidCiphertext, size, MACSize+cbc.BlockSize)
	}
	body := size - int64(MACSize)
	if body%cbc.BlockSize != 0 {
		return 0, fmt.Errorf("%w: ciphertext length %d is not a multiple of %d", ErrInvalidCiphertext, body, cbc.BlockSize)
	}
	if offset > body {
		return 0, fmt.Errorf("%w: offset %d is past the %d-byte padded plaintext", ErrInvalidRange, offset, body)
	}
	if length == 0 {
		return 0, nil
	}

	block, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	// The padding length is the only way to know where the plaintext ends, so
	// it is always resolved, not just for ranges near the tail. The block was
	// authenticated by the caller, so a padding failure here means an
	// authentic-but-malformed blob, exactly as in DecryptStream.
	padding, err := streamPaddingLen(src, block, body, keys)
	if err != nil {
		return 0, err
	}
	plaintextLen := body - int64(padding)
	if offset >= plaintextLen {
		return 0, io.EOF
	}

	want := length
	if remaining := plaintextLen - offset; want > remaining {
		want = remaining
	}
	if want > int64(maxRangeCount) {
		return 0, fmt.Errorf("%w: range of %d bytes exceeds the reportable count %d", ErrInvalidRange, want, int64(maxRangeCount))
	}
	if limit := MaxStreamBytes; limit > 0 && want > limit {
		return 0, &StreamLimitError{Limit: limit, Observed: want}
	}

	windowStart, windowEnd, discard := rangeWindow(offset, want)

	// ct and pt are separate buffers: cipher.BlockMode must not be handed
	// overlapping slices, and the ciphertext has to survive each chunk so its
	// last block can chain into the next.
	ct := make([]byte, streamChunkSize)
	pt := make([]byte, streamChunkSize)
	var chain [cbc.BlockSize]byte
	prev := keys.IV[:]
	written := 0
	remaining := want

	for off := windowStart; off < windowEnd; {
		n := min(int64(streamChunkSize), windowEnd-off)
		if err := readAtFull(src, ct[:n], off); err != nil {
			return written, err
		}
		// The decrypter copies its IV, so it must be constructed before chain
		// is overwritten with the block that chains the following chunk.
		decrypter := cipher.NewCBCDecrypter(block, prev)
		copy(chain[:], ct[n-int64(cbc.BlockSize):n])
		decrypter.CryptBlocks(pt[:n], ct[:n])
		prev = chain[:]

		start := int64(0)
		if discard > 0 {
			start = min(discard, n)
			discard -= start
		}
		if discard == 0 && remaining > 0 {
			take := min(remaining, n-start)
			w, err := writeCounted(dst, pt[start:start+take])
			written += w
			remaining -= int64(w)
			if err != nil {
				return written, err
			}
		}
		off += n
	}
	if remaining != 0 {
		// Unreachable: the window arithmetic covers exactly want bytes.
		return written, fmt.Errorf("media: range decrypt: %w", io.ErrUnexpectedEOF)
	}
	if want < length {
		return written, io.EOF
	}
	return written, nil
}

// rangeWindow returns the ciphertext window [start, end) that the plaintext
// range [offset, offset+n) depends on (PF-048), plus the number of decrypted
// bytes at the start of that window to discard. offset must be non-negative,
// n positive and offset+n within the padded plaintext length.
//
// start is one block before the first requested block whenever that block is
// not the body's first, aligned or not, because the first requested block XORs
// against its predecessor's ciphertext. At offset 0 there is no predecessor to
// read and start is 0. The lead-in block decrypts against the wrong IV so its
// plaintext is meaningless; discard counts it plus offset%16 bytes of the first
// requested block.
func rangeWindow(offset, n int64) (start, end, discard int64) {
	blockSize := int64(cbc.BlockSize)
	firstBlock := offset / blockSize
	lastBlock := (offset + n - 1) / blockSize

	start = firstBlock * blockSize
	discard = offset % blockSize
	if firstBlock > 0 {
		start -= blockSize
		discard += blockSize
	}
	end = (lastBlock + 1) * blockSize
	return start, end, discard
}

// writeCounted writes all of p and returns how many bytes dst accepted, so a
// short write that also reports an error still contributes its prefix to the
// count DecryptRange reports. It is writeFull's behaviour plus the count.
func writeCounted(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			total += n
			p = p[n:]
		}
		if err != nil {
			return total, fmt.Errorf("media: range write: %w", err)
		}
		if n == 0 {
			return total, fmt.Errorf("media: range write: %w", io.ErrShortWrite)
		}
	}
	return total, nil
}
