package media

// Streaming form of the envelope (PF-046, PF-047): the same
// ciphertext ‖ mac[10] wire format, produced and consumed without holding the
// whole payload in memory. EncryptStream output is byte-identical to Encrypt
// for the same plaintext and key set, so either path can consume it.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/angga0x3/whatscore/internal/cbc"
)

const (
	// streamChunkSize is the plaintext chunk size EncryptStream reads and
	// DecryptStream writes. It is a multiple of the AES block size and
	// bounds the working set of a stream to one chunk plus one block.
	streamChunkSize = 32 << 10

	// maxEmptyReads is how many consecutive (0, nil) reads EncryptStream
	// tolerates before giving up with io.ErrNoProgress, matching io.Copy's
	// tolerance for a source that makes no progress.
	maxEmptyReads = 100
)

// MaxStreamBytes is the largest plaintext payload the streaming entry points
// accept, in bytes; 512 MiB by default. A non-positive value disables the
// cap. Set it during initialization, before any stream runs: it is read
// without synchronization, so changing it while streams are in flight is a
// data race.
//
// The cap bounds work per call, not memory: a hostile reader cannot drive
// unbounded encryption or decryption through this package. It is a policy
// value, not a protocol constant.
var MaxStreamBytes int64 = 512 << 20

// Sentinel errors for the streaming entry points
// (docs/architecture/technical-specification.md §8.1). Callers match with
// errors.Is; every returned error wraps one of these with %w, or the
// buffered-path sentinel it originates from.
var (
	// ErrInvalidStream is returned when a stream cannot start: a nil
	// writer or reader, or a negative size.
	ErrInvalidStream = errors.New("media: invalid stream")

	// ErrStreamLimit is returned, wrapped by *StreamLimitError, when a
	// payload exceeds MaxStreamBytes. It is a sentinel so callers can
	// branch with errors.Is; errors.As recovers the sizes.
	ErrStreamLimit = errors.New("media: stream limit exceeded")
)

// StreamLimitError reports a payload that crossed MaxStreamBytes. Observed is
// the byte count that tripped the limit: for encryption it is the number of
// plaintext bytes read so far (a lower bound on the real payload, because a
// stream cannot know the length up front); for decryption it is the
// ciphertext body from the caller-supplied size when that body alone already
// proves the limit was crossed, otherwise the exact plaintext length once the
// padding has been validated.
type StreamLimitError struct {
	// Limit is the MaxStreamBytes value in force.
	Limit int64
	// Observed is the byte count that exceeded Limit.
	Observed int64
}

// Error implements error.
func (e *StreamLimitError) Error() string {
	return fmt.Sprintf("%s: %d bytes exceeds %d", ErrStreamLimit, e.Observed, e.Limit)
}

// Unwrap makes errors.Is(err, ErrStreamLimit) report true.
func (e *StreamLimitError) Unwrap() error { return ErrStreamLimit }

// EncryptStream encrypts every byte readable from src into dst in the
// envelope's wire format (PF-042, PF-043, PF-046):
//
//	dst = AES-256-CBC(pad(plaintext)) ‖ HMAC-SHA256(keys.MACKey, keys.IV ‖ ciphertext)[:10]
//
// The plaintext is read in chunks, only the trailing partial block is held
// back, and the MAC is fed each encrypted chunk as it is written, so the
// working set is a fixed chunk plus one block regardless of payload size.
// Padding is always added, exactly like Encrypt: an empty source produces one
// 0x10 block.
//
// ciphertextLen is the total number of bytes written to dst, i.e. the
// ciphertext length plus MACSize. On error it is a lower bound: whatever
// prefix reached dst before the failure. A failed call never writes the MAC,
// so a partial output is not a valid blob and DecryptStream or Decrypt will
// reject it.
//
// A plaintext above MaxStreamBytes returns a *StreamLimitError. A read error
// from src, a write error from dst, or a source that keeps returning no
// progress (io.ErrNoProgress, after the same tolerance as io.Copy) is
// returned wrapped; the stream stops at that point. Nothing is buffered for a
// retry, so callers that retry must truncate or replace dst.
func EncryptStream(dst io.Writer, src io.Reader, keys Keys) (ciphertextLen int64, err error) {
	if dst == nil {
		return 0, fmt.Errorf("%w: nil destination writer", ErrInvalidStream)
	}
	if src == nil {
		return 0, fmt.Errorf("%w: nil source reader", ErrInvalidStream)
	}
	block, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	encrypter := cipher.NewCBCEncrypter(block, keys.IV[:])
	tag := newStreamMAC(keys)

	// chunk sizes the reads; pending carries the less-than-a-block tail
	// between reads; sealed holds the encrypted blocks of one chunk.
	chunk := make([]byte, streamChunkSize)
	pending := make([]byte, 0, streamChunkSize+cbc.BlockSize)
	sealed := make([]byte, 0, streamChunkSize+cbc.BlockSize)
	var total int64
	noProgress := 0

	for {
		n, readErr := src.Read(chunk)
		if n > 0 {
			noProgress = 0
			total += int64(n)
			if limit := MaxStreamBytes; limit > 0 && total > limit {
				return ciphertextLen, &StreamLimitError{Limit: limit, Observed: total}
			}
			pending = append(pending, chunk[:n]...)

			if full := len(pending) - len(pending)%cbc.BlockSize; full > 0 {
				sealed = sealed[:full]
				encrypter.CryptBlocks(sealed, pending[:full])
				tag.Write(sealed)
				if err := writeFull(dst, sealed); err != nil {
					return ciphertextLen, err
				}
				ciphertextLen += int64(full)
				pending = append(pending[:0], pending[full:]...)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return ciphertextLen, fmt.Errorf("media: stream read: %w", readErr)
		}
		// A reader that keeps returning (0, nil) would spin forever;
		// io.Copy gives up on the same condition with ErrNoProgress.
		if n == 0 {
			noProgress++
			if noProgress >= maxEmptyReads {
				return ciphertextLen, fmt.Errorf("media: stream read: %w", io.ErrNoProgress)
			}
		}
	}

	// Always pad: the tail is 0..15 bytes, so padLen is 1..16 and a
	// payload that ended on a block boundary gains a whole 0x10 block.
	last := make([]byte, cbc.BlockSize)
	padding := cbc.BlockSize - len(pending)
	copy(last, pending)
	for i := len(pending); i < len(last); i++ {
		last[i] = byte(padding)
	}
	encrypter.CryptBlocks(last, last)
	tag.Write(last)
	if err := writeFull(dst, last); err != nil {
		return ciphertextLen, err
	}
	ciphertextLen += int64(cbc.BlockSize)

	if err := writeFull(dst, tag.Sum(nil)[:MACSize]); err != nil {
		return ciphertextLen, err
	}
	ciphertextLen += int64(MACSize)
	return ciphertextLen, nil
}

// DecryptStream verifies and decrypts one envelope blob of size bytes
// readable through src at offsets [0, size) and writes the plaintext to dst
// (PF-043, PF-044, PF-046).
//
// The MAC covers the whole ciphertext, so it cannot be checked while
// decrypting forward. DecryptStream therefore requires an io.ReaderAt plus
// the blob size and re-reads the source instead of buffering it:
//
//  1. hash [0, size-MACSize) into HMAC-SHA256(macKey, iv ‖ ciphertext) and
//     compare the trailing MACSize bytes in constant time;
//  2. decrypt the last ciphertext block on its own to validate PKCS#7
//     padding;
//  3. only then decrypt the body chunk by chunk to dst, truncating the
//     padding.
//
// A byte of plaintext is written only after the blob has proven authentic
// (step 1) and canonically padded (step 2), so a tampered or malformed blob
// leaves dst untouched. A nil dst, nil src or negative size returns
// ErrInvalidStream; a blob shorter than one padded block plus the MAC, a
// body that is not a positive multiple of the AES block size, or non-canonical
// padding returns ErrInvalidCiphertext; a MAC mismatch returns ErrBadMAC; a
// plaintext above MaxStreamBytes returns a *StreamLimitError. A source shorter
// than size surfaces the wrapped io.ErrUnexpectedEOF.
func DecryptStream(dst io.Writer, src io.ReaderAt, size int64, keys Keys) error {
	if dst == nil {
		return fmt.Errorf("%w: nil destination writer", ErrInvalidStream)
	}
	if src == nil {
		return fmt.Errorf("%w: nil source reader", ErrInvalidStream)
	}
	if size < 0 {
		return fmt.Errorf("%w: negative size %d", ErrInvalidStream, size)
	}
	if size < int64(MACSize+cbc.BlockSize) {
		return fmt.Errorf("%w: %d bytes, need at least %d", ErrInvalidCiphertext, size, MACSize+cbc.BlockSize)
	}
	body := size - int64(MACSize)
	if body%cbc.BlockSize != 0 {
		return fmt.Errorf("%w: ciphertext length %d is not a multiple of %d", ErrInvalidCiphertext, body, cbc.BlockSize)
	}
	// A body of n bytes decrypts to between n-16 and n-1 plaintext bytes,
	// so this rejects only sizes no permitted plaintext could produce; the
	// exact check follows the padding validation below.
	limit := MaxStreamBytes
	if limit > 0 && body > limit+int64(cbc.BlockSize) {
		return &StreamLimitError{Limit: limit, Observed: body}
	}

	block, err := aes.NewCipher(keys.CipherKey[:])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	// Pass 1: authenticate before anything is decrypted.
	tag := newStreamMAC(keys)
	if err := hashRange(tag, src, 0, body); err != nil {
		return err
	}
	stored := make([]byte, MACSize)
	if err := readAtFull(src, stored, body); err != nil {
		return err
	}
	if !hmac.Equal(tag.Sum(nil)[:MACSize], stored) {
		return ErrBadMAC
	}

	// Pass 2: the padding length lives in the last block, which CBC can
	// only decrypt with its predecessor (or the IV for a single block).
	// Checking it here keeps the fail-closed guarantee on dst.
	padding, err := streamPaddingLen(src, block, body, keys)
	if err != nil {
		return err
	}
	if plaintextLen := body - int64(padding); limit > 0 && plaintextLen > limit {
		return &StreamLimitError{Limit: limit, Observed: plaintextLen}
	}

	// Pass 3: decrypt and emit every byte except the padding.
	decrypter := cipher.NewCBCDecrypter(block, keys.IV[:])
	buf := make([]byte, streamChunkSize)
	out := make([]byte, streamChunkSize)
	remaining := body - int64(padding)
	for off := int64(0); off < body; off += int64(streamChunkSize) {
		n := min(int64(streamChunkSize), body-off)
		if err := readAtFull(src, buf[:n], off); err != nil {
			return err
		}
		decrypter.CryptBlocks(out[:n], buf[:n])
		if want := min(n, remaining); want > 0 {
			if err := writeFull(dst, out[:want]); err != nil {
				return err
			}
			remaining -= want
		}
	}
	return nil
}

// SidecarHash returns SHA-256 over the plaintext payload read from src in
// fixed-size chunks, i.e. the media object's fileSHA256 companion value
// (PF-045, PF-047). It is the digest the sender records beside the message
// and the video streaming sidecar, and the value a receiver recomputes over
// the decrypted plaintext to confirm it reassembled the same bytes.
//
// The digest is corroboration, not authentication: an attacker who changes
// the ciphertext can recompute the hash over the changed bytes. Trust
// decisions belong to the envelope MAC (PF-043), and a comparison against a
// remembered digest should use crypto/subtle. SidecarHash does not enforce
// MaxStreamBytes; it performs no cryptography beyond the digest, so callers
// that need a size policy apply it to the source themselves.
func SidecarHash(src io.Reader) ([32]byte, error) {
	var sum [32]byte
	if src == nil {
		return sum, fmt.Errorf("%w: nil source reader", ErrInvalidStream)
	}
	h := sha256.New()
	if _, err := io.CopyBuffer(h, src, make([]byte, streamChunkSize)); err != nil {
		return sum, fmt.Errorf("media: sidecar hash: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// newStreamMAC starts the envelope HMAC and writes the IV, so chunks can be
// appended as they are encrypted. The IV is authenticated even though it is
// not transmitted (PF-043).
func newStreamMAC(keys Keys) hash.Hash {
	h := hmac.New(sha256.New, keys.MACKey[:])
	h.Write(keys.IV[:])
	return h
}

// streamPaddingLen decrypts the final ciphertext block and returns its PKCS#7
// padding length, validating every padding byte (PF-042, PF-044). Each CBC
// block needs only its predecessor, so one extra block is read at most.
func streamPaddingLen(src io.ReaderAt, block cipher.Block, body int64, keys Keys) (int, error) {
	prev := keys.IV[:]
	if body > int64(cbc.BlockSize) {
		p := make([]byte, cbc.BlockSize)
		if err := readAtFull(src, p, body-int64(2*cbc.BlockSize)); err != nil {
			return 0, err
		}
		prev = p
	}
	last := make([]byte, cbc.BlockSize)
	if err := readAtFull(src, last, body-int64(cbc.BlockSize)); err != nil {
		return 0, err
	}
	plain := make([]byte, cbc.BlockSize)
	cipher.NewCBCDecrypter(block, prev).CryptBlocks(plain, last)
	padding := int(plain[cbc.BlockSize-1])
	if padding == 0 || padding > cbc.BlockSize {
		return 0, fmt.Errorf("%w: padding %d", ErrInvalidCiphertext, padding)
	}
	for _, b := range plain[cbc.BlockSize-padding:] {
		if int(b) != padding {
			return 0, fmt.Errorf("%w: inconsistent padding", ErrInvalidCiphertext)
		}
	}
	return padding, nil
}

// hashRange feeds n bytes starting at off from r into h.
func hashRange(h hash.Hash, r io.ReaderAt, off, n int64) error {
	buf := make([]byte, streamChunkSize)
	for n > 0 {
		c := min(int64(len(buf)), n)
		if err := readAtFull(r, buf[:c], off); err != nil {
			return err
		}
		h.Write(buf[:c])
		off += c
		n -= c
	}
	return nil
}

// readAtFull fills p from r at off. io.ReaderAt promises a non-nil error when
// it returns short, but implementations that return short reads with a nil
// error are handled instead of trusted, and a premature EOF is reported as
// io.ErrUnexpectedEOF rather than as a plain EOF.
func readAtFull(r io.ReaderAt, p []byte, off int64) error {
	start := off
	for len(p) > 0 {
		n, err := r.ReadAt(p, off)
		if n > 0 {
			p = p[n:]
			off += int64(n)
		}
		if err != nil {
			if len(p) == 0 && errors.Is(err, io.EOF) {
				return nil
			}
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return fmt.Errorf("media: stream read at offset %d: %w", start, err)
		}
		if n == 0 {
			return fmt.Errorf("media: stream read at offset %d: %w", start, io.ErrUnexpectedEOF)
		}
	}
	return nil
}

// writeFull writes all of p, so a short write from dst surfaces as
// io.ErrShortWrite instead of silently truncating the envelope.
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return fmt.Errorf("media: stream write: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("media: stream write: %w", io.ErrShortWrite)
		}
	}
	return nil
}
