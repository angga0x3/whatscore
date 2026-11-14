package noise

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"github.com/angga0x3/whatscore/protocol/transport"
)

// testKey derives a deterministic synthetic 32-byte AES key for transport
// tests (never a real credential).
func testKey(label string) [32]byte {
	return sha256.Sum256([]byte("whatscore-test-key:" + label))
}

// TestSecureConnFrameOrderAndCounters exchanges sequential frames in both
// directions over an in-memory pair and asserts ordering, counter
// progression, and nonce uniqueness (PF-008).
func TestSecureConnFrameOrderAndCounters(t *testing.T) {
	ctx := context.Background()
	a, b := newPipePair()

	writeKey, readKey := testKey("write"), testKey("read")
	clientConn, err := newSecureConn(a, writeKey, readKey)
	if err != nil {
		t.Fatalf("client secureConn: %v", err)
	}
	serverConn, err := newSecureConn(b, readKey, writeKey) // swapped per PF-008
	if err != nil {
		t.Fatalf("server secureConn: %v", err)
	}
	if got := clientConn.CipherSuiteName(); got != CipherSuite {
		t.Fatalf("CipherSuiteName = %q, want %q", got, CipherSuite)
	}

	first := []byte("frame-one")
	second := []byte("frame-two")
	if err := clientConn.WriteFrame(ctx, first); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := clientConn.WriteFrame(ctx, second); err != nil {
		t.Fatalf("write 2: %v", err)
	}

	got1, err := serverConn.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("read 1: %v", err)
	}
	got2, err := serverConn.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if !bytes.Equal(got1, first) || !bytes.Equal(got2, second) {
		t.Fatalf("frames out of order: %q then %q", got1, got2)
	}
	if clientConn.writeCounter != 2 {
		t.Fatalf("write counter = %d, want 2", clientConn.writeCounter)
	}
	if serverConn.readCounter != 2 {
		t.Fatalf("read counter = %d, want 2", serverConn.readCounter)
	}

	// Nonce uniqueness is implied by the counter progression: the two
	// ciphertexts of distinct plaintexts at distinct counters must differ.
	if bytes.Equal(got1, got2) {
		t.Fatal("distinct plaintexts at distinct counters must yield distinct ciphertexts")
	}

	// Reverse direction uses the server's write counter from 0 (PF-008).
	reply := []byte("server reply")
	if err := serverConn.WriteFrame(ctx, reply); err != nil {
		t.Fatalf("server write: %v", err)
	}
	gotReply, err := clientConn.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(gotReply, reply) {
		t.Fatalf("reply mismatch: %q", gotReply)
	}
	if serverConn.writeCounter != 1 || clientConn.readCounter != 1 {
		t.Fatalf("reverse counters wrong: server w=%d client r=%d", serverConn.writeCounter, clientConn.readCounter)
	}
}

// TestSecureConnConcurrentWrites exercises the write mutex: two goroutines
// writing simultaneously must still produce independently decryptable
// frames (run under -race).
func TestSecureConnConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	a, b := newPipePair()

	writeKey, readKey := testKey("write"), testKey("read")
	w, err := newSecureConn(a, writeKey, readKey)
	if err != nil {
		t.Fatalf("writer secureConn: %v", err)
	}
	r, err := newSecureConn(b, readKey, writeKey)
	if err != nil {
		t.Fatalf("reader secureConn: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < n; j++ {
				if err := w.WriteFrame(ctx, []byte{byte(id), byte(j)}); err != nil {
					t.Errorf("concurrent write: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	seen := make(map[[2]byte]bool)
	for k := 0; k < 2*n; k++ {
		frame, err := r.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read %d: %v", k, err)
		}
		if len(frame) != 2 {
			t.Fatalf("frame %d corrupted by concurrent writes: %x", k, frame)
		}
		var key [2]byte
		copy(key[:], frame)
		if seen[key] {
			t.Fatalf("frame %x delivered twice", key)
		}
		seen[key] = true
	}
	if len(seen) != 2*n {
		t.Fatalf("got %d distinct frames, want %d", len(seen), 2*n)
	}
}

// TestSecureConnCloseIdempotent asserts PF-008 connection teardown:
// Close is idempotent and operations after Close report
// transport.ErrClosed.
func TestSecureConnCloseIdempotent(t *testing.T) {
	ctx := context.Background()
	a, _ := newPipePair()

	conn, err := newSecureConn(a, testKey("write"), testKey("read"))
	if err != nil {
		t.Fatalf("secureConn: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}

	if _, err := conn.ReadFrame(ctx); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("ReadFrame after Close: want transport.ErrClosed, got %v", err)
	}
	if err := conn.WriteFrame(ctx, []byte("late")); !errors.Is(err, transport.ErrClosed) {
		t.Fatalf("WriteFrame after Close: want transport.ErrClosed, got %v", err)
	}
}

// TestFrameIVLayout pins the PF-005/PF-008 nonce layout: 12 bytes, bytes
// 0-7 zero, bytes 8-11 the big-endian uint32 counter, with 32-bit
// wraparound semantics at 2^32-1 → 0.
func TestFrameIVLayout(t *testing.T) {
	iv0 := frameIV(0)
	if len(iv0) != 12 {
		t.Fatalf("IV length = %d, want 12", len(iv0))
	}
	if !bytes.Equal(iv0, make([]byte, 12)) {
		t.Fatalf("IV(0) must be all zero, got %x", iv0)
	}

	iv := frameIV(0x01020304)
	want := append(make([]byte, 8), 0x01, 0x02, 0x03, 0x04)
	if !bytes.Equal(iv, want) {
		t.Fatalf("IV(0x01020304) = %x, want %x", iv, want)
	}

	ivMax := frameIV(0xffffffff)
	wantMax := append(make([]byte, 8), 0xff, 0xff, 0xff, 0xff)
	if !bytes.Equal(ivMax, wantMax) {
		t.Fatalf("IV(0xffffffff) = %x, want %x", ivMax, wantMax)
	}

	// Handshake nonce uses the identical layout (PF-005).
	if !bytes.Equal(handshakeIV(0x01020304), iv) {
		t.Fatal("handshakeIV and frameIV must share the same layout")
	}
}
