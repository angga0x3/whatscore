package session

import (
	"errors"
	"testing"
)

func TestWriteFrame(t *testing.T) {
	conn := newFakeConn()
	dialer := &scriptedDialer{outcomes: []dialOutcome{{conn: conn}}}
	s, _ := newFrameHarness(t, dialer, nil, nil)
	ctx := testContext(t)

	if err := s.WriteFrame(ctx, []byte("before")); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("before connect: want ErrNotConnected, got %v", err)
	}
	if err := s.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := s.WriteFrame(ctx, []byte("frame")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case got := <-conn.writes:
		if string(got) != "frame" {
			t.Fatalf("write = %q", got)
		}
	case <-ctx.Done():
		t.Fatal("frame was not written")
	}
	if err := s.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if err := s.WriteFrame(ctx, []byte("after")); err == nil {
		t.Fatal("write after disconnect must fail")
	}
}
