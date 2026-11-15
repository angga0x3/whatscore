package messaging

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
)

type fakeWriter struct {
	frames [][]byte
	err    error
}

func (f *fakeWriter) WriteFrame(_ context.Context, frame []byte) error {
	if f.err != nil {
		return f.err
	}
	f.frames = append(f.frames, append([]byte(nil), frame...))
	return nil
}

func TestSendText(t *testing.T) {
	ctx := context.Background()
	writer := &fakeWriter{}
	sender, err := NewSender(writer)
	if err != nil {
		t.Fatal(err)
	}
	id, err := sender.SendText(ctx, "628123@s.whatsapp.net", "hello")
	if err != nil {
		t.Fatalf("SendText: %v", err)
	}
	if len(id) != 20 {
		t.Fatalf("id = %q", id)
	}
	if len(writer.frames) != 1 {
		t.Fatalf("writes = %d", len(writer.frames))
	}

	codec := binary.NewCodec(nil)
	node, err := codec.Decode(bytes.NewReader(writer.frames[0]))
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	msg, err := stanza.ParseTextMessage(node)
	if err != nil {
		t.Fatalf("parse stanza: %v", err)
	}
	if msg.ID != id || msg.Text != "hello" || msg.To.String() != "628123@s.whatsapp.net" {
		t.Fatalf("message = %#v", msg)
	}
}

func TestSendTextUniqueIDs(t *testing.T) {
	writer := &fakeWriter{}
	sender, _ := NewSender(writer)
	first, err := sender.SendText(context.Background(), "1@s.whatsapp.net", "a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := sender.SendText(context.Background(), "1@s.whatsapp.net", "b")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("duplicate id %q", first)
	}
}

func TestSendTextInvalid(t *testing.T) {
	writer := &fakeWriter{}
	sender, _ := NewSender(writer)
	cases := []string{"", "s.whatsapp.net", "@s.whatsapp.net", "a:b:c@s.whatsapp.net", "has space@s.whatsapp.net"}
	for _, to := range cases {
		if _, err := sender.SendText(context.Background(), to, "x"); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("to %q: want ErrInvalidMessage, got %v", to, err)
		}
	}
	if len(writer.frames) != 0 {
		t.Fatal("invalid message was written")
	}
}

func TestSenderErrors(t *testing.T) {
	if _, err := NewSender(nil); err == nil {
		t.Fatal("nil writer must fail")
	}
	writer := &fakeWriter{}
	if _, err := NewSender(writer, WithCodec(nil)); err == nil {
		t.Fatal("nil codec must fail")
	}
	if _, err := NewSender(writer, WithIDGenerator(nil)); err == nil {
		t.Fatal("nil id generator must fail")
	}
	sentinel := errors.New("write failed")
	sender, err := NewSender(&fakeWriter{err: sentinel})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.SendText(context.Background(), "1@s.whatsapp.net", "x"); !errors.Is(err, sentinel) {
		t.Fatalf("want write error, got %v", err)
	}
	idErr := errors.New("id failed")
	sender, err = NewSender(writer, WithIDGenerator(func() (string, error) { return "", idErr }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.SendText(context.Background(), "1@s.whatsapp.net", "x"); !errors.Is(err, idErr) {
		t.Fatalf("want id error, got %v", err)
	}
	sender, err = NewSender(writer, WithIDGenerator(func() (string, error) { return "", nil }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.SendText(context.Background(), "1@s.whatsapp.net", "x"); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("empty id: %v", err)
	}
}

func TestSendTextCanceled(t *testing.T) {
	sender, _ := NewSender(&fakeWriter{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sender.SendText(ctx, "1@s.whatsapp.net", "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
