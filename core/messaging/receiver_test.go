package messaging

import (
	"context"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/protocol/binary"
)

func encodeNode(t *testing.T, node *binary.Node) []byte {
	t.Helper()
	frame, err := binary.NewCodec(nil).Encode(node)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return frame
}

func TestReceiverPublishesMessage(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	receiver, err := NewReceiver(bus, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	frame := encodeNode(t, &binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id": "ABC", "type": "text", "from": "628123@s.whatsapp.net", "t": "1700000000",
		},
		Children: []binary.Node{{Tag: "body", Bytes: []byte("hello")}},
	})
	if err := receiver.HandleFrame(context.Background(), frame); err != nil {
		t.Fatalf("HandleFrame: %v", err)
	}

	select {
	case ev := <-sub.C:
		if ev.Type != events.TypeMessage || ev.SessionID != "session-1" || ev.Message == nil {
			t.Fatalf("event = %#v", ev)
		}
		msg := ev.Message
		if msg.ID != "ABC" || msg.Chat != "628123@s.whatsapp.net" || msg.Sender != msg.Chat ||
			msg.Text != "hello" || msg.Direction != events.DirectionIncoming || msg.IsGroup {
			t.Fatalf("message = %#v", msg)
		}
		if !msg.Timestamp.Equal(time.Unix(1700000000, 0).UTC()) {
			t.Fatalf("timestamp = %v", msg.Timestamp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event published")
	}
}

func TestReceiverGroupMessage(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()
	receiver, _ := NewReceiver(bus, "s")

	frame := encodeNode(t, &binary.Node{
		Tag: "message",
		Attrs: binary.Attrs{
			"id": "G1", "type": "text", "from": "123@g.us", "participant": "456@s.whatsapp.net",
		},
		Children: []binary.Node{{Tag: "body", Bytes: []byte("group")}},
	})
	if err := receiver.HandleFrame(context.Background(), frame); err != nil {
		t.Fatal(err)
	}
	ev := <-sub.C
	if !ev.Message.IsGroup || ev.Message.Chat != "123@g.us" || ev.Message.Sender != "456@s.whatsapp.net" {
		t.Fatalf("message = %#v", ev.Message)
	}
	if ev.Message.Timestamp.IsZero() {
		t.Fatal("timestamp was not filled")
	}
}

func TestReceiverIgnoresNonMessagesAndMalformed(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()
	receiver, _ := NewReceiver(bus, "s")

	frames := [][]byte{
		nil,
		{0x00, 0xFF},
		encodeNode(t, &binary.Node{Tag: "iq", Attrs: binary.Attrs{"id": "x"}}),
		encodeNode(t, &binary.Node{Tag: "message", Attrs: binary.Attrs{"id": "x", "type": "image"}}),
	}
	for _, frame := range frames {
		if err := receiver.HandleFrame(context.Background(), frame); err != nil {
			t.Fatalf("HandleFrame(%x): %v", frame, err)
		}
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("unexpected event: %#v", ev)
	default:
	}
}

func TestReceiverValidation(t *testing.T) {
	if _, err := NewReceiver(nil, "s"); err == nil {
		t.Fatal("nil bus must fail")
	}
	bus := events.NewBus()
	defer bus.Close()
	if _, err := NewReceiver(bus, ""); err == nil {
		t.Fatal("empty session id must fail")
	}
	if _, err := NewReceiver(bus, "s", WithReceiverCodec(nil)); err == nil {
		t.Fatal("nil codec must fail")
	}
	if _, err := NewReceiver(bus, "s", WithReceiverLogger(nil)); err == nil {
		t.Fatal("nil logger must fail")
	}
}

func TestReceiverPublishesReceipts(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()
	receiver, _ := NewReceiver(bus, "s")

	node := &binary.Node{Tag: "receipt", Attrs: binary.Attrs{
		"from": "628123@s.whatsapp.net", "id": "M1", "type": "read", "t": "1700000000",
	}}
	if err := receiver.HandleFrame(context.Background(), encodeNode(t, node)); err != nil {
		t.Fatal(err)
	}
	ev := <-sub.C
	if ev.Type != events.TypeReceipt || ev.Receipt == nil {
		t.Fatalf("event = %#v", ev)
	}
	if ev.Receipt.MessageID != "M1" || ev.Receipt.Chat != "628123@s.whatsapp.net" ||
		ev.Receipt.Status != events.ReceiptRead {
		t.Fatalf("receipt = %#v", ev.Receipt)
	}
	if !ev.Receipt.Timestamp.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("timestamp = %v", ev.Receipt.Timestamp)
	}
}

func TestReceiverPublishesBatchedReceipts(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()
	receiver, _ := NewReceiver(bus, "s")

	node := &binary.Node{
		Tag:   "receipt",
		Attrs: binary.Attrs{"from": "1@s.whatsapp.net", "id": "A", "type": "played"},
		Children: []binary.Node{{Tag: "list", Children: []binary.Node{
			{Tag: "item", Attrs: binary.Attrs{"id": "B"}},
		}}},
	}
	if err := receiver.HandleFrame(context.Background(), encodeNode(t, node)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"A", "B"} {
		ev := <-sub.C
		if ev.Receipt == nil || ev.Receipt.MessageID != want || ev.Receipt.Status != events.ReceiptPlayed {
			t.Fatalf("receipt = %#v", ev.Receipt)
		}
	}
}

func TestReceiverDropsUnsupportedReceipt(t *testing.T) {
	bus := events.NewBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()
	receiver, _ := NewReceiver(bus, "s")

	node := &binary.Node{Tag: "receipt", Attrs: binary.Attrs{
		"from": "1@s.whatsapp.net", "id": "M1", "type": "retry",
	}}
	if err := receiver.HandleFrame(context.Background(), encodeNode(t, node)); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("unexpected event: %#v", ev)
	default:
	}
}
