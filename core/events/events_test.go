package events

import (
	"sync"
	"testing"
	"time"
)

// recv reads one event or fails the test if the subscription closes first.
func recv(t *testing.T, sub *Subscription) Event {
	t.Helper()

	select {
	case ev, ok := <-sub.C:
		if !ok {
			t.Fatal("subscription closed before an event arrived")
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for an event")
		return Event{}
	}
}

func TestPublishOrderingAndSequence(t *testing.T) {
	bus := NewBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	const count = 8
	for i := 0; i < count; i++ {
		bus.Publish(Event{
			Type:      TypeMessage,
			SessionID: "session-a",
			Message:   &Message{ID: string(rune('a' + i))},
		})
	}

	for i := 0; i < count; i++ {
		ev := recv(t, sub)
		if ev.Type != TypeMessage {
			t.Fatalf("event %d type = %q, want %q", i, ev.Type, TypeMessage)
		}
		if ev.SessionID != "session-a" {
			t.Fatalf("event %d session = %q, want session-a", i, ev.SessionID)
		}
		if want := uint64(i + 1); ev.Seq != want {
			t.Fatalf("event %d Seq = %d, want %d", i, ev.Seq, want)
		}
		if got, want := ev.Message.ID, string(rune('a'+i)); got != want {
			t.Fatalf("event %d payload ID = %q, want %q", i, got, want)
		}
		if ev.Timestamp.IsZero() {
			t.Fatalf("event %d timestamp was not stamped", i)
		}
	}
}

func TestMultipleSubscribersReceiveEveryEvent(t *testing.T) {
	bus := NewBus()
	defer bus.Close()

	first := bus.Subscribe()
	defer first.Close()
	second := bus.Subscribe()
	defer second.Close()

	want := Event{Type: TypeConnected, SessionID: "session-a", Connected: &Connected{}}
	bus.Publish(want)

	for name, sub := range map[string]*Subscription{"first": first, "second": second} {
		ev := recv(t, sub)
		if ev.Type != want.Type || ev.SessionID != want.SessionID {
			t.Fatalf("%s subscriber got %+v, want type %q session %q", name, ev, want.Type, want.SessionID)
		}
		if ev.Seq != 1 {
			t.Fatalf("%s subscriber Seq = %d, want 1", name, ev.Seq)
		}
		if ev.Connected == nil || ev.Connected.Reconnected != want.Connected.Reconnected {
			t.Fatalf("%s subscriber payload = %+v, want connected payload", name, ev.Connected)
		}
	}
}

func TestSlowSubscriberDropsWithoutBlockingOthers(t *testing.T) {
	bus := NewBus(WithBuffer(1))
	defer bus.Close()

	slow := bus.Subscribe()
	defer slow.Close()
	fast := bus.Subscribe()
	defer fast.Close()

	bus.Publish(Event{Type: TypeMessage, Message: &Message{ID: "one"}})
	if got := recv(t, slow).Message.ID; got != "one" {
		t.Fatalf("slow subscriber first event = %q, want one", got)
	}
	if got := recv(t, fast).Message.ID; got != "one" {
		t.Fatalf("fast subscriber first event = %q, want one", got)
	}

	// slow is now full (it is not reading), fast is drained.
	bus.Publish(Event{Type: TypeMessage, Message: &Message{ID: "two"}})
	if got := recv(t, fast).Message.ID; got != "two" {
		t.Fatalf("fast subscriber second event = %q, want two", got)
	}
	bus.Publish(Event{Type: TypeMessage, Message: &Message{ID: "three"}})
	if got := recv(t, fast).Message.ID; got != "three" {
		t.Fatalf("fast subscriber third event = %q, want three", got)
	}
	bus.Publish(Event{Type: TypeMessage, Message: &Message{ID: "four"}})
	if got := recv(t, fast).Message.ID; got != "four" {
		t.Fatalf("fast subscriber fourth event = %q, want four", got)
	}

	if got, want := slow.Dropped(), uint64(2); got != want {
		t.Fatalf("slow subscriber dropped = %d, want %d", got, want)
	}
	if got := fast.Dropped(); got != 0 {
		t.Fatalf("fast subscriber dropped = %d, want 0", got)
	}

	// The slow subscriber only ever saw the two events that fit its buffer.
	if got := recv(t, slow).Message.ID; got != "two" {
		t.Fatalf("slow subscriber buffered event = %q, want two", got)
	}
	select {
	case ev := <-slow.C:
		t.Fatalf("slow subscriber got extra event %q", ev.Message.ID)
	default:
	}
}

func TestUnsubscribeStopsDeliveryAndClosesChannel(t *testing.T) {
	bus := NewBus()
	defer bus.Close()

	sub := bus.Subscribe()
	other := bus.Subscribe()
	defer other.Close()

	bus.Publish(Event{Type: TypeConnected, Connected: &Connected{}})
	if got := recv(t, sub).Type; got != TypeConnected {
		t.Fatalf("type = %q, want %q", got, TypeConnected)
	}
	if got := recv(t, other).Type; got != TypeConnected {
		t.Fatalf("other subscriber type = %q, want %q", got, TypeConnected)
	}

	sub.Close()
	sub.Close() // idempotent

	bus.Publish(Event{Type: TypeDisconnected, Disconnected: &Disconnected{}})

	if got := recv(t, other).Type; got != TypeDisconnected {
		t.Fatalf("other subscriber type = %q, want %q", got, TypeDisconnected)
	}

	select {
	case ev, ok := <-sub.C:
		if ok {
			t.Fatalf("unsubscribed channel delivered %+v", ev)
		}
	default:
		t.Fatal("unsubscribed channel was not closed")
	}
}

func TestCloseSemantics(t *testing.T) {
	bus := NewBus()
	sub := bus.Subscribe()

	bus.Publish(Event{Type: TypeConnected, Connected: &Connected{}})
	bus.Close()
	bus.Close() // idempotent

	// Buffered events are still drainable after Close.
	ev, ok := <-sub.C
	if !ok {
		t.Fatal("buffered event lost on Close")
	}
	if ev.Type != TypeConnected {
		t.Fatalf("type = %q, want %q", ev.Type, TypeConnected)
	}
	if _, ok := <-sub.C; ok {
		t.Fatal("subscription channel still open after Close")
	}

	// Further operations are harmless.
	bus.Publish(Event{Type: TypeError, Error: &SessionError{}})
	sub.Close()
	bus.Unsubscribe(sub)

	late := bus.Subscribe()
	defer late.Close()
	if _, ok := <-late.C; ok {
		t.Fatal("Subscribe after Close returned an open channel")
	}
}

func TestEventsAreDeliveredPerSessionInPublishOrder(t *testing.T) {
	bus := NewBus()
	defer bus.Close()

	sub := bus.Subscribe()
	defer sub.Close()

	// One publisher (the shape of an actor) interleaves two sessions; each
	// session's own events must stay in order.
	bus.Publish(Event{Type: TypeMessage, SessionID: "a", Message: &Message{ID: "a1"}})
	bus.Publish(Event{Type: TypeMessage, SessionID: "b", Message: &Message{ID: "b1"}})
	bus.Publish(Event{Type: TypeMessage, SessionID: "a", Message: &Message{ID: "a2"}})
	bus.Publish(Event{Type: TypeMessage, SessionID: "b", Message: &Message{ID: "b2"}})

	want := []struct {
		session string
		id      string
	}{
		{"a", "a1"},
		{"b", "b1"},
		{"a", "a2"},
		{"b", "b2"},
	}
	for i, w := range want {
		ev := recv(t, sub)
		if ev.SessionID != w.session || ev.Message.ID != w.id {
			t.Fatalf("event %d = (%q,%q), want (%q,%q)", i, ev.SessionID, ev.Message.ID, w.session, w.id)
		}
	}
}

func TestConcurrentPublishUnsubscribeClose(_ *testing.T) {
	bus := NewBus(WithBuffer(2))

	const (
		publishers = 4
		perWriter  = 50
		subs       = 4
	)

	subscriptions := make([]*Subscription, subs)
	for i := range subscriptions {
		subscriptions[i] = bus.Subscribe()
	}

	var readers sync.WaitGroup
	readers.Add(subs)
	for _, sub := range subscriptions {
		go func(sub *Subscription) {
			defer readers.Done()
			for range sub.C {
				// Drain so publishers are not blocked by a full buffer.
			}
		}(sub)
	}

	var writers sync.WaitGroup
	writers.Add(publishers)
	for i := 0; i < publishers; i++ {
		go func() {
			defer writers.Done()
			for j := 0; j < perWriter; j++ {
				bus.Publish(Event{Type: TypeMessage, Message: &Message{ID: "x"}})
			}
		}()
	}

	// Unsubscribe half the subscribers while publishing; the rest are closed
	// by Bus.Close.
	for i := 0; i < subs/2; i++ {
		bus.Unsubscribe(subscriptions[i])
	}

	writers.Wait()
	bus.Close()
	readers.Wait()

	for _, sub := range subscriptions {
		sub.Close()
	}
}
