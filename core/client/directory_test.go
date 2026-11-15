package client

import (
	"context"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/core/contacts"
	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/core/groups"
)

func directoryClient(t *testing.T) (*Client, *events.Bus) {
	t.Helper()
	bus := events.NewBus()
	c, err := New("session-1", WithDialer(&fakeDialer{conn: newFakeConn()}), WithBus(bus))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close(context.Background())
		bus.Close()
	})
	return c, bus
}

func TestContactsLazyAndChangeDetection(t *testing.T) {
	c, bus := directoryClient(t)
	sub := c.Subscribe()
	defer sub.Close()

	contact := contacts.Contact{JID: "628123@s.whatsapp.net", Name: "Ani"}
	changed, err := c.UpsertContact(contact)
	if err != nil || !changed {
		t.Fatalf("first upsert: changed=%v err=%v", changed, err)
	}
	select {
	case ev := <-sub.C:
		if ev.Type != events.TypeGroupUpdate || ev.GroupUpdate == nil || ev.GroupUpdate.GroupID != contact.JID {
			t.Fatalf("event = %#v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event published")
	}

	// A duplicate push with a newer timestamp is not a change and not an event.
	contact.UpdatedAt = time.Now()
	changed, err = c.UpsertContact(contact)
	if err != nil || changed {
		t.Fatalf("duplicate upsert: changed=%v err=%v", changed, err)
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("unexpected event: %#v", ev)
	default:
	}

	if len(c.ListContacts()) != 1 {
		t.Fatalf("contacts = %v", c.ListContacts())
	}
	if _, err := c.UpsertContact(contacts.Contact{}); err == nil {
		t.Fatal("empty JID must fail")
	}
	_ = bus
}

func TestGroupsParticipantEvents(t *testing.T) {
	c, _ := directoryClient(t)
	sub := c.Subscribe()
	defer sub.Close()

	base := groups.Group{ID: "123@g.us", Subject: "Team", Participants: []string{"a@s.whatsapp.net"}}
	if err := c.UpsertGroup(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	ev := <-sub.C
	if ev.GroupUpdate == nil || ev.GroupUpdate.Change != events.GroupJoined {
		t.Fatalf("join event = %#v", ev.GroupUpdate)
	}

	added := base
	added.Participants = []string{"a@s.whatsapp.net", "b@s.whatsapp.net"}
	if err := c.UpsertGroup(context.Background(), added); err != nil {
		t.Fatal(err)
	}
	ev = <-sub.C
	if ev.GroupUpdate.Change != events.GroupParticipantsAdded {
		t.Fatalf("add event = %#v", ev.GroupUpdate)
	}

	removed := added
	removed.Participants = []string{"b@s.whatsapp.net"}
	if err := c.UpsertGroup(context.Background(), removed); err != nil {
		t.Fatal(err)
	}
	ev = <-sub.C
	if ev.GroupUpdate.Change != events.GroupParticipantsRemoved {
		t.Fatalf("remove event = %#v", ev.GroupUpdate)
	}

	renamed := removed
	renamed.Subject = "Team 2"
	if err := c.UpsertGroup(context.Background(), renamed); err != nil {
		t.Fatal(err)
	}
	ev = <-sub.C
	if ev.GroupUpdate.Change != events.GroupMetadataChanged {
		t.Fatalf("metadata event = %#v", ev.GroupUpdate)
	}

	// No change: no event.
	if err := c.UpsertGroup(context.Background(), renamed); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.C:
		t.Fatalf("unexpected event: %#v", ev)
	default:
	}

	if len(c.ListGroups()) != 1 {
		t.Fatalf("groups = %v", c.ListGroups())
	}
}

func TestGroupsValidation(t *testing.T) {
	c, _ := directoryClient(t)
	if err := c.UpsertGroup(context.Background(), groups.Group{}); err == nil {
		t.Fatal("empty group id must fail")
	}
	if err := c.UpsertGroup(context.Background(), groups.Group{ID: "g@g.us", Participants: []string{""}}); err == nil {
		t.Fatal("blank participant must fail")
	}
}

func TestDiffParticipants(t *testing.T) {
	added, removed := groups.DiffParticipants(
		[]string{"a", "b", ""},
		[]string{"b", "c", "c"},
	)
	if len(added) != 1 || added[0] != "c" {
		t.Fatalf("added = %v", added)
	}
	if len(removed) != 1 || removed[0] != "a" {
		t.Fatalf("removed = %v", removed)
	}
}
