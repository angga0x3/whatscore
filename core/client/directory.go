package client

import (
	"context"
	"fmt"

	"github.com/angga0x3/whatscore/core/contacts"
	"github.com/angga0x3/whatscore/core/events"
	"github.com/angga0x3/whatscore/core/groups"
)

// Contacts returns the contact cache, creating it on first use. The SDK keeps
// caches lazy so a client that never reads contacts pays nothing.
func (c *Client) Contacts() *contacts.Cache {
	c.directoryOnce.Do(func() {
		if c.directory.contacts == nil {
			c.directory.contacts = contacts.New()
		}
	})
	return c.directory.contacts
}

// Groups returns the group cache, creating it on first use.
func (c *Client) Groups() *groups.Cache {
	c.directoryOnce.Do(func() {
		if c.directory.groups == nil {
			c.directory.groups = groups.New()
		}
	})
	return c.directory.groups
}

// UpsertContact stores a contact profile and publishes a message-free update
// event when the cache reports a real change. Duplicate pushes are silent,
// which is why the cache distinguishes "new or edited" from "seen again".
func (c *Client) UpsertContact(contact contacts.Contact) (bool, error) {
	changed, err := c.Contacts().Upsert(contact)
	if err != nil {
		return false, fmt.Errorf("client: upsert contact: %w", err)
	}
	if changed {
		c.bus.Publish(events.Event{
			Type:      events.TypeGroupUpdate,
			SessionID: c.id,
			GroupUpdate: &events.GroupUpdate{
				GroupID: contact.JID,
				Change:  events.GroupMetadataChanged,
			},
		})
	}
	return changed, nil
}

// UpsertGroup stores group metadata and publishes one event describing the
// participant delta, or a metadata change when only the subject changed.
func (c *Client) UpsertGroup(ctx context.Context, group groups.Group) error {
	before, existed := c.Groups().Get(group.ID)
	if err := c.Groups().Upsert(group); err != nil {
		return fmt.Errorf("client: upsert group: %w", err)
	}
	if !existed {
		c.publishGroup(ctx, group.ID, events.GroupJoined)
		return nil
	}
	added, removed := groups.DiffParticipants(before.Participants, group.Participants)
	switch {
	case len(added) > 0:
		c.publishGroup(ctx, group.ID, events.GroupParticipantsAdded)
	case len(removed) > 0:
		c.publishGroup(ctx, group.ID, events.GroupParticipantsRemoved)
	case before.Subject != group.Subject:
		c.publishGroup(ctx, group.ID, events.GroupMetadataChanged)
	}
	return nil
}

func (c *Client) publishGroup(_ context.Context, groupID string, change events.GroupChange) {
	c.bus.Publish(events.Event{
		Type:        events.TypeGroupUpdate,
		SessionID:   c.id,
		GroupUpdate: &events.GroupUpdate{GroupID: groupID, Change: change},
	})
}

// ListContacts returns contacts sorted by JID.
func (c *Client) ListContacts() []contacts.Contact { return c.Contacts().List() }

// ListGroups returns groups sorted by ID.
func (c *Client) ListGroups() []groups.Group { return c.Groups().List() }
