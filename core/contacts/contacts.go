// Package contacts caches WhatsApp contact profiles keyed by JID.
//
// The cache is deliberately storage-free and dependency-free (technical
// specification §4.15): callers feed it profiles observed on the wire and read
// them back by JID. Persistence, fetch orchestration, and event publication
// stay with the caller, so the cache is usable from the session actor, the SDK
// facade, and tests without a store.
//
// A Cache is safe for concurrent use. Reads never block each other; writers
// serialize on a single mutex.
package contacts

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrInvalidContact is returned for contacts that cannot be cached.
var ErrInvalidContact = errors.New("core/contacts: invalid contact")

// Contact is one cached profile. JID is the chat address as rendered by
// protocol/messaging (for example "628123@s.whatsapp.net"); the cache treats
// it as an opaque key and never reparses it.
type Contact struct {
	JID       string
	Name      string
	PushName  string
	UpdatedAt time.Time
}

// Cache is a concurrency-safe contact store keyed by JID. The zero value is
// not usable; call New.
type Cache struct {
	mu    sync.RWMutex
	items map[string]Contact
}

// New returns an empty Cache.
func New() *Cache {
	return &Cache{items: make(map[string]Contact)}
}

// Upsert stores c and reports whether the cache changed.
//
// A contact counts as changed when its JID is new or its Name or PushName
// differs from the cached value. A newer UpdatedAt alone is not a change: the
// timestamp is refreshed on every write, so counting it would report change on
// every duplicate push.
//
// An empty or blank JID is rejected with ErrInvalidContact and leaves the
// cache untouched.
func (c *Cache) Upsert(contact Contact) (bool, error) {
	if strings.TrimSpace(contact.JID) == "" {
		return false, fmt.Errorf("%w: empty jid", ErrInvalidContact)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	prev, ok := c.items[contact.JID]
	c.items[contact.JID] = contact
	changed := !ok || prev.Name != contact.Name || prev.PushName != contact.PushName
	return changed, nil
}

// Get returns the cached contact for jid. The second result is false when the
// JID is unknown.
func (c *Cache) Get(jid string) (Contact, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	contact, ok := c.items[jid]
	return contact, ok
}

// Delete removes jid from the cache. Deleting an unknown JID is a no-op.
func (c *Cache) Delete(jid string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, jid)
}

// List returns every cached contact sorted by JID. The result is a fresh
// slice; the caller owns it.
func (c *Cache) List() []Contact {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Contact, 0, len(c.items))
	for _, contact := range c.items {
		out = append(out, contact)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JID < out[j].JID })
	return out
}

// Len reports how many contacts are cached.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.items)
}
