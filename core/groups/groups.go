// Package groups caches WhatsApp group metadata and participant lists.
//
// The cache is storage-free and dependency-free (technical specification
// §4.16): it holds what the caller learned from group stanzas, detects which
// participants a metadata update added or removed, and hands sender-key work
// to protocol/signal at the caller's layer. Persistence and event publication
// stay outside this package.
//
// A Cache is safe for concurrent use. Every value handed out is a copy, so a
// caller can neither observe partial updates nor mutate cached state.
package groups

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrInvalidGroup is returned for metadata that cannot be cached.
var ErrInvalidGroup = errors.New("core/groups: invalid group")

// Group is one cached group. Participants are unique JIDs in ascending order;
// the cache normalizes them on every write, so a Group read back from a Cache
// always satisfies that invariant.
type Group struct {
	ID           string
	Subject      string
	Participants []string
	UpdatedAt    time.Time
}

// Cache is a concurrency-safe group store keyed by group ID. The zero value is
// not usable; call New.
type Cache struct {
	mu    sync.RWMutex
	items map[string]Group
}

// New returns an empty Cache.
func New() *Cache {
	return &Cache{items: make(map[string]Group)}
}

// Upsert stores g after normalizing its participants.
//
// An empty or blank ID or a blank participant JID is rejected with
// ErrInvalidGroup and leaves the cache untouched. Duplicate participants are
// collapsed and the list is sorted, keeping List and change detection
// deterministic.
func (c *Cache) Upsert(group Group) error {
	if strings.TrimSpace(group.ID) == "" {
		return fmt.Errorf("%w: empty id", ErrInvalidGroup)
	}
	participants, err := normalizeParticipants(group.Participants)
	if err != nil {
		return err
	}

	group.Participants = participants

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[group.ID] = group
	return nil
}

// Get returns the cached group for id. The second result is false when the ID
// is unknown. The returned participants slice is a copy.
func (c *Cache) Get(id string) (Group, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	group, ok := c.items[id]
	if !ok {
		return Group{}, false
	}
	return copyGroup(group), true
}

// Delete removes id from the cache. Deleting an unknown ID is a no-op.
func (c *Cache) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, id)
}

// List returns every cached group sorted by ID. The result and the participant
// slices in it are copies.
func (c *Cache) List() []Group {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Group, 0, len(c.items))
	for _, group := range c.items {
		out = append(out, copyGroup(group))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Len reports how many groups are cached.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.items)
}

// DiffParticipants returns the participants added and removed between two
// participant lists. Blank entries are ignored, so raw stanza data can be
// passed in; both results are sorted and deduped.
func DiffParticipants(before, after []string) (added, removed []string) {
	return applyParticipantChange(before, after)
}

// applyParticipantChange returns the participants present in after but not
// before, and those present in before but not after. Both results are sorted
// and contain no duplicates, so callers can compare them directly.
//
// Blank JIDs are ignored rather than reported as changes.
func applyParticipantChange(before, after []string) (added, removed []string) {
	beforeSet := participantSet(before)
	afterSet := participantSet(after)

	for jid := range afterSet {
		if _, ok := beforeSet[jid]; !ok {
			added = append(added, jid)
		}
	}
	for jid := range beforeSet {
		if _, ok := afterSet[jid]; !ok {
			removed = append(removed, jid)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// participantSet collects non-blank JIDs, discarding duplicates.
func participantSet(participants []string) map[string]struct{} {
	set := make(map[string]struct{}, len(participants))
	for _, jid := range participants {
		if strings.TrimSpace(jid) == "" {
			continue
		}
		set[jid] = struct{}{}
	}
	return set
}

// normalizeParticipants validates, dedupes, and sorts participants. The result
// is always a non-nil copy, so callers never share a backing array with the
// cache.
func normalizeParticipants(participants []string) ([]string, error) {
	set := make(map[string]struct{}, len(participants))
	for _, jid := range participants {
		if strings.TrimSpace(jid) == "" {
			return nil, fmt.Errorf("%w: empty participant jid", ErrInvalidGroup)
		}
		set[jid] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for jid := range set {
		out = append(out, jid)
	}
	sort.Strings(out)
	return out, nil
}

// copyGroup returns g with its participant slice copied. A stored empty list
// stays empty rather than nil, so a caller sees the same shape it wrote.
func copyGroup(group Group) Group {
	participants := make([]string, len(group.Participants))
	copy(participants, group.Participants)
	group.Participants = participants
	return group
}
