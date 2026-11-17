package main

// LID↔PN mapping: WhatsApp modern accounts route messages via LID (a
// server-assigned identifier), not the phone number. Incoming messages carry
// both: from=<lid>@lid and sender_pn=<number>@s.whatsapp.net. Outbound sends
// must use the LID JID when one is known, or the message might not route.
//
// The mapping is derived from incoming messages (the sender_pn attribute)
// and persisted alongside the sessions so it survives restarts. whatsmeow
// keeps the same mapping in its LID store.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// lidMapping stores the LID↔PN pairs observed from live traffic.
type lidMapping struct {
	mu    sync.Mutex
	pairs map[string]string // lidUser → pnUser ("123339465080863" → "62817408010")
	path  string
}

func newLIDMapping(path string) *lidMapping {
	m := &lidMapping{pairs: make(map[string]string), path: path}
	m.load()
	return m
}

// load restores persisted mappings.
func (m *lidMapping) load() {
	if m.path == "" {
		return
	}
	blob, err := os.ReadFile(m.path)
	if err != nil {
		return
	}
	var pairs map[string]string
	if err := json.Unmarshal(blob, &pairs); err != nil {
		return
	}
	m.mu.Lock()
	m.pairs = pairs
	m.mu.Unlock()
}

// save persists the current mappings.
func (m *lidMapping) save() {
	if m.path == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	blob, err := json.MarshalIndent(m.pairs, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(m.path), 0o700)
	os.WriteFile(m.path, blob, 0o600)
}

// record stores a LID→PN pair from an incoming message.
func (m *lidMapping) record(lid, pn string) {
	lidUser := jidUser(lid)
	pnUser := jidUser(pn)
	if lidUser == "" || pnUser == "" {
		return
	}
	m.mu.Lock()
	changed := m.pairs[lidUser] != pnUser
	if changed {
		m.pairs[lidUser] = pnUser
	}
	m.mu.Unlock()
	if changed {
		m.save()
	}
}

// pnForLID returns the phone-number JID for a LID user, or empty if no
// mapping is known.
func (m *lidMapping) pnForLID(lid string) string {
	lidUser := jidUser(lid)
	m.mu.Lock()
	defer m.mu.Unlock()
	if pn, ok := m.pairs[lidUser]; ok {
		return pn + "@s.whatsapp.net"
	}
	return ""
}

// lidForPN returns the LID JID for a phone-number user, or empty if no
// mapping is known.
func (m *lidMapping) lidForPN(pn string) string {
	pnUser := jidUser(pn)
	m.mu.Lock()
	defer m.mu.Unlock()
	for lidUser, mappedPN := range m.pairs {
		if mappedPN == pnUser {
			return lidUser + "@lid"
		}
	}
	return ""
}

// sendAddress returns the JID to use for an outbound send: the LID JID when
// a mapping is known, the PN JID otherwise. WhatsApp modern routing prefers
// LID addressing; sending to the PN JID when the LID is known can produce a
// message that the recipient cannot decrypt (Baileys issue 1701).
func (m *lidMapping) sendAddress(jid string) string {
	// Already LID-addressed — use as-is.
	if strings.Contains(jid, "@lid") {
		return jid
	}
	// Try the mapping.
	if lid := m.lidForPN(jid); lid != "" {
		return lid
	}
	// No mapping: use the PN JID.
	return jid
}
