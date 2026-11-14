// Package core is the application layer of WhatsCore: it turns protocol
// capabilities (protocol/*) into a developer-facing Go API consumed by the
// Go SDK and the REST server (server/*).
//
// Core principle — one session, one actor: every WhatsApp session is owned
// by a single goroutine (the actor) that serializes all state mutations and
// engine interaction for that account. Callers interact through contexts,
// channels, and the event bus; they never touch session state directly.
// This is what keeps many accounts isolated inside one process.
//
// Sub-packages (client, session, messaging, events, contacts, groups,
// media) land in Phases 4-5; their contracts are defined in
// docs/architecture/technical-specification.md.
//
// Status: reserved (Phase 4-5).
package core
