// Package messaging implements the stanza layer of the WhatsApp Web protocol
// on top of protocol/binary: JID parsing and normalization plus the
// <message> and <receipt> node shapes.
//
// The package knows stanza structure only. It never produces or consumes
// ciphertext; the envelope it builds is the plaintext carrier that a later
// Signal layer replaces with encrypted <enc> children. Wire rules are
// recorded in docs/protocol/messaging.md (PF-030..PF-035) and pinned by the
// tables and round-trip tests in this package.
package messaging

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Known WhatsApp JID servers (PF-030). Group and broadcast addresses are
// ordinary JID pairs on these servers.
const (
	UserServer       = "s.whatsapp.net"
	LegacyUserServer = "c.us"
	GroupServer      = "g.us"
	BroadcastServer  = "broadcast"
	LIDServer        = "lid"
	NewsletterServer = "newsletter"
	HostedServer     = "hosted"
	HostedLIDServer  = "hosted.lid"
)

var (
	// ErrInvalidJID means the input is not a well-formed JID.
	ErrInvalidJID = errors.New("messaging: invalid jid")
	// ErrUnsupportedJIDForm means the input is a reference-accepted form this
	// package does not model yet (agent-qualified AD JIDs).
	ErrUnsupportedJIDForm = errors.New("messaging: unsupported jid form")
)

// JID is a WhatsApp address: user@server with an optional device.
//
// An empty Server means no address (JID{}); the zero value is not usable as a
// chat target. A JID with a server but no user denotes a server entity such as
// "s.whatsapp.net". Device > 0 renders as user:device@server.
type JID struct {
	User   string
	Device uint16
	Server string
}

// IsEmpty reports whether the JID has no server, matching the reference's
// definition of an unusable address.
func (j JID) IsEmpty() bool { return j.Server == "" }

// String renders the JID in the form ParseJID accepts (PF-032).
//
// A device of 0 is never rendered, so a parsed "user:0@server" comes back as
// "user@server".
func (j JID) String() string {
	switch {
	case j.Server == "":
		return ""
	case j.User == "":
		return j.Server
	case j.Device > 0:
		return j.User + ":" + strconv.FormatUint(uint64(j.Device), 10) + "@" + j.Server
	default:
		return j.User + "@" + j.Server
	}
}

// Normalize returns the canonical chat address (PF-031): the legacy user
// server c.us is rewritten to s.whatsapp.net and the device is dropped.
// Other servers are preserved, and an empty JID stays empty.
func (j JID) Normalize() JID {
	if j.Server == "" {
		return JID{}
	}
	server := j.Server
	if server == LegacyUserServer {
		server = UserServer
	}
	return JID{User: j.User, Server: server}
}

// ParseJID parses user@server and user:device@server (PF-030). A bare token
// without '@' is read as a server JID, matching the reference.
//
// Rejected: an empty string, an empty server, more than one '@' or ':',
// whitespace, an empty device, a non-decimal or out-of-range device, and the
// agent-qualified AD form user.agent[:device]@server (ErrUnsupportedJIDForm).
func ParseJID(raw string) (JID, error) {
	if raw == "" {
		return JID{}, fmt.Errorf("%w: empty string", ErrInvalidJID)
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return JID{}, fmt.Errorf("%w: %q contains whitespace", ErrInvalidJID, raw)
	}

	at := strings.IndexByte(raw, '@')
	if at < 0 {
		return JID{Server: raw}, nil
	}
	if strings.LastIndexByte(raw, '@') != at {
		return JID{}, fmt.Errorf("%w: %q has more than one '@'", ErrInvalidJID, raw)
	}

	user, server := raw[:at], raw[at+1:]
	if server == "" {
		return JID{}, fmt.Errorf("%w: %q has an empty server", ErrInvalidJID, raw)
	}

	jid := JID{User: user, Server: server}
	if colon := strings.IndexByte(user, ':'); colon >= 0 {
		if strings.IndexByte(user[colon+1:], ':') >= 0 {
			return JID{}, fmt.Errorf("%w: %q has more than one ':'", ErrInvalidJID, raw)
		}
		if colon == 0 {
			return JID{}, fmt.Errorf("%w: %q has an empty user before ':'", ErrInvalidJID, raw)
		}
		device, err := parseDevice(user[colon+1:])
		if err != nil {
			return JID{}, fmt.Errorf("%w: %q: %w", ErrInvalidJID, raw, err)
		}
		jid.User, jid.Device = user[:colon], device
	}

	// AD JIDs place the domain/agent after a dot in the user part. They need a
	// field this type does not carry yet, so reject instead of dropping data.
	if strings.ContainsRune(jid.User, '.') {
		return JID{}, fmt.Errorf("%w: %q is an agent-qualified (AD) jid", ErrUnsupportedJIDForm, raw)
	}
	return jid, nil
}

// parseDevice accepts a non-empty decimal in the uint16 range. A leading zero
// is accepted and canonicalized away by String.
func parseDevice(s string) (uint16, error) {
	if s == "" {
		return 0, errors.New("empty device")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("device %q is not decimal", s)
		}
	}
	device, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("device %q out of range", s)
	}
	return uint16(device), nil
}

// validateAddress checks the fields of a JID that message builders require:
// a server and a user, with no whitespace or '@' that would break the wire
// form. Parsed JIDs already satisfy this; it also guards struct literals.
func (j JID) validateAddress() error {
	if j.Server == "" {
		return fmt.Errorf("%w: empty server", ErrInvalidJID)
	}
	if j.User == "" {
		return fmt.Errorf("%w: empty user", ErrInvalidJID)
	}
	if strings.ContainsAny(j.User+j.Server, "@ \t\r\n") {
		return fmt.Errorf("%w: %q contains an address separator or whitespace", ErrInvalidJID, j.String())
	}
	return nil
}
