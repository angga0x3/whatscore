package messaging

import (
	"errors"
	"testing"
)

func TestParseJID(t *testing.T) {
	valid := []struct {
		name string
		in   string
		want JID
	}{
		{"user server", "6281234567890@s.whatsapp.net", JID{User: "6281234567890", Server: UserServer}},
		{"group", "120363021234567890@g.us", JID{User: "120363021234567890", Server: GroupServer}},
		{"status broadcast", "status@broadcast", JID{User: "status", Server: BroadcastServer}},
		{"lid", "99999999999999@lid", JID{User: "99999999999999", Server: LIDServer}},
		{"newsletter", "120363021234567890@newsletter", JID{User: "120363021234567890", Server: NewsletterServer}},
		{"legacy server", "6281234567890@c.us", JID{User: "6281234567890", Server: LegacyUserServer}},
		{"device", "6281234567890:5@s.whatsapp.net", JID{User: "6281234567890", Device: 5, Server: UserServer}},
		{"device zero", "6281234567890:0@s.whatsapp.net", JID{User: "6281234567890", Server: UserServer}},
		{"device max", "6281234567890:65535@s.whatsapp.net", JID{User: "6281234567890", Device: 65535, Server: UserServer}},
		{"device leading zero", "6281234567890:007@s.whatsapp.net", JID{User: "6281234567890", Device: 7, Server: UserServer}},
		{"server only", "s.whatsapp.net", JID{Server: UserServer}},
		{"server only group", "g.us", JID{Server: GroupServer}},
		{"explicit empty user", "@s.whatsapp.net", JID{Server: UserServer}},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseJID(tc.in)
			if err != nil {
				t.Fatalf("ParseJID(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseJID(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
			// String must be re-parseable to the same value (PF-032).
			again, err := ParseJID(got.String())
			if err != nil {
				t.Fatalf("ParseJID(%q) after String: %v", got.String(), err)
			}
			if again != got {
				t.Fatalf("String round trip = %#v, want %#v", again, got)
			}
		})
	}

	if got, err := ParseJID("6281234567890:007@s.whatsapp.net"); err != nil || got.String() != "6281234567890:7@s.whatsapp.net" {
		t.Fatalf("device canonicalization = %q, %v", got.String(), err)
	}
}

func TestParseJIDInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrInvalidJID},
		{"empty server", "6281234567890@", ErrInvalidJID},
		{"only at", "@", ErrInvalidJID},
		{"two at signs", "a@b@c", ErrInvalidJID},
		{"two colons", "user:1:2@server", ErrInvalidJID},
		{"empty device", "user:@server", ErrInvalidJID},
		{"empty user before device", ":5@server", ErrInvalidJID},
		{"non decimal device", "user:abc@server", ErrInvalidJID},
		{"negative device", "user:-1@server", ErrInvalidJID},
		{"signed device", "user:+1@server", ErrInvalidJID},
		{"hex device", "user:0x10@server", ErrInvalidJID},
		{"device out of range", "user:65536@server", ErrInvalidJID},
		{"fractional device", "user:1.5@server", ErrInvalidJID},
		{"leading space", " user@server", ErrInvalidJID},
		{"inner space", "user@ser ver", ErrInvalidJID},
		{"newline", "user@server\n", ErrInvalidJID},
		{"agent form with device", "1234.5:2@s.whatsapp.net", ErrUnsupportedJIDForm},
		{"agent form", "1234.5@s.whatsapp.net", ErrUnsupportedJIDForm},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseJID(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ParseJID(%q) error = %v, want %v", tc.in, err, tc.want)
			}
			if got != (JID{}) {
				t.Fatalf("ParseJID(%q) = %#v, want zero JID", tc.in, got)
			}
		})
	}
}

func TestJIDString(t *testing.T) {
	cases := []struct {
		jid  JID
		want string
	}{
		{JID{}, ""},
		{JID{Server: GroupServer}, GroupServer},
		{JID{User: "6281234567890", Server: UserServer}, "6281234567890@s.whatsapp.net"},
		{JID{User: "6281234567890", Device: 2, Server: UserServer}, "6281234567890:2@s.whatsapp.net"},
		{JID{User: "6281234567890", Device: 0, Server: UserServer}, "6281234567890@s.whatsapp.net"},
		// A device without a user is not a renderable address; the server form
		// wins so String never emits ":d@server".
		{JID{Device: 2, Server: UserServer}, UserServer},
	}
	for _, tc := range cases {
		if got := tc.jid.String(); got != tc.want {
			t.Fatalf("JID%#v.String() = %q, want %q", tc.jid, got, tc.want)
		}
	}

	if !(JID{}).IsEmpty() {
		t.Fatal("zero JID should be empty")
	}
	if (JID{Server: UserServer}).IsEmpty() {
		t.Fatal("server JID should not be empty")
	}
}

func TestJIDNormalize(t *testing.T) {
	cases := []struct {
		in   JID
		want JID
	}{
		{JID{}, JID{}},
		{JID{User: "6281234567890", Server: LegacyUserServer}, JID{User: "6281234567890", Server: UserServer}},
		{JID{User: "6281234567890", Device: 3, Server: UserServer}, JID{User: "6281234567890", Server: UserServer}},
		{JID{User: "120363021234567890", Server: GroupServer}, JID{User: "120363021234567890", Server: GroupServer}},
		{JID{User: "status", Server: BroadcastServer}, JID{User: "status", Server: BroadcastServer}},
	}
	for _, tc := range cases {
		if got := tc.in.Normalize(); got != tc.want {
			t.Fatalf("JID%#v.Normalize() = %#v, want %#v", tc.in, got, tc.want)
		}
		if got := tc.in.Normalize().Normalize(); got != tc.in.Normalize() {
			t.Fatalf("Normalize is not idempotent: %#v", got)
		}
	}
}
