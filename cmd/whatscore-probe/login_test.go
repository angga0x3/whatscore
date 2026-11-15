package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/angga0x3/whatscore/protocol/auth"
	"github.com/angga0x3/whatscore/protocol/protobuf"
)

// TestLoadCredentialRecordRejectsIncompleteFiles keeps the login path from
// building a payload out of missing key material, which would fail at the
// server with a message that says nothing useful.
func TestLoadCredentialRecordRejectsIncompleteFiles(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name string
		json string
	}{
		{"empty", `{}`},
		{"no jid", `{"noise_private_key":[1],"noise_public_key":[2],"identity_private_key":[3],"adv_secret":[4]}`},
		{"no adv secret", `{"jid":"100:1@s.whatsapp.net","noise_private_key":[1],"noise_public_key":[2],"identity_private_key":[3]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(path, []byte(tc.json), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := loadCredentialRecord(path); err == nil {
				t.Fatal("incomplete record accepted")
			}
		})
	}
}

// TestLoadCredentialRecordNeedsAPath pins the error a user actually hits: the
// login flags are separate from the pairing ones.
func TestLoadCredentialRecordNeedsAPath(t *testing.T) {
	if _, err := loadCredentialRecord(""); err == nil {
		t.Fatal("empty path accepted")
	}
}

// TestLoginUserAgentMatchesPairing keeps both connections describing one
// device. A mismatch is the kind of thing the server accepts and then behaves
// strangely about, so it is pinned rather than left to memory.
func TestLoginUserAgentMatchesPairing(t *testing.T) {
	if loginVersion != (auth.Version{Primary: 2, Secondary: 3000, Tertiary: 1052556849}) {
		t.Fatalf("login version drifted: %+v", loginVersion)
	}
	if loginUserAgent.Platform != protobuf.ClientPayload_UserAgent_WEB {
		t.Fatalf("login platform is %v, want WEB", loginUserAgent.Platform)
	}
}
