package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	coremessaging "github.com/angga0x3/whatscore/core/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// persist is the send path's own write: an outbound send advances the ratchet
// and nobody observes it, so -send has to persist the returned session itself.
// Without this the next run encrypts from a chain the peer has already moved
// past.
func TestPersistRoundTripsAndIsOwnerOnly(t *testing.T) {
	t.Chdir(t.TempDir())
	path := sessionsPathFor("paired.keys.json")

	store, err := loadSessionsFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	session := newTestPeerSession(t)
	peerJID := "628111@s.whatsapp.net"
	if err := store.persist(path, peerJID, session); err != nil {
		t.Fatalf("persist: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}

	restored, err := loadSessionsFile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	rec, ok := restored.Sessions[peerJID]
	if !ok {
		t.Fatalf("session %s missing after persist", peerJID)
	}
	if string(rec.PeerIdentity) != string(session.PeerIdentity[:]) {
		t.Fatal("peer identity did not survive the round trip")
	}
	raw, err := base64.StdEncoding.DecodeString(rec.State)
	if err != nil {
		t.Fatalf("decode state: %v", err)
	}
	var back signal.State
	if err := back.UnmarshalBinary(raw); err != nil {
		t.Fatalf("restore state: %v", err)
	}
}

// TestPersistKeepsEarlierSessions guards against a send-path write replacing
// the whole file: the phone's session is what carries the own-device copy, and
// it must survive a send to somebody else.
func TestPersistKeepsEarlierSessions(t *testing.T) {
	t.Chdir(t.TempDir())
	path := sessionsPathFor("paired.keys.json")

	store, err := loadSessionsFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := store.persist(path, "111@s.whatsapp.net", newTestPeerSession(t)); err != nil {
		t.Fatalf("persist first: %v", err)
	}
	if err := store.persist(path, "222@s.whatsapp.net", newTestPeerSession(t)); err != nil {
		t.Fatalf("persist second: %v", err)
	}

	reloaded, err := loadSessionsFile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(reloaded.Sessions))
	}
}

// TestPersistRejectsNoPath keeps the failure loud instead of writing nowhere
// and reporting success.
func TestPersistRejectsNoPath(t *testing.T) {
	store := &sessionsFile{Sessions: map[string]storedSession{}}
	if err := store.persist("", "111@s.whatsapp.net", newTestPeerSession(t)); err == nil {
		t.Fatal("empty path accepted")
	}
}

// TestInstallSenderRestoresEverySession is the -send half of the PF-087 fix:
// the send path has no receiver, but a session the listener bootstrapped must
// still be usable, or every send initiates a fresh prekey session.
func TestInstallSenderRestoresEverySession(t *testing.T) {
	t.Chdir(t.TempDir())
	path := sessionsPathFor("paired.keys.json")

	store := &sessionsFile{Sessions: map[string]storedSession{}}
	for _, peer := range []string{"111@s.whatsapp.net", "266988689592415:39@lid"} {
		if err := store.persist(path, peer, newTestPeerSession(t)); err != nil {
			t.Fatalf("persist %s: %v", peer, err)
		}
	}
	reloaded, err := loadSessionsFile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	sender, err := coremessaging.NewSender(discardWriter{})
	if err != nil {
		t.Fatalf("sender: %v", err)
	}
	n, err := reloaded.installSender(sender)
	if err != nil {
		t.Fatalf("installSender: %v", err)
	}
	if n != 2 {
		t.Fatalf("installed = %d, want 2", n)
	}
}

// discardWriter accepts frames and drops them: tests that exercise session
// installation never reach the wire.
type discardWriter struct{}

func (discardWriter) WriteFrame(context.Context, []byte) error { return nil }

// TestInstallSenderRejectsNilSender keeps a programming error visible.
func TestInstallSenderRejectsNilSender(t *testing.T) {
	store := &sessionsFile{Sessions: map[string]storedSession{}}
	if _, err := store.installSender(nil); err == nil {
		t.Fatal("nil sender accepted")
	}
}

// TestSessionsPathSitsBesideTheKeys pins the derived name -send and -listen
// must agree on, or the send path writes a file the listener never reads.
func TestSessionsPathSitsBesideTheKeys(t *testing.T) {
	got := sessionsPathFor(filepath.Join("creds", "paired.keys.json"))
	want := filepath.Join("creds", "paired.keys.sessions.json")
	if got != want {
		t.Fatalf("sessionsPathFor = %q, want %q", got, want)
	}
}

func newTestPeerSession(t *testing.T) *coremessaging.PeerSession {
	t.Helper()
	identity, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	peer, err := signal.GenerateKeyPair()
	if err != nil {
		t.Fatalf("peer: %v", err)
	}
	signed, err := signal.GenerateSignedPreKey(1, signal.XEdDSASigner{Private: peer.Private})
	if err != nil {
		t.Fatalf("signed prekey: %v", err)
	}
	oneTime, err := signal.GeneratePreKey(2)
	if err != nil {
		t.Fatalf("one-time prekey: %v", err)
	}
	initiated, err := signal.Initiate(identity, signal.PreKeyBundle{
		IdentityKey:           peer.Public,
		SignedPreKeyID:        signed.ID,
		SignedPreKey:          signed.Pair.Public,
		SignedPreKeySignature: signed.Signature,
		OneTimePreKeyID:       oneTime.ID,
		OneTimePreKey:         &oneTime.Pair.Public,
	})
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	state, err := signal.NewInitiator(initiated.Keys.RootKey, signed.Pair.Public, initiated.Keys.ChainKey)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	return &coremessaging.PeerSession{PeerIdentity: peer.Public, State: state}
}
