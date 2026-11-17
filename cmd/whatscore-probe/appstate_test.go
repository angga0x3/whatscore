package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAppStateKeysRoundTrip pins the file: a run that stored the phone's keys
// must not ask for them again, so the bytes and the owner-only permissions
// both matter.
func TestAppStateKeysRoundTrip(t *testing.T) {
	t.Chdir(t.TempDir())
	path := appStatePathFor("paired.keys.json")
	keys := map[string][]byte{
		"aa": {0x01, 0x02},
		"bb": {0x03},
	}
	if err := saveAppStateKeys(path, keys); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}
	restored, err := loadAppStateKeys(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(restored) != 2 || string(restored["aa"]) != string([]byte{0x01, 0x02}) {
		t.Fatalf("restored = %#v", restored)
	}
}

// TestAppStateKeysMissingFileIsFirstRun keeps a fresh checkout from looking
// broken.
func TestAppStateKeysMissingFileIsFirstRun(t *testing.T) {
	t.Chdir(t.TempDir())
	keys, err := loadAppStateKeys(appStatePathFor("paired.keys.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("keys = %#v", keys)
	}
}

// TestAppStateKeysRejectCorruptFile keeps a damaged file loud: starting empty
// would silently re-ask the phone and look like the keys were never stored.
func TestAppStateKeysRejectCorruptFile(t *testing.T) {
	t.Chdir(t.TempDir())
	path := appStatePathFor("paired.keys.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAppStateKeys(path); err == nil {
		t.Fatal("corrupt file accepted")
	}
}

// TestAppStatePathSitsBesideTheKeys pins the derived name so save and load
// cannot disagree.
func TestAppStatePathSitsBesideTheKeys(t *testing.T) {
	got := appStatePathFor(filepath.Join("creds", "paired.keys.json"))
	want := filepath.Join("creds", "paired.appstate.keys.json")
	if got != want {
		t.Fatalf("appStatePathFor = %q, want %q", got, want)
	}
}

// TestSaveAppStateKeysNeedsAPath keeps the failure loud.
func TestSaveAppStateKeysNeedsAPath(t *testing.T) {
	if err := saveAppStateKeys("", map[string][]byte{}); err == nil {
		t.Fatal("empty path accepted")
	}
}
