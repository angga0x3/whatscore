package main

// App state sync keys the phone shares, kept across runs.
//
// The keys are the HKDF roots every app state patch MAC is verified against.
// The phone shares them once; a run that forgets them has to ask again, and
// the phone only answers while it is awake. The probe's other secrets (the
// key file, the session file) already live beside the credentials, so these
// do too — owner-only, same directory, same lifetime.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// appStatePathFor derives the key file from the key path:
// paired.keys.json -> paired.appstate.keys.json. The ".keys" suffix is
// dropped first so the name describes what the file holds, not what it was
// derived from.
func appStatePathFor(keysPath string) string {
	base := strings.TrimSuffix(filepath.Base(keysPath), filepath.Ext(keysPath))
	base = strings.TrimSuffix(base, ".keys")
	return filepath.Join(filepath.Dir(keysPath), base+".appstate.keys.json")
}

// loadAppStateKeys reads the stored map. A missing file is the first run, not
// an error.
func loadAppStateKeys(path string) (map[string][]byte, error) {
	if path == "" {
		return map[string][]byte{}, nil
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read app state keys: %w", err)
	}
	keys := map[string][]byte{}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("decode app state keys: %w", err)
	}
	return keys, nil
}

// saveAppStateKeys writes the map with owner-only permissions.
func saveAppStateKeys(path string, keys map[string][]byte) error {
	if path == "" {
		return fmt.Errorf("no app state key path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create app state key directory: %w", err)
	}
	raw, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("encode app state keys: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write app state keys: %w", err)
	}
	return nil
}
