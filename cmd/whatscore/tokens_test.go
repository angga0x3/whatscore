package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/angga0x3/whatscore/config"
)

// writeTable writes a synthetic token table with the provenance ADR 0002
// requires, and returns its path.
func writeTable(t *testing.T, overrides map[string]any) string {
	t.Helper()
	table := map[string]any{
		"source":        "synthetic test table",
		"observed_date": "2026-11-15",
		"license":       "Apache-2.0",
		"single":        []string{"", "example-one", "example-two"},
		"double":        [][]string{{"example-three"}},
	}
	for key, value := range overrides {
		table[key] = value
	}
	raw, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "table.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func configWithTable(path string) *config.Config {
	cfg := &config.Config{}
	cfg.Engine.TokenDictionaryPath = path
	return cfg
}

func TestLoadTokenDictionaryAbsent(t *testing.T) {
	dictionary, err := loadTokenDictionary(&config.Config{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("no table must not fail: %v", err)
	}
	if dictionary == nil {
		t.Fatal("nil dictionary")
	}
	// An empty table still encodes raw strings, so the codec is usable.
	if _, ok := dictionary.IndexSingle("example-one"); ok {
		t.Fatal("empty dictionary has tokens")
	}
}

func TestLoadTokenDictionaryValid(t *testing.T) {
	path := writeTable(t, nil)
	dictionary, err := loadTokenDictionary(configWithTable(path), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	index, ok := dictionary.IndexSingle("example-one")
	if !ok || index != 1 {
		t.Fatalf("example-one index = %d, %v", index, ok)
	}
	if dict, idx, ok := dictionary.IndexDouble("example-three"); !ok || dict != 0 || idx != 0 {
		t.Fatalf("example-three = %d/%d/%v", dict, idx, ok)
	}
}

func TestLoadTokenDictionaryRejected(t *testing.T) {
	cases := map[string]map[string]any{
		"missing source":    {"source": ""},
		"bad date":          {"observed_date": "2026-1-5"},
		"missing license":   {"license": ""},
		"reserved index":    {"single": []string{"nope", "example-one"}},
		"duplicate token":   {"double": [][]string{{"example-one"}}},
		"empty token":       {"single": []string{"", ""}},
		"control character": {"single": []string{"", "bad\x00token"}},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeTable(t, overrides)
			_, err := loadTokenDictionary(configWithTable(path), slog.New(slog.DiscardHandler))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !bytes.Contains([]byte(err.Error()), []byte("tokendict")) {
				t.Fatalf("error does not name the validator: %v", err)
			}
		})
	}
}

func TestLoadTokenDictionaryMissingFile(t *testing.T) {
	_, err := loadTokenDictionary(configWithTable(filepath.Join(t.TempDir(), "absent.json")), slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoadTokenDictionaryNilConfig(t *testing.T) {
	if _, err := loadTokenDictionary(nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("nil config must fail")
	}
}
