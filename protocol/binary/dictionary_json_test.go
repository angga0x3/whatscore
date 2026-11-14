package binary

import (
	"strings"
	"testing"
)

func TestLoadDictionary(t *testing.T) {
	d, err := LoadDictionary(strings.NewReader(`{
		"single": ["", "alpha", "beta"],
		"double": [["gamma"], [], [], ["delta"]]
	}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if s, ok := d.Single(1); !ok || s != "alpha" {
		t.Fatalf("single[1] = %q, %v", s, ok)
	}
	if s, ok := d.Double(3, 0); !ok || s != "delta" {
		t.Fatalf("double[3][0] = %q, %v", s, ok)
	}
	if _, err := LoadDictionary(strings.NewReader(`{"single":["","a"],"double":[],"extra":1}`)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
	if _, err := LoadDictionary(strings.NewReader(`{"single":["","a","a"],"double":[]}`)); err != nil {
		t.Fatalf("duplicate token should be allowed: %v", err)
	}
	if _, err := LoadDictionary(strings.NewReader(`not json`)); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
}
