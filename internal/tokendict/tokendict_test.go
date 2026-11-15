package tokendict

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// exampleTable is deliberately fake. Every token is an English word with an
// "example-" prefix so no value could be mistaken for a real WhatsApp token.
func exampleTable() Table {
	return Table{
		Source:       "synthetic example written for this test",
		ObservedDate: "2026-11-15",
		License:      "CC0-1.0 (example only)",
		Single:       []string{"", "example-one", "example-two"},
		Double: [][]string{
			{"example-bravo", "example-charlie"},
			{"example-delta"},
		},
	}
}

func TestValidateAcceptsSyntheticTable(t *testing.T) {
	if err := Validate(exampleTable()); err != nil {
		t.Fatalf("example table rejected: %v", err)
	}
	// A table with only the reserved slot and no double rows is structurally
	// valid: the policy does not require a minimum token count.
	minimal := Table{
		Source:       "synthetic example",
		ObservedDate: "2026-11-15",
		License:      "CC0-1.0",
		Single:       []string{""},
	}
	if err := Validate(minimal); err != nil {
		t.Fatalf("minimal table rejected: %v", err)
	}
}

func TestValidateRejections(t *testing.T) {
	fullSingle := func() []string {
		out := make([]string, MaxSingleEntries+1)
		for i := 1; i < len(out); i++ {
			out[i] = "example-" + string(rune('a'+(i/26)%26)) + string(rune('a'+i%26))
		}
		return out
	}
	fullRow := func(prefix string) []string {
		out := make([]string, MaxDictionaryEntries+1)
		for i := range out {
			out[i] = prefix + "-" + string(rune('a'+(i/26)%26)) + string(rune('a'+i%26))
		}
		return out
	}

	tests := []struct {
		name      string
		edit      func(*Table)
		wantKind  Kind
		wantField string
		wantIndex int
		wantDict  int
	}{
		{
			name:      "missing source",
			edit:      func(tb *Table) { tb.Source = "" },
			wantKind:  KindMissingField,
			wantField: "source",
			wantIndex: -1,
			wantDict:  -1,
		},
		{
			name:      "whitespace source",
			edit:      func(tb *Table) { tb.Source = "   \t " },
			wantKind:  KindMissingField,
			wantField: "source",
			wantIndex: -1,
			wantDict:  -1,
		},
		{
			name:      "missing observed date",
			edit:      func(tb *Table) { tb.ObservedDate = "" },
			wantKind:  KindMissingField,
			wantField: "observed_date",
			wantIndex: -1,
			wantDict:  -1,
		},
		{
			name:      "date without zero padding",
			edit:      func(tb *Table) { tb.ObservedDate = "2026-1-5" },
			wantKind:  KindInvalidDate,
			wantField: "observed_date",
			wantIndex: -1,
			wantDict:  -1,
		},
		{
			name:      "date in the wrong order",
			edit:      func(tb *Table) { tb.ObservedDate = "15-11-2026" },
			wantKind:  KindInvalidDate,
			wantField: "observed_date",
			wantIndex: -1,
			wantDict:  -1,
		},
		{
			name:      "impossible calendar date",
			edit:      func(tb *Table) { tb.ObservedDate = "2026-02-30" },
			wantKind:  KindInvalidDate,
			wantField: "observed_date",
			wantIndex: -1,
			wantDict:  -1,
		},
		{
			name:      "missing license",
			edit:      func(tb *Table) { tb.License = "" },
			wantKind:  KindMissingField,
			wantField: "license",
			wantIndex: -1,
			wantDict:  -1,
		},
		{
			name: "missing single table",
			edit: func(tb *Table) {
				tb.Single = nil
				tb.Double = nil
			},
			wantKind:  KindMissingSingle,
			wantField: "single",
			wantIndex: -1,
			wantDict:  -1,
		},
		{
			name:      "reserved index zero populated",
			edit:      func(tb *Table) { tb.Single[0] = "example-zero" },
			wantKind:  KindReservedIndex,
			wantField: "single",
			wantIndex: 0,
			wantDict:  -1,
		},
		{
			name:      "too many single entries",
			edit:      func(tb *Table) { tb.Single = fullSingle() },
			wantKind:  KindTooManySingle,
			wantField: "single",
			wantIndex: MaxSingleEntries + 1, // reported observed length
			wantDict:  -1,
		},
		{
			name: "too many dictionaries",
			edit: func(tb *Table) {
				tb.Double = [][]string{{"example-a"}, {"example-b"}, {"example-c"}, {"example-d"}, {"example-e"}}
			},
			wantKind:  KindTooManyDicts,
			wantField: "double",
			wantIndex: -1,
			wantDict:  -1,
		},
		{
			name:      "too many entries in one dictionary",
			edit:      func(tb *Table) { tb.Double = [][]string{fullRow("example-row")} },
			wantKind:  KindTooManyEntries,
			wantField: "double",
			wantIndex: -1,
			wantDict:  0,
		},
		{
			name:      "duplicate in single table",
			edit:      func(tb *Table) { tb.Single = []string{"", "example-one", "example-two", "example-one"} },
			wantKind:  KindDuplicateToken,
			wantField: "single",
			wantIndex: 3,
			wantDict:  -1,
		},
		{
			name: "duplicate across double rows",
			edit: func(tb *Table) {
				tb.Double = [][]string{{"example-bravo"}, {"example-charlie", "example-bravo"}}
			},
			wantKind:  KindDuplicateToken,
			wantField: "double",
			wantIndex: 1,
			wantDict:  1,
		},
		{
			name:      "empty token in single table",
			edit:      func(tb *Table) { tb.Single = []string{"", "example-one", ""} },
			wantKind:  KindEmptyToken,
			wantField: "single",
			wantIndex: 2,
			wantDict:  -1,
		},
		{
			name:      "empty token in double table",
			edit:      func(tb *Table) { tb.Double = [][]string{{"example-bravo", ""}} },
			wantKind:  KindEmptyToken,
			wantField: "double",
			wantIndex: 1,
			wantDict:  0,
		},
		{
			name:      "bell control character",
			edit:      func(tb *Table) { tb.Single = []string{"", "example-one", "example\x07two"} },
			wantKind:  KindControlChar,
			wantField: "single",
			wantIndex: 2,
			wantDict:  -1,
		},
		{
			name:      "newline control character",
			edit:      func(tb *Table) { tb.Double = [][]string{{"example\nbravo"}} },
			wantKind:  KindControlChar,
			wantField: "double",
			wantIndex: 0,
			wantDict:  0,
		},
		{
			name:      "oversized token",
			edit:      func(tb *Table) { tb.Single = []string{"", strings.Repeat("example-", MaxTokenLength)} },
			wantKind:  KindTokenTooLong,
			wantField: "single",
			wantIndex: 1,
			wantDict:  -1,
		},
		{
			name:      "invalid utf8 token",
			edit:      func(tb *Table) { tb.Double = [][]string{{string([]byte{0xff, 0xfe})}} },
			wantKind:  KindInvalidUTF8,
			wantField: "double",
			wantIndex: 0,
			wantDict:  0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table := exampleTable()
			test.edit(&table)
			err := Validate(table)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("error is not *Error: %T %v", err, err)
			}
			if typed.Kind != test.wantKind {
				t.Fatalf("kind = %q, want %q (%v)", typed.Kind, test.wantKind, err)
			}
			if test.wantField != "" && typed.Field != test.wantField {
				t.Fatalf("field = %q, want %q (%v)", typed.Field, test.wantField, err)
			}
			if typed.Index != test.wantIndex {
				t.Fatalf("index = %d, want %d (%v)", typed.Index, test.wantIndex, err)
			}
			if typed.Dict != test.wantDict {
				t.Fatalf("dict = %d, want %d (%v)", typed.Dict, test.wantDict, err)
			}
		})
	}
}

func TestErrorDoesNotLeakTokenValues(t *testing.T) {
	table := exampleTable()
	table.Single = []string{"", "example-one", "example-secret-two", "example-secret-two"}
	err := Validate(table)
	if err == nil {
		t.Fatal("expected duplicate error")
	}
	if strings.Contains(err.Error(), "example-secret-two") {
		t.Fatalf("error message leaks a token value: %v", err)
	}
	if !strings.Contains(err.Error(), "duplicate of index 2") {
		t.Fatalf("error should identify the first occurrence by index: %v", err)
	}
}

func TestLoadAndValidateAcceptsSyntheticTable(t *testing.T) {
	raw, err := json.Marshal(exampleTable())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"source"`, `"observed_date"`, `"license"`, `"single"`, `"double"`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Fatalf("marshalled table missing JSON key %s: %s", key, raw)
		}
	}

	table, err := LoadAndValidate(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := table.Provenance(); got != exampleTable().Provenance() {
		t.Fatalf("provenance = %+v", got)
	}
	if len(table.Single) != 3 || len(table.Double) != 2 {
		t.Fatalf("shape = %d single, %d double rows", len(table.Single), len(table.Double))
	}
}

func TestLoadAndValidateRejections(t *testing.T) {
	valid := `{"source":"synthetic","observed_date":"2026-11-15","license":"CC0-1.0","single":["","example-one"],"double":[["example-bravo"]]}`

	tests := []struct {
		name     string
		input    string
		wantKind Kind
	}{
		{name: "empty input", input: "", wantKind: KindMalformedJSON},
		{name: "truncated object", input: `{"source":`, wantKind: KindMalformedJSON},
		{name: "top-level array", input: `[]`, wantKind: KindMalformedJSON},
		{name: "wrong type for single", input: `{"source":"s","observed_date":"2026-11-15","license":"l","single":"nope"}`, wantKind: KindMalformedJSON},
		{name: "trailing json value", input: valid + `{}`, wantKind: KindMalformedJSON},
		{name: "unknown field", input: `{"source":"s","observed_date":"2026-11-15","license":"l","single":[""],"token_table_version":2}`, wantKind: KindUnknownField},
		{name: "unknown field nested is still unknown", input: `{"source":"s","observed_date":"2026-11-15","license":"l","single":[""],"Double":[]}`, wantKind: KindUnknownField},
		{name: "null provenance", input: `{"source":null,"observed_date":"2026-11-15","license":"l","single":[""]}`, wantKind: KindMissingField},
		{name: "valid but no license", input: `{"source":"s","observed_date":"2026-11-15","single":[""]}`, wantKind: KindMissingField},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadAndValidate(strings.NewReader(test.input))
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("error is not *Error: %T %v", err, err)
			}
			if typed.Kind != test.wantKind {
				t.Fatalf("kind = %q, want %q (%v)", typed.Kind, test.wantKind, err)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
		})
	}
}

func TestLoadAndValidateRejectsOversizedInput(t *testing.T) {
	// Whitespace is enough: the byte cap is enforced before parsing.
	reader := io.LimitReader(strings.NewReader(strings.Repeat(" ", maxFileBytes+1)), maxFileBytes+1)
	_, err := LoadAndValidate(reader)
	if err == nil {
		t.Fatal("expected size error")
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindFileTooLarge {
		t.Fatalf("want KindFileTooLarge, got %v", err)
	}
}

func TestBuild(t *testing.T) {
	dict, err := Build(exampleTable())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for index, want := range []string{"", "example-one", "example-two"} {
		got, ok := dict.Single(byte(index))
		if index == 0 {
			if ok {
				t.Fatal("index 0 must stay reserved in the built dictionary")
			}
			continue
		}
		if !ok || got != want {
			t.Fatalf("single[%d] = %q, %v", index, got, ok)
		}
	}
	got, ok := dict.Double(0, 1)
	if !ok || got != "example-charlie" {
		t.Fatalf("double[0][1] = %q, %v", got, ok)
	}
	if dictIndex, dictOffset, ok := dict.IndexDouble("example-delta"); !ok || dictIndex != 1 || dictOffset != 0 {
		t.Fatalf("IndexDouble(example-delta) = %d, %d, %v", dictIndex, dictOffset, ok)
	}
	if _, ok := dict.IndexSingle("example-one"); !ok {
		t.Fatal("IndexSingle(example-one) not found")
	}
}

func TestBuildRejectsInvalidTable(t *testing.T) {
	table := exampleTable()
	table.Source = ""
	if _, err := Build(table); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestProvenanceIsAttributionOnly(t *testing.T) {
	prov := exampleTable().Provenance()
	if prov.Source == "" || prov.ObservedDate != "2026-11-15" || prov.License == "" {
		t.Fatalf("provenance = %+v", prov)
	}
	encoded, err := json.Marshal(prov)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("example-one")) {
		t.Fatalf("provenance must not carry token values: %s", encoded)
	}
}
