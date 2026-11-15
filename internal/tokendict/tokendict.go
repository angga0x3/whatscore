// Package tokendict validates candidate WhatsApp token tables before they are
// turned into a binary.Dictionary.
//
// No token table ships with this repository. The real table's licensing and
// derivation question is open (technical specification §10.2), so this package
// only checks the *shape and provenance* of a table a contributor supplies
// locally. It never embeds, downloads, or reconstructs token strings.
//
// Validation errors never include token values: a rejected table is described
// by index and reason only, so a validator run cannot copy a proprietary table
// into CI logs or terminal scrollback.
//
// The rule set is documented in docs/protocol/tokens.md.
package tokendict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// Table limits. They mirror the wire layout in protocol/binary: single-byte
// index 0 is reserved, usable single tokens are 1..235, and there are at most
// four double-byte dictionaries of at most 256 entries each.
const (
	// MaxSingleEntries is the maximum length of Single, including the
	// reserved index 0.
	MaxSingleEntries = 236
	// MaxSingleTokens is the number of usable single-byte tokens (1..235).
	MaxSingleTokens = MaxSingleEntries - 1
	// MaxDictionaries is the maximum number of double-byte rows.
	MaxDictionaries = 4
	// MaxDictionaryEntries is the maximum length of one double-byte row.
	MaxDictionaryEntries = 256
	// MaxTokenLength caps one token in bytes. Reference tokens are far
	// shorter; the cap only bounds memory and reviewer attention.
	MaxTokenLength = 256
	// MaxTokens is the structural maximum of a table: every usable single
	// slot plus every double slot. It is re-checked explicitly so a future
	// relaxation of the shape limits cannot silently raise the total.
	MaxTokens = MaxSingleTokens + MaxDictionaries*MaxDictionaryEntries
)

// maxFileBytes caps LoadAndValidate input, matching the codec's loader.
const maxFileBytes = 4 << 20

// Kind classifies a validation failure. It is stable for scripting.
type Kind string

// Validation failure kinds.
const (
	KindMissingField   Kind = "missing-field"
	KindInvalidDate    Kind = "invalid-date"
	KindMissingSingle  Kind = "missing-single-table"
	KindReservedIndex  Kind = "reserved-index"
	KindTooManySingle  Kind = "too-many-single-entries"
	KindTooManyDicts   Kind = "too-many-dictionaries"
	KindTooManyEntries Kind = "too-many-dictionary-entries"
	KindTooManyTokens  Kind = "too-many-tokens"
	KindEmptyToken     Kind = "empty-token"
	KindDuplicateToken Kind = "duplicate-token"
	KindControlChar    Kind = "control-character"
	KindInvalidUTF8    Kind = "invalid-utf8"
	KindTokenTooLong   Kind = "token-too-long"
	KindMalformedJSON  Kind = "malformed-json"
	KindUnknownField   Kind = "unknown-json-field"
	KindFileTooLarge   Kind = "file-too-large"
)

// ErrInvalid is the sentinel wrapped by every *Error, so callers can test
// errors.Is(err, tokendict.ErrInvalid) without matching on message text.
var ErrInvalid = errors.New("tokendict: invalid table")

// Error is the typed validation failure. Index is -1 when the failure is not
// tied to one entry; Dict is -1 when it is not tied to a double-byte row.
type Error struct {
	Kind  Kind
	Field string
	Index int
	Dict  int
	Msg   string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("tokendict: ")
	b.WriteString(string(e.Kind))
	if e.Field != "" {
		b.WriteString(": field ")
		b.WriteString(e.Field)
	}
	if e.Dict >= 0 {
		fmt.Fprintf(&b, ": dictionary %d", e.Dict)
	}
	if e.Index >= 0 {
		fmt.Fprintf(&b, ": index %d", e.Index)
	}
	if e.Msg != "" {
		b.WriteString(": ")
		b.WriteString(e.Msg)
	}
	return b.String()
}

// Unwrap exposes ErrInvalid for errors.Is.
func (e *Error) Unwrap() error { return ErrInvalid }

func failure(kind Kind, field string, index, dict int, format string, args ...any) error {
	return &Error{
		Kind:  kind,
		Field: field,
		Index: index,
		Dict:  dict,
		Msg:   fmt.Sprintf(format, args...),
	}
}

// Table is a candidate token table with the provenance the policy requires.
// The JSON shape matches protocol/binary's loader plus the provenance fields:
//
//	{"source":"...","observed_date":"YYYY-MM-DD","license":"...",
//	 "single":["", ...],"double":[["..."], ...]}
type Table struct {
	Source       string     `json:"source"`
	ObservedDate string     `json:"observed_date"`
	License      string     `json:"license"`
	Single       []string   `json:"single"`
	Double       [][]string `json:"double"`
}

// Provenance is the attribution half of a Table. It is what the CLI prints
// and what a review cites; it never contains token material.
type Provenance struct {
	Source       string `json:"source"`
	ObservedDate string `json:"observed_date"`
	License      string `json:"license"`
}

// Provenance returns the table's source, observation date, and license.
func (t Table) Provenance() Provenance {
	return Provenance{
		Source:       t.Source,
		ObservedDate: t.ObservedDate,
		License:      t.License,
	}
}

// Validate checks a candidate table against the acceptance rules in
// docs/protocol/tokens.md. Every failure is an *Error.
func Validate(t Table) error {
	if err := validateProvenance(t); err != nil {
		return err
	}
	if err := validateShape(t); err != nil {
		return err
	}
	return validateEntries(t)
}

func validateProvenance(t Table) error {
	if strings.TrimSpace(t.Source) == "" {
		return failure(KindMissingField, "source", -1, -1, "a candidate table must record its source")
	}
	if strings.TrimSpace(t.ObservedDate) == "" {
		return failure(KindMissingField, "observed_date", -1, -1, "a candidate table must record an observation date")
	}
	when, err := time.Parse("2006-01-02", t.ObservedDate)
	if err != nil || when.Format("2006-01-02") != t.ObservedDate {
		return failure(KindInvalidDate, "observed_date", -1, -1, "want YYYY-MM-DD, got %q", t.ObservedDate)
	}
	if strings.TrimSpace(t.License) == "" {
		return failure(KindMissingField, "license", -1, -1, "a candidate table must record its license")
	}
	return nil
}

func validateShape(t Table) error {
	if len(t.Single) == 0 {
		return failure(KindMissingSingle, "single", -1, -1, "single must have at least the reserved index 0")
	}
	if len(t.Single) > MaxSingleEntries {
		return failure(KindTooManySingle, "single", len(t.Single), -1,
			"%d entries exceed the maximum of %d", len(t.Single), MaxSingleEntries)
	}
	if t.Single[0] != "" {
		return failure(KindReservedIndex, "single", 0, -1, "index 0 is reserved and must be empty")
	}
	if len(t.Double) > MaxDictionaries {
		return failure(KindTooManyDicts, "double", -1, -1,
			"%d dictionaries exceed the maximum of %d", len(t.Double), MaxDictionaries)
	}
	for dict, row := range t.Double {
		if len(row) > MaxDictionaryEntries {
			return failure(KindTooManyEntries, "double", -1, dict,
				"%d entries exceed the maximum of %d", len(row), MaxDictionaryEntries)
		}
	}
	return nil
}

func validateEntries(t Table) error {
	singleSeen := make(map[string]int, len(t.Single))
	total := 0
	for i := 1; i < len(t.Single); i++ {
		if err := validateToken("single", t.Single[i], i, -1, singleSeen); err != nil {
			return err
		}
		singleSeen[t.Single[i]] = i
		total++
	}

	doubleSeen := make(map[string]struct{ dict, index int }, MaxDictionaries*MaxDictionaryEntries/4)
	for dict, row := range t.Double {
		for index, token := range row {
			if err := validateToken("double", token, index, dict, nil); err != nil {
				return err
			}
			if first, ok := doubleSeen[token]; ok {
				return failure(KindDuplicateToken, "double", index, dict,
					"duplicate of dictionary %d index %d", first.dict, first.index)
			}
			doubleSeen[token] = struct{ dict, index int }{dict: dict, index: index}
			total++
		}
	}

	if total > MaxTokens {
		return failure(KindTooManyTokens, "table", -1, -1,
			"%d tokens exceed the maximum of %d", total, MaxTokens)
	}
	return nil
}

// validateToken checks one entry. It returns only index/row positions, never
// the token itself, so rejected tables do not leak into logs.
func validateToken(field, token string, index, dict int, singleSeen map[string]int) error {
	if token == "" {
		return failure(KindEmptyToken, field, index, dict, "token must not be empty; truncate trailing slots instead of leaving holes")
	}
	if !utf8.ValidString(token) {
		return failure(KindInvalidUTF8, field, index, dict, "token is not valid UTF-8")
	}
	if strings.IndexFunc(token, unicode.IsControl) >= 0 {
		return failure(KindControlChar, field, index, dict, "token contains a control character")
	}
	if len(token) > MaxTokenLength {
		return failure(KindTokenTooLong, field, index, dict,
			"token is %d bytes, maximum %d", len(token), MaxTokenLength)
	}
	if singleSeen != nil {
		if first, ok := singleSeen[token]; ok {
			return failure(KindDuplicateToken, field, index, dict, "duplicate of index %d", first)
		}
	}
	return nil
}

// LoadAndValidate decodes a candidate table and validates it. Decoding is
// strict: unknown fields, trailing data, and files over 4 MiB are rejected so
// a table cannot smuggle extra payload past review.
func LoadAndValidate(r io.Reader) (Table, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxFileBytes+1))
	if err != nil {
		return Table{}, failure(KindMalformedJSON, "", -1, -1, "read table: %v", err)
	}
	if len(raw) > maxFileBytes {
		return Table{}, failure(KindFileTooLarge, "", -1, -1,
			"table exceeds %d bytes", maxFileBytes)
	}

	// First pass: reject unknown top-level keys deterministically. Sorting
	// keeps the reported key stable across runs (Go maps are unordered).
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return Table{}, failure(KindMalformedJSON, "", -1, -1, "decode table: %v", err)
	}
	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)
	for _, key := range sortedKeys {
		if !allowedField(key) {
			return Table{}, failure(KindUnknownField, key, -1, -1, "unknown field %q", key)
		}
	}

	// Second pass: strict decode into the typed table.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var t Table
	if err := decoder.Decode(&t); err != nil {
		return Table{}, failure(KindMalformedJSON, "", -1, -1, "decode table: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("unexpected second JSON value")
		}
		return Table{}, failure(KindMalformedJSON, "", -1, -1, "trailing data after table: %v", err)
	}

	if err := Validate(t); err != nil {
		return Table{}, err
	}
	return t, nil
}

func allowedField(name string) bool {
	switch name {
	case "source", "observed_date", "license", "single", "double":
		return true
	default:
		return false
	}
}

// Build validates a table and converts it into a codec dictionary. Callers
// are responsible for deciding whether a table may be used at all (§10.2).
func Build(t Table) (*binary.Dictionary, error) {
	if err := Validate(t); err != nil {
		return nil, err
	}
	dict, err := binary.NewDictionaryFromTokens(t.Single, t.Double)
	if err != nil {
		return nil, fmt.Errorf("tokendict: build dictionary: %w", err)
	}
	return dict, nil
}
