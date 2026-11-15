package binary

import "fmt"

// Wire tags (PF-011..PF-014).
const (
	tagListEmpty       = 0
	tagDictionary0     = 236
	tagDictionary1     = 237
	tagDictionary2     = 238
	tagDictionary3     = 239
	tagInteropJID      = 245
	tagFBJID           = 246
	tagADJID           = 247
	tagList8           = 248
	tagList16          = 249
	tagJIDPair         = 250
	tagHex8            = 251
	tagBinary8         = 252
	tagBinary20        = 253
	tagBinary32        = 254
	tagNibble8         = 255
	singleByteTokenMax = 235
	dictionaryCount    = 4
	dictionarySize     = 256
	packedMax          = 127
)

// Dictionary maps strings to wire tokens. Index 0 of the single-byte table
// is reserved; usable string tokens are 1..235.
type Dictionary struct {
	single    [singleByteTokenMax + 1]string
	singleOK  [singleByteTokenMax + 1]bool
	double    [dictionaryCount][dictionarySize]string
	doubleOK  [dictionaryCount][dictionarySize]bool
	singleIdx map[string]byte
	doubleIdx map[string]doubleTokenRef
}

type doubleTokenRef struct {
	dictionary byte
	index      byte
}

// NewDictionary returns an empty dictionary.
func NewDictionary() *Dictionary {
	return &Dictionary{
		singleIdx: make(map[string]byte),
		doubleIdx: make(map[string]doubleTokenRef),
	}
}

// DefaultDictionary returns a shared empty dictionary.
func DefaultDictionary() *Dictionary {
	return NewDictionary()
}

// Clone returns a deep copy. A caller that mutates a working copy — the probe's
// hole-filled table — must not quietly change the table a strict codec is
// still reading: one shared pointer turned every unknown token into a
// placeholder and silently ended the loud failure the table exists for.
func (d *Dictionary) Clone() *Dictionary {
	out := NewDictionary()
	out.single = d.single
	out.singleOK = d.singleOK
	out.double = d.double
	out.doubleOK = d.doubleOK
	for token, index := range d.singleIdx {
		out.singleIdx[token] = index
	}
	for token, ref := range d.doubleIdx {
		out.doubleIdx[token] = ref
	}
	return out
}

// SetSingle sets token at index 1..235.
func (d *Dictionary) SetSingle(index byte, token string) error {
	if index == 0 || index > singleByteTokenMax {
		return fmt.Errorf("binary: single-byte token index %d out of range 1..%d", index, singleByteTokenMax)
	}
	if token == "" {
		return fmt.Errorf("binary: single-byte token must not be empty")
	}
	if old, ok := d.singleIdx[token]; ok && old != index {
		delete(d.singleIdx, token)
	}
	d.single[index] = token
	d.singleOK[index] = true
	d.singleIdx[token] = index
	return nil
}

// SetDouble sets token at (dict 0..3, index 0..255).
func (d *Dictionary) SetDouble(dict, index byte, token string) error {
	if dict >= dictionaryCount {
		return fmt.Errorf("binary: double-byte dictionary %d out of range 0..%d", dict, dictionaryCount-1)
	}
	if token == "" {
		return fmt.Errorf("binary: double-byte token must not be empty")
	}
	if old, ok := d.doubleIdx[token]; ok && (old.dictionary != dict || old.index != index) {
		delete(d.doubleIdx, token)
	}
	d.double[dict][index] = token
	d.doubleOK[dict][index] = true
	d.doubleIdx[token] = doubleTokenRef{dictionary: dict, index: index}
	return nil
}

// Single returns the token at index.
func (d *Dictionary) Single(index byte) (string, bool) {
	if index == 0 || index > singleByteTokenMax || !d.singleOK[index] {
		return "", false
	}
	return d.single[index], true
}

// Double returns the token at (dict, index).
func (d *Dictionary) Double(dict, index byte) (string, bool) {
	if dict >= dictionaryCount || !d.doubleOK[dict][index] {
		return "", false
	}
	return d.double[dict][index], true
}

// IndexSingle returns the index for s.
func (d *Dictionary) IndexSingle(s string) (byte, bool) {
	index, ok := d.singleIdx[s]
	return index, ok
}

// IndexDouble returns the position for s.
func (d *Dictionary) IndexDouble(s string) (dict, index byte, ok bool) {
	ref, found := d.doubleIdx[s]
	return ref.dictionary, ref.index, found
}

// NewDictionaryFromTokens builds a dictionary from reference-layout tables:
// single[0] is reserved, double holds at most four slices of 256 entries.
func NewDictionaryFromTokens(single []string, double [][]string) (*Dictionary, error) {
	if len(single) > singleByteTokenMax+1 {
		return nil, fmt.Errorf("binary: %d single-byte tokens exceed %d", len(single), singleByteTokenMax+1)
	}
	if len(double) > dictionaryCount {
		return nil, fmt.Errorf("binary: %d double-byte dictionaries exceed %d", len(double), dictionaryCount)
	}
	d := NewDictionary()
	for i := 1; i < len(single); i++ {
		if single[i] == "" {
			continue
		}
		if err := d.SetSingle(byte(i), single[i]); err != nil {
			return nil, err
		}
	}
	for dict, tokens := range double {
		if len(tokens) > dictionarySize {
			return nil, fmt.Errorf("binary: dictionary %d has %d tokens, maximum %d", dict, len(tokens), dictionarySize)
		}
		for index, token := range tokens {
			if token == "" {
				continue
			}
			if err := d.SetDouble(byte(dict), byte(index), token); err != nil {
				return nil, err
			}
		}
	}
	return d, nil
}
