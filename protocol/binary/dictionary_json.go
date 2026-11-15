package binary

import (
	"encoding/json"
	"fmt"
	"io"
)

const maxDictionaryFileBytes = 4 << 20

type dictionaryDocument struct {
	Single []string   `json:"single"`
	Double [][]string `json:"double"`
}

// LoadDictionary reads a JSON token table with the shape
// {"single":[...],"double":[[...],...]}. Single-byte index 0 is reserved.
func LoadDictionary(r io.Reader) (*Dictionary, error) {
	decoder := json.NewDecoder(io.LimitReader(r, maxDictionaryFileBytes))
	decoder.DisallowUnknownFields()
	var document dictionaryDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("binary: decode dictionary: %w", err)
	}
	return NewDictionaryFromTokens(document.Single, document.Double)
}
