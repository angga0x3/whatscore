package binary

import (
	"fmt"
	"sort"
	"strings"
)

const frameFlagNone = 0

type codec struct {
	dict *Dictionary
}

// NewCodec returns a Codec using dict; nil means DefaultDictionary.
func NewCodec(dict *Dictionary) Codec {
	if dict == nil {
		dict = DefaultDictionary()
	}
	return &codec{dict: dict}
}

// Encode serializes n with the uncompressed frame flag (PF-010).
func (c *codec) Encode(n *Node) ([]byte, error) {
	e := &encoder{dict: c.dict, buf: []byte{frameFlagNone}}
	if err := e.writeNode(n, 0); err != nil {
		return nil, err
	}
	return e.buf, nil
}

type encoder struct {
	dict  *Dictionary
	buf   []byte
	nodes int
}

func (e *encoder) writeNode(n *Node, depth int) error {
	if n == nil || n.Tag == "" {
		return fmt.Errorf("%w: empty tag", ErrInvalidNode)
	}
	if len(n.Children) > 0 && n.Bytes != nil {
		return fmt.Errorf("%w: node %q has both children and bytes", ErrInvalidNode, n.Tag)
	}
	if depth > MaxDepth || e.nodes >= MaxNodes {
		return fmt.Errorf("%w: node tree exceeds depth or node limit", ErrTooLarge)
	}
	e.nodes++

	content := len(n.Children) > 0 || n.Bytes != nil
	if len(n.Attrs) > (MaxChildCount-1)/2 {
		return fmt.Errorf("%w: node %q has too many attributes", ErrTooLarge, n.Tag)
	}
	size := 1 + 2*len(n.Attrs)
	if content {
		size++
	}
	if err := e.writeListStart(size); err != nil {
		return err
	}
	if err := e.writeString(n.Tag); err != nil {
		return err
	}

	keys := make([]string, 0, len(n.Attrs))
	for key := range n.Attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := e.writeString(key); err != nil {
			return err
		}
		if err := e.writeString(n.Attrs[key]); err != nil {
			return err
		}
	}

	if len(n.Children) > 0 {
		if len(n.Children) > MaxChildCount {
			return fmt.Errorf("%w: %d children", ErrTooLarge, len(n.Children))
		}
		if err := e.writeListStart(len(n.Children)); err != nil {
			return err
		}
		for i := range n.Children {
			if err := e.writeNode(&n.Children[i], depth+1); err != nil {
				return err
			}
		}
	} else if n.Bytes != nil {
		if err := e.writeByteLength(len(n.Bytes)); err != nil {
			return err
		}
		e.buf = append(e.buf, n.Bytes...)
	}
	return e.checkSize()
}

func (e *encoder) checkSize() error {
	if len(e.buf) > MaxNodeBytes {
		return fmt.Errorf("%w: encoded node exceeds %d bytes", ErrTooLarge, MaxNodeBytes)
	}
	return nil
}

func (e *encoder) writeListStart(size int) error {
	switch {
	case size == 0:
		e.buf = append(e.buf, tagListEmpty)
	case size < 256:
		e.buf = append(e.buf, tagList8, byte(size))
	default:
		e.buf = append(e.buf, tagList16, byte(size>>8), byte(size))
	}
	return e.checkSize()
}

func (e *encoder) writeString(s string) error {
	if s == "" {
		return e.writeByteLength(0)
	}
	if index, ok := e.dict.IndexSingle(s); ok {
		e.buf = append(e.buf, index)
		return e.checkSize()
	}
	if dict, index, ok := e.dict.IndexDouble(s); ok {
		e.buf = append(e.buf, tagDictionary0+dict, index)
		return e.checkSize()
	}
	if isNibble(s) {
		return e.writePacked(s, tagNibble8)
	}
	if isHex(s) {
		return e.writePacked(s, tagHex8)
	}
	if user, server, ok := splitJID(s); ok {
		e.buf = append(e.buf, tagJIDPair)
		if user == "" {
			e.buf = append(e.buf, tagListEmpty)
		} else if err := e.writeString(user); err != nil {
			return err
		}
		return e.writeString(server)
	}
	data := []byte(s)
	if err := e.writeByteLength(len(data)); err != nil {
		return err
	}
	e.buf = append(e.buf, data...)
	return e.checkSize()
}

func (e *encoder) writeByteLength(length int) error {
	if length > MaxNodeBytes {
		return fmt.Errorf("%w: string of %d bytes", ErrTooLarge, length)
	}
	switch {
	case length < 256:
		e.buf = append(e.buf, tagBinary8, byte(length))
	case length < 1<<20:
		e.buf = append(e.buf, tagBinary20, byte(length>>16), byte(length>>8), byte(length))
	default:
		e.buf = append(e.buf, tagBinary32,
			byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	}
	return e.checkSize()
}

func (e *encoder) writePacked(s string, tag byte) error {
	e.buf = append(e.buf, tag)
	rounded := (len(s) + 1) / 2
	if len(s)%2 != 0 {
		rounded |= 0x80
	}
	e.buf = append(e.buf, byte(rounded))
	for i := 0; i < len(s); i += 2 {
		var b byte
		if tag == tagNibble8 {
			b = packNibble(s[i]) << 4
		} else {
			b = packHex(s[i]) << 4
		}
		if i+1 < len(s) {
			if tag == tagNibble8 {
				b |= packNibble(s[i+1])
			} else {
				b |= packHex(s[i+1])
			}
		} else if tag == tagNibble8 {
			b |= 0x0f
		} else {
			b |= 0x0f
		}
		e.buf = append(e.buf, b)
	}
	return e.checkSize()
}

func isNibble(s string) bool {
	if len(s) > packedMax {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	if len(s) > packedMax {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func packNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c == '-':
		return 10
	case c == '.':
		return 11
	default:
		return 15
	}
}

func packHex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return 10 + c - 'A'
	default:
		return 15
	}
}

// splitJID accepts user@server strings with exactly one '@', a non-empty
// server, and no whitespace. The user part may be empty.
func splitJID(s string) (user, server string, ok bool) {
	at := strings.IndexByte(s, '@')
	if at < 0 || at != strings.LastIndexByte(s, '@') {
		return "", "", false
	}
	server = s[at+1:]
	if server == "" || strings.ContainsAny(s, " \t\r\n") {
		return "", "", false
	}
	return s[:at], server, true
}
