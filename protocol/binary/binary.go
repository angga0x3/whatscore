// Package binary implements WhatsApp's binary node protocol.
//
// The codec is symmetric (Decode(Encode(n)) == n) and deterministic:
// attributes are emitted in lexicographic key order. Wire rules are recorded
// in docs/protocol/binary.md (PF-010..PF-014) and pinned by synthetic vectors
// in tests/fixtures/binary_vectors.json.
//
// The token dictionary is injected; DefaultDictionary is empty because the
// real WhatsApp tables have an unresolved licensing question (spec §10.2).
package binary

import (
	"errors"
	"io"
)

// Attrs is a node attribute map. The encoder always sorts keys.
type Attrs map[string]string

// Node is one element of the WhatsApp binary protocol tree.
type Node struct {
	Tag      string
	Attrs    Attrs
	Children []Node
	// Bytes is the content when the node has no children. A non-nil empty
	// slice still means "content"; nil means none.
	Bytes []byte
}

// Codec converts nodes to and from the wire format.
type Codec interface {
	Encode(n *Node) ([]byte, error)
	Decode(r io.Reader) (*Node, error)
}

var (
	// ErrTruncated means the input ended mid-value.
	ErrTruncated = io.ErrUnexpectedEOF
	// ErrUnknownToken means a token is absent from the dictionary.
	ErrUnknownToken = errors.New("binary: unknown token")
	// ErrInvalidNode means the node or wire structure is malformed.
	ErrInvalidNode = errors.New("binary: invalid node")
	// ErrTooLarge means a limit was exceeded.
	ErrTooLarge = errors.New("binary: value too large")
	// ErrUnsupported means the construct is not implemented.
	ErrUnsupported = errors.New("binary: unsupported")
)

// Decode and encode limits.
const (
	MaxNodeBytes  = 1 << 24 // 16 MiB, matches the transport frame limit
	MaxDepth      = 64
	MaxNodes      = 1 << 20
	MaxChildCount = 1<<16 - 1
)
