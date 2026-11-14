// Package binary implements WhatsApp's binary node protocol: the compact,
// token-dictionary-based encoding used for every application-layer payload
// carried inside Noise-encrypted frames.
//
// The codec must be symmetric — Decode(Encode(n)) equals n — and
// deterministic: encoding a given node twice yields identical bytes.
// Encoding details (token dictionaries, list conventions, JID packing) are
// documented in docs/protocol with provenance and pinned by golden fixtures
// under tests/fixtures.
//
// Status: contract skeleton (Phase 2 implements it).
package binary

import "io"

// Attrs is a node attribute map. Decoders must accept any attribute order;
// encoders must produce deterministic output for a given node.
type Attrs map[string]string

// Node is one element of the WhatsApp binary protocol tree.
type Node struct {
	// Tag is the element name (a dictionary token or inline string on the
	// wire).
	Tag string

	// Attrs are the node's key/value attributes.
	Attrs Attrs

	// Children holds child elements. Exactly one of Children and Bytes may
	// be non-empty; a node with neither has no content.
	Children []Node

	// Bytes holds raw content when the node carries binary data instead of
	// child elements.
	Bytes []byte
}

// ErrTruncated is returned when input ends in the middle of an encoded
// node.
var ErrTruncated = io.ErrUnexpectedEOF

// Codec converts nodes to and from the wire format.
type Codec interface {
	// Encode serializes n into wire bytes.
	Encode(n *Node) ([]byte, error)

	// Decode reads exactly one encoded node from r.
	Decode(r io.Reader) (*Node, error)
}
