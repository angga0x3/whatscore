package binary

import (
	"bytes"
	"testing"
)

// benchNode is a realistic text-message stanza: token tag, two attributes,
// one child with bytes content.
func benchNode() *Node {
	return &Node{
		Tag:   "message",
		Attrs: Attrs{"id": "3EB0C8F1D2A4B5C6D7E8", "to": "628123456789@s.whatsapp.net", "type": "text"},
		Children: []Node{
			{Tag: "body", Bytes: []byte("halo dunia, ini pesan percobaan")},
		},
	}
}

func BenchmarkEncode(b *testing.B) {
	codec := NewCodec(syntheticDictionary())
	node := benchNode()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := codec.Encode(node); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	codec := NewCodec(syntheticDictionary())
	frame, err := codec.Encode(benchNode())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		if _, err := codec.Decode(bytes.NewReader(frame)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	codec := NewCodec(syntheticDictionary())
	node := benchNode()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		frame, err := codec.Encode(node)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := codec.Decode(bytes.NewReader(frame)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeLargeMedia(b *testing.B) {
	codec := NewCodec(syntheticDictionary())
	node := &Node{Tag: "media", Bytes: bytes.Repeat([]byte{0xAB}, 64<<10)}
	b.SetBytes(int64(len(node.Bytes)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := codec.Encode(node); err != nil {
			b.Fatal(err)
		}
	}
}
