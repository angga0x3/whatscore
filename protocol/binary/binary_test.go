package binary

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func syntheticDictionary() *Dictionary {
	d, err := NewDictionaryFromTokens(
		[]string{"", "s.whatsapp.net", "type", "id", "message", "from", "to", "get"},
		[][]string{{"read-self", "reaction"}, {"w:gp2"}},
	)
	if err != nil {
		panic(err)
	}
	return d
}

func testDictionary(t *testing.T) *Dictionary {
	t.Helper()
	return syntheticDictionary()
}

func TestRoundTrip(t *testing.T) {
	codec := NewCodec(testDictionary(t))
	nodes := []*Node{
		{Tag: "ping"},
		{Tag: "message", Attrs: Attrs{"type": "text", "id": "ABC123"}},
		{Tag: "message", Attrs: Attrs{"to": "628123@s.whatsapp.net", "from": "read-self"}},
		{Tag: "list", Attrs: Attrs{"type": "123-45.6", "id": "DEADBEEF", "message": "hello world"}},
		{Tag: "iq", Children: []Node{{Tag: "ping"}, {Tag: "get", Attrs: Attrs{"id": ""}}}},
		{Tag: "media", Bytes: []byte{0x00, 0xff, 0x10}},
		{Tag: "media", Bytes: []byte{}},
	}
	for _, want := range nodes {
		data, err := codec.Encode(want)
		if err != nil {
			t.Fatalf("encode %q: %v", want.Tag, err)
		}
		got, err := codec.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode %q: %v", want.Tag, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round trip mismatch for %q:\n got %#v\nwant %#v", want.Tag, got, want)
		}
	}
}

func TestDeterministicAttributeOrder(t *testing.T) {
	codec := NewCodec(testDictionary(t))
	a := &Node{Tag: "message", Attrs: Attrs{"z": "1", "a": "2", "m": "3"}}
	b := &Node{Tag: "message", Attrs: Attrs{"m": "3", "z": "1", "a": "2"}}
	first, err := codec.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := codec.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("attribute insertion order changed the output")
	}
	again, err := codec.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("encoding is not deterministic")
	}
}

type goldenFile struct {
	Dictionary struct {
		Single []string   `json:"single"`
		Double [][]string `json:"double"`
	} `json:"dictionary"`
	Vectors []struct {
		Name string     `json:"name"`
		Hex  string     `json:"hex"`
		Node goldenNode `json:"node"`
	} `json:"vectors"`
}

type goldenNode struct {
	Tag      string            `json:"tag"`
	Attrs    map[string]string `json:"attrs"`
	Children []goldenNode      `json:"children"`
	Bytes    *string           `json:"bytes_base64"`
}

func (g goldenNode) node(t *testing.T) *Node {
	t.Helper()
	n := &Node{Tag: g.Tag, Attrs: g.Attrs}
	for _, child := range g.Children {
		n.Children = append(n.Children, *child.node(t))
	}
	if g.Bytes != nil {
		raw, err := base64.StdEncoding.DecodeString(*g.Bytes)
		if err != nil {
			t.Fatalf("decode fixture bytes: %v", err)
		}
		n.Bytes = raw
	}
	return n
}

func TestGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("../../tests/fixtures/binary_vectors.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fixtures goldenFile
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	dict, err := NewDictionaryFromTokens(fixtures.Dictionary.Single, fixtures.Dictionary.Double)
	if err != nil {
		t.Fatalf("fixture dictionary: %v", err)
	}
	codec := NewCodec(dict)
	if len(fixtures.Vectors) == 0 {
		t.Fatal("fixture file has no vectors")
	}
	for _, vector := range fixtures.Vectors {
		wantBytes, err := hex.DecodeString(vector.Hex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", vector.Name, err)
		}
		want := vector.Node.node(t)
		got, err := codec.Decode(bytes.NewReader(wantBytes))
		if err != nil {
			t.Fatalf("%s: decode: %v", vector.Name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: decoded node mismatch\n got %#v\nwant %#v", vector.Name, got, want)
		}
		encoded, err := codec.Encode(want)
		if err != nil {
			t.Fatalf("%s: encode: %v", vector.Name, err)
		}
		if !bytes.Equal(encoded, wantBytes) {
			t.Fatalf("%s: encoded bytes differ\n got %x\nwant %x", vector.Name, encoded, wantBytes)
		}
	}
}

func TestDecodeCompressedFrame(t *testing.T) {
	codec := NewCodec(testDictionary(t))
	want := &Node{Tag: "message", Attrs: Attrs{"type": "text"}, Children: []Node{{Tag: "body", Bytes: []byte("hello")}}}
	plain, err := codec.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(plain[1:]); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	frame := append([]byte{2}, compressed.Bytes()...)
	got, err := codec.Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decode compressed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compressed round trip mismatch: %#v", got)
	}
}

func TestDecodeErrors(t *testing.T) {
	codec := NewCodec(testDictionary(t))
	emptyDict := NewCodec(NewDictionary())

	valid, err := codec.Encode(&Node{Tag: "ping"})
	if err != nil {
		t.Fatal(err)
	}

	deep := []byte{0xF8, 0x01, 0xFC, 0x01, 'a'}
	for i := 0; i < MaxDepth+2; i++ {
		deep = append([]byte{0xF8, 0x02, 0xFC, 0x01, 'a', 0xF8, 0x01}, deep...)
	}

	cases := []struct {
		name  string
		codec Codec
		frame []byte
		want  error
	}{
		{"empty", codec, nil, ErrTruncated},
		{"flag only", codec, []byte{0}, ErrTruncated},
		{"unknown token", emptyDict, []byte{0, 0xF8, 0x01, 0x01}, ErrUnknownToken},
		{"bad list tag", codec, []byte{0, 0x01}, ErrInvalidNode},
		{"trailing bytes", codec, append(append([]byte{}, valid...), 0x00), ErrInvalidNode},
		{"deep nesting", codec, append([]byte{0}, deep...), ErrTooLarge},
		{"oversized content", codec, []byte{0, 0xF8, 0x02, 0xFC, 0x01, 'a', 0xFE, 0xFF, 0xFF, 0xFF, 0xFF}, ErrTooLarge},
		{"bad zlib", codec, []byte{2, 0xFF, 0xFF}, ErrInvalidNode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.codec.Decode(bytes.NewReader(tc.frame))
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestEncodeErrors(t *testing.T) {
	codec := NewCodec(testDictionary(t))
	cases := []struct {
		name string
		node *Node
		want error
	}{
		{"nil", nil, ErrInvalidNode},
		{"empty tag", &Node{}, ErrInvalidNode},
		{"children and bytes", &Node{Tag: "a", Children: []Node{{Tag: "b"}}, Bytes: []byte("x")}, ErrInvalidNode},
		{"too deep", deepNode(MaxDepth + 2), ErrTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := codec.Encode(tc.node)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func deepNode(depth int) *Node {
	n := &Node{Tag: "a"}
	for i := 0; i < depth; i++ {
		n = &Node{Tag: "a", Children: []Node{*n}}
	}
	return n
}

func TestJIDWireForms(t *testing.T) {
	codec := NewCodec(testDictionary(t))
	raw := func(s string) []byte { return append([]byte{0xFC, byte(len(s))}, s...) }

	cases := []struct {
		name  string
		value []byte
		want  string
	}{
		{"jid pair", append([]byte{0xFA}, append(raw("123"), raw("s.whatsapp.net")...)...), "123@s.whatsapp.net"},
		// The reference renders a userless JID as the bare server name; this
		// package keeps the empty user so decode/encode stays byte-identical,
		// which the pairing acknowledgement depends on.
		{"jid pair empty user", append([]byte{0xFA}, append([]byte{0x00}, raw("s.whatsapp.net")...)...), "@s.whatsapp.net"},
		{"ad jid", append([]byte{0xF7, 0x00, 0x00}, raw("123")...), "123@s.whatsapp.net"},
		{"ad jid device", append([]byte{0xF7, 0x01, 0x02}, raw("123")...), "123:2@lid"},
		{"fb jid", append([]byte{0xF6}, append(raw("123"), append([]byte{0x00, 0x02}, raw("messenger")...)...)...), "123:2@messenger"},
		{"interop jid", append([]byte{0xF5}, append(raw("123"), append([]byte{0x00, 0x02, 0x00, 0x07}, raw("interop")...)...)...), "7-123:2@interop"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := []byte{0, 0xF8, 0x03, 0xFC, 0x01, 'a', 0xFC, 0x01, 'k'}
			frame = append(frame, tc.value...)
			node, err := codec.Decode(bytes.NewReader(frame))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := node.Attrs["k"]; got != tc.want {
				t.Fatalf("attr = %q, want %q", got, tc.want)
			}
		})
	}
}
