package binary

import (
	"bytes"
	"strings"
	"testing"
)

func TestDictionaryValidation(t *testing.T) {
	d := NewDictionary()
	if err := d.SetSingle(0, "x"); err == nil {
		t.Fatal("index 0 must be rejected")
	}
	if err := d.SetSingle(1, "x"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetSingle(236, "x"); err == nil {
		t.Fatal("structural token range must be rejected")
	}
	if err := d.SetDouble(4, 0, "x"); err == nil {
		t.Fatal("dictionary 4 must be rejected")
	}
	if err := d.SetDouble(0, 0, "y"); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Single(0); ok {
		t.Fatal("index 0 has no token")
	}
	if err := d.SetSingle(2, "x"); err != nil {
		t.Fatal(err)
	}
	if index, ok := d.IndexSingle("x"); !ok || index != 2 {
		t.Fatalf("IndexSingle(x) = %d, %v", index, ok)
	}
	if dict, index, ok := d.IndexDouble("y"); !ok || dict != 0 || index != 0 {
		t.Fatalf("IndexDouble(y) = %d, %d, %v", dict, index, ok)
	}

	if _, err := NewDictionaryFromTokens(make([]string, 240), nil); err == nil {
		t.Fatal("too many single tokens must be rejected")
	}
	if _, err := NewDictionaryFromTokens(nil, make([][]string, 5)); err == nil {
		t.Fatal("too many double dictionaries must be rejected")
	}
	if _, err := NewDictionaryFromTokens(nil, [][]string{make([]string, 257)}); err == nil {
		t.Fatal("too many double tokens must be rejected")
	}
}

func TestLargeValues(t *testing.T) {
	codec := NewCodec(testDictionary(t))

	var children []Node
	for i := 0; i < 300; i++ {
		children = append(children, Node{Tag: "n", Bytes: []byte{byte(i)}})
	}
	longString := strings.Repeat("x", 300)
	bigBytes := bytes.Repeat([]byte{0xAB}, 1<<20+1)

	nodes := []*Node{
		{Tag: "list", Children: children},
		{Tag: "message", Attrs: Attrs{"message": longString}},
		{Tag: "media", Bytes: bigBytes},
	}
	for _, want := range nodes {
		data, err := codec.Encode(want)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, err := codec.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Tag != want.Tag || len(got.Children) != len(want.Children) || !bytes.Equal(got.Bytes, want.Bytes) {
			t.Fatalf("round trip mismatch for %q", want.Tag)
		}
		if want.Attrs != nil && got.Attrs["message"] != want.Attrs["message"] {
			t.Fatalf("string mismatch: %d vs %d bytes", len(got.Attrs["message"]), len(want.Attrs["message"]))
		}
	}
}

func TestPackedOddLengths(t *testing.T) {
	codec := NewCodec(testDictionary(t))
	want := &Node{Tag: "message", Attrs: Attrs{"id": "ABC", "type": "123"}}
	data, err := codec.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := codec.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.Attrs["id"] != "ABC" || got.Attrs["type"] != "123" {
		t.Fatalf("odd packed values: %#v", got.Attrs)
	}
}
