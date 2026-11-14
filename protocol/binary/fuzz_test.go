package binary

import (
	"bytes"
	"reflect"
	"testing"
)

func FuzzDecode(f *testing.F) {
	codec := NewCodec(syntheticDictionary())
	seed, err := codec.Encode(&Node{
		Tag:   "message",
		Attrs: Attrs{"type": "text", "id": "ABC123"},
		Children: []Node{
			{Tag: "body", Bytes: []byte("hello")},
			{Tag: "to", Attrs: Attrs{"jid": "628123@s.whatsapp.net"}},
		},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0})
	f.Add([]byte{0, 0xF8, 0x01, 0xFC, 0x01, 'a'})
	f.Add([]byte{2, 0x78, 0x9C})

	f.Fuzz(func(t *testing.T, data []byte) {
		node, err := codec.Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		encoded, err := codec.Encode(node)
		if err != nil {
			t.Fatalf("decoded node failed to encode: %v", err)
		}
		again, err := codec.Decode(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("re-encoded node failed to decode: %v", err)
		}
		if !reflect.DeepEqual(node, again) {
			t.Fatalf("node changed across round trip:\n first %#v\nsecond %#v", node, again)
		}
	})
}
