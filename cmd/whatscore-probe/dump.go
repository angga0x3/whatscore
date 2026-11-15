package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	wabinary "github.com/angga0x3/whatscore/protocol/binary"
)

// dumpUndecoded decodes one saved frame from undecoded/ against the token
// table, now that the table has grown past it, and prints the tree. It exists
// because the .bin files are the only record of stanzas the table could not
// read yet; recovering their shape is how the table earns its next entries.
func dumpUndecoded(dictPath, framePath string) error {
	dict, err := loadDictionary(dictPath)
	if err != nil {
		return err
	}
	codec := wabinary.NewCodec(holeFilled(dict))
	raw, err := os.ReadFile(framePath)
	if err != nil {
		return err
	}
	node, err := codec.Decode(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("still undecodable: %w\nraw: %s", err, hex.Dump(raw))
	}
	var dump func(n *wabinary.Node, depth int)
	dump = func(n *wabinary.Node, depth int) {
		indent := ""
		for i := 0; i < depth; i++ {
			indent += "  "
		}
		fmt.Printf("%s<%s> %v bytes=%q\n", indent, n.Tag, n.Attrs, string(n.Bytes))
		for i := range n.Children {
			dump(&n.Children[i], depth+1)
		}
	}
	dump(node, 0)
	return nil
}

// holeFilled returns the dictionary with every missing slot replaced by a
// placeholder that names its position (¿s153, ¿d1[158]). A frame the table
// almost covers then decodes far enough to show its shape, and the
// placeholders name the exact entries to record in the table afterwards.
func holeFilled(dict *wabinary.Dictionary) *wabinary.Dictionary {
	for i := 1; i <= 235; i++ {
		if _, ok := dict.Single(byte(i)); !ok {
			_ = dict.SetSingle(byte(i), fmt.Sprintf("¿s%d", i))
		}
	}
	for dIndex := 0; dIndex < 4; dIndex++ {
		for i := 0; i < 256; i++ {
			if _, ok := dict.Double(byte(dIndex), byte(i)); !ok {
				_ = dict.SetDouble(byte(dIndex), byte(i), fmt.Sprintf("¿d%d[%d]", dIndex, i))
			}
		}
	}
	return dict
}
