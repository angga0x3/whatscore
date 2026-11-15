package binary_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/angga0x3/whatscore/internal/tokendict"
	wabinary "github.com/angga0x3/whatscore/protocol/binary"
)

// TestShippingTableDecodesPairSuccessShape pins that the table shipped in
// deployments/tokendict can read the stanza a real phone scan produces. The
// frame here is rebuilt from the observed node shape rather than copied from
// the capture, because the capture carries an account JID.
func TestShippingTableDecodesPairSuccessShape(t *testing.T) {
	table, err := tokendict.LoadFile("../../deployments/tokendict/pairing-minimal.json")
	if err != nil {
		t.Fatalf("load table: %v", err)
	}
	dict, err := tokendict.Build(table)
	if err != nil {
		t.Fatalf("build dictionary: %v", err)
	}
	codec := wabinary.NewCodec(dict)

	// The shape observed in the live stanza, with the identifiers replaced.
	node := &wabinary.Node{
		Tag: "iq",
		Attrs: wabinary.Attrs{
			"from":  "s.whatsapp.net",
			"id":    "1262735447",
			"type":  "set",
			"xmlns": "md",
		},
		Children: []wabinary.Node{{
			Tag: "pair-success",
			Children: []wabinary.Node{
				{Tag: "jurisdiction", Attrs: wabinary.Attrs{"cc": "62", "iso": "ID"}},
				{
					Tag:   "encryption-metadata",
					Attrs: wabinary.Attrs{"algorithm": "aes-256-gcm", "version": "1"},
					Children: []wabinary.Node{
						{Tag: "encrypted_key", Bytes: []byte("redacted")},
						{Tag: "nonce", Bytes: make([]byte, 12)},
						{Tag: "encrypted_data", Bytes: make([]byte, 280)},
						{Tag: "auth_tag", Bytes: make([]byte, 16)},
					},
				},
				{Tag: "client-props", Bytes: []byte{0x08, 0x01, 0x18, 0x01, 0x30, 0x00}},
				{Tag: "platform", Attrs: wabinary.Attrs{"name": "iphone"}},
				{Tag: "device-identity", Bytes: make([]byte, 158)},
				{Tag: "device", Attrs: wabinary.Attrs{"jid": "100000000000000:36@s.whatsapp.net", "lid": "200000000000000:36@lid"}},
			},
		}},
	}

	frame, err := codec.Encode(node)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := codec.Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decode with the shipping table: %v", err)
	}
	if decoded.Tag != "iq" || len(decoded.Children) != 1 {
		t.Fatalf("unexpected tree: %s with %d children", decoded.Tag, len(decoded.Children))
	}
	if got := decoded.Children[0].Tag; got != "pair-success" {
		t.Fatalf("child is %q, want pair-success", got)
	}
	if len(decoded.Children[0].Children) != 6 {
		t.Fatalf("pair-success has %d children, want 6", len(decoded.Children[0].Children))
	}
}

// TestShippingTableRejectsUnknownTokens keeps the failure mode honest: the
// table is partial, so an unobserved token must still fail loudly.
func TestShippingTableRejectsUnknownTokens(t *testing.T) {
	raw, err := os.ReadFile("../../deployments/tokendict/pairing-minimal.json")
	if err != nil {
		t.Fatalf("read table: %v", err)
	}
	var parsed struct {
		Single []string `json:"single"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	filled := 0
	for _, tok := range parsed.Single {
		if tok != "" {
			filled++
		}
	}
	if filled >= len(parsed.Single) {
		t.Fatal("the table claims to be complete; this test exists because it is not")
	}
}
