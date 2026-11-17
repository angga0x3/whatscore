package main

import (
	"testing"

	stanza "github.com/angga0x3/whatscore/protocol/messaging"
)

// TestMediaKindFor pins the MIME → kind table the probe sends: images travel
// as imageMessage, everything else as a document. The media key type follows
// the kind, because stickers and images share the image envelope but a
// document does not.
func TestMediaKindFor(t *testing.T) {
	cases := map[string]stanza.PayloadKind{
		"image/jpeg":               stanza.PayloadImage,
		"image/png":                stanza.PayloadImage,
		"application/pdf":          stanza.PayloadDocument,
		"text/plain":               stanza.PayloadDocument,
		"application/octet-stream": stanza.PayloadDocument,
		"application/vnd.ms-excel": stanza.PayloadDocument,
	}
	for mimeType, want := range cases {
		kind, keyType, err := mediaKindFor(mimeType)
		if err != nil {
			t.Fatalf("mediaKindFor(%q): %v", mimeType, err)
		}
		if kind != want {
			t.Fatalf("mediaKindFor(%q) = %q, want %q", mimeType, kind, want)
		}
		if keyType == "" {
			t.Fatalf("mediaKindFor(%q) returned no key type", mimeType)
		}
	}
	if _, _, err := mediaKindFor("video/mp4"); err == nil {
		t.Fatal("video accepted without a probe flag for it")
	}
}

// TestBuildOutgoingNeedsContent keeps an empty send loud instead of putting an
// empty conversation on the wire.
func TestBuildOutgoingNeedsContent(t *testing.T) {
	if _, _, err := buildOutgoing(t.Context(), nil, sendConfig{}); err == nil {
		t.Fatal("empty send accepted")
	}
}

// TestBuildOutgoingText pins the text half: one conversation field and the
// text stanza class.
func TestBuildOutgoingText(t *testing.T) {
	message, msgType, err := buildOutgoing(t.Context(), nil, sendConfig{Text: "halo"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if message.GetConversation() != "halo" {
		t.Fatalf("conversation = %q", message.GetConversation())
	}
	if msgType != stanza.MessageTypeText {
		t.Fatalf("type = %q, want text", msgType)
	}
}
