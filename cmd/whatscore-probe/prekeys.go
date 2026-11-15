package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"

	wabinary "github.com/angga0x3/whatscore/protocol/binary"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// describeError renders an iq error child so a rejection says why.
func describeError(node *wabinary.Node) string {
	for i := range node.Children {
		if node.Children[i].Tag == "error" {
			if text := node.Children[i].Attrs["text"]; text != "" {
				return fmt.Sprintf("code=%s text=%s", node.Children[i].Attrs["code"], text)
			}
			return fmt.Sprintf("code=%s", node.Children[i].Attrs["code"])
		}
	}
	return "no error child"
}

// parsePreKeyResponse turns the key reply into a bundle this project can use.
func parsePreKeyResponse(reply *wabinary.Node, jid string) (*signal.PreKeyBundle, error) {
	user := findUserNode(reply, jid)
	if user == nil {
		return nil, fmt.Errorf("key reply has no user node for %s", jid)
	}
	for i := range user.Children {
		if user.Children[i].Tag == "error" {
			return nil, fmt.Errorf("server reports no keys for %s: %s", jid, describeError(user))
		}
	}

	registrationRaw := childBytes(user, "registration")
	if len(registrationRaw) != 4 {
		return nil, fmt.Errorf("registration id is %d bytes, want 4", len(registrationRaw))
	}
	// The peer's registration id is validated and then dropped: the bundle type
	// has no field for it because X3DH never uses it. Keeping the length check
	// still catches a malformed reply.
	_ = binary.BigEndian.Uint32(registrationRaw)
	bundle := &signal.PreKeyBundle{}

	identityRaw := childBytes(user, "identity")
	if len(identityRaw) != signal.KeySize {
		return nil, fmt.Errorf("identity key is %d bytes, want %d", len(identityRaw), signal.KeySize)
	}
	copy(bundle.IdentityKey[:], identityRaw)

	signed, err := parseKeyNode(child(user, "skey"))
	if err != nil {
		return nil, fmt.Errorf("signed prekey: %w", err)
	}
	if len(signed.signature) != signal.SignatureSize {
		return nil, fmt.Errorf("signed prekey signature is %d bytes, want %d", len(signed.signature), signal.SignatureSize)
	}
	bundle.SignedPreKeyID = signed.id
	bundle.SignedPreKey = signed.value
	bundle.SignedPreKeySignature = signed.signature

	if oneTime := child(user, "key"); oneTime != nil {
		parsed, err := parseKeyNode(oneTime)
		if err != nil {
			return nil, fmt.Errorf("one-time prekey: %w", err)
		}
		bundle.OneTimePreKeyID = parsed.id
		value := parsed.value
		bundle.OneTimePreKey = &value
	}
	return bundle, nil
}

type parsedKey struct {
	id        uint32
	value     [signal.KeySize]byte
	signature []byte
}

// parseKeyNode reads <key id value signature> or <skey id value signature>.
func parseKeyNode(node *wabinary.Node) (parsedKey, error) {
	var out parsedKey
	if node == nil {
		return out, fmt.Errorf("missing key node")
	}
	idRaw := childBytes(node, "id")
	if len(idRaw) == 0 || len(idRaw) > 4 {
		return out, fmt.Errorf("key id is %d bytes", len(idRaw))
	}
	var idBytes [4]byte
	copy(idBytes[4-len(idRaw):], idRaw)
	out.id = binary.BigEndian.Uint32(idBytes[:])

	value := childBytes(node, "value")
	if len(value) != signal.KeySize {
		return out, fmt.Errorf("key value is %d bytes, want %d", len(value), signal.KeySize)
	}
	copy(out.value[:], value)
	out.signature = childBytes(node, "signature")
	return out, nil
}

// findUserNode locates the user entry, tolerating both <list><user> and a
// direct <user> reply.
func findUserNode(reply *wabinary.Node, jid string) *wabinary.Node {
	if user := child(reply, "user"); user != nil {
		return user
	}
	list := child(reply, "list")
	if list == nil {
		return nil
	}
	for i := range list.Children {
		if list.Children[i].Tag != "user" {
			continue
		}
		// A reply may carry several users; match on jid when present.
		if got := list.Children[i].Attrs["jid"]; got == "" || got == jid {
			return &list.Children[i]
		}
	}
	return nil
}

func child(node *wabinary.Node, tag string) *wabinary.Node {
	for i := range node.Children {
		if node.Children[i].Tag == tag {
			return &node.Children[i]
		}
	}
	return nil
}

func childBytes(node *wabinary.Node, tag string) []byte {
	sub := child(node, tag)
	if sub == nil {
		return nil
	}
	return sub.Bytes
}

// randomID returns a fresh request id for stanzas that need one.
func randomID() (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(buf[0])<<24|uint64(buf[1])<<16|uint64(buf[2])<<8|uint64(buf[3]), 10), nil
}
