package messaging

// Group sender keys: the per-member ratchet that makes group messages
// readable. A member distributes a chain key and a signing key once (inside a
// 1:1 carrier), then encrypts each group message once under a key derived
// from that chain and signs it (PF-093). This file holds the receiver's
// store plus the decode path; the primitives live in protocol/signal.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/angga0x3/whatscore/protocol/binary"
	stanza "github.com/angga0x3/whatscore/protocol/messaging"
	"github.com/angga0x3/whatscore/protocol/signal"
)

// SenderKey is one member's group ratchet position: the key id, the chain
// key at Iteration, and the signing key every message is verified against.
type SenderKey struct {
	ID         uint32
	Iteration  uint32
	ChainKey   [32]byte
	SigningKey [32]byte
}

// SenderKeyEntry pairs one stored key with the addresses it belongs to.
type SenderKeyEntry struct {
	Group  string
	Sender string
	Key    SenderKey
}

// senderKeyID is the map key: a group, a member, and nothing else. JIDs never
// contain a NUL byte.
func senderKeyID(group, sender string) string { return group + "\x00" + sender }

// SetSenderKey installs one member's key for a group.
func (r *Receiver) SetSenderKey(group, sender string, key *SenderKey) error {
	if key == nil {
		return fmt.Errorf("core/messaging: nil sender key")
	}
	if group == "" || sender == "" {
		return fmt.Errorf("core/messaging: sender key needs a group and a sender")
	}
	r.senderKeyMu.Lock()
	defer r.senderKeyMu.Unlock()
	if r.senderKeys == nil {
		r.senderKeys = make(map[string]*SenderKey)
	}
	copied := *key
	r.senderKeys[senderKeyID(group, sender)] = &copied
	return nil
}

// SenderKey returns a member's key for a group, if one is stored.
func (r *Receiver) SenderKey(group, sender string) (*SenderKey, bool) {
	r.senderKeyMu.Lock()
	defer r.senderKeyMu.Unlock()
	key, ok := r.senderKeys[senderKeyID(group, sender)]
	if !ok {
		return nil, false
	}
	copied := *key
	return &copied, true
}

// SenderKeyEntries returns every stored key, sorted by group then sender, for
// a caller that persists them.
func (r *Receiver) SenderKeyEntries() []SenderKeyEntry {
	r.senderKeyMu.Lock()
	defer r.senderKeyMu.Unlock()
	entries := make([]SenderKeyEntry, 0, len(r.senderKeys))
	for id, key := range r.senderKeys {
		group, sender, ok := strings.Cut(id, "\x00")
		if !ok {
			continue
		}
		entries = append(entries, SenderKeyEntry{Group: group, Sender: sender, Key: *key})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Group != entries[j].Group {
			return entries[i].Group < entries[j].Group
		}
		return entries[i].Sender < entries[j].Sender
	})
	return entries
}

// SetSenderKeyObserver installs a callback invoked whenever a key is stored
// or its chain advances, so a caller can persist it.
func (r *Receiver) SetSenderKeyObserver(fn func(group, sender string, key *SenderKey)) {
	r.senderKeyMu.Lock()
	defer r.senderKeyMu.Unlock()
	r.observeSenderKey = fn
}

// observeKey is the nil-safe notify. The caller must not hold senderKeyMu.
func (r *Receiver) observeKey(group, sender string) {
	r.senderKeyMu.Lock()
	key, ok := r.senderKeys[senderKeyID(group, sender)]
	var copied SenderKey
	if ok {
		copied = *key
	}
	observe := r.observeSenderKey
	r.senderKeyMu.Unlock()
	if observe != nil && ok {
		observe(group, sender, &copied)
	}
}

// storeSenderKey parses a distribution message and installs the key it
// carries. The sender is the peer that delivered it, because that is the
// address every later group stanza names in "participant".
func (r *Receiver) storeSenderKey(ctx context.Context, sender stanza.JID, share *stanza.SenderKeyShare) {
	if share == nil || len(share.Raw) == 0 {
		return
	}
	group := share.GroupID
	if group == "" {
		r.logger.WarnContext(ctx, "sender key distribution names no group", "sender", sender.String())
		return
	}
	distribution, err := signal.ParseSenderKeyDistribution(share.Raw)
	if err != nil {
		r.logger.WarnContext(ctx, "unreadable sender key distribution", "group", group, "sender", sender.String(), "error", err)
		return
	}
	key := &SenderKey{
		ID:         distribution.ID,
		Iteration:  distribution.Iteration,
		ChainKey:   distribution.ChainKey,
		SigningKey: distribution.SigningKey,
	}
	if err := r.SetSenderKey(group, sender.String(), key); err != nil {
		r.logger.WarnContext(ctx, "could not store sender key", "group", group, "sender", sender.String(), "error", err)
		return
	}
	r.logger.InfoContext(ctx, "sender key stored", "group", group, "sender", sender.String(), "iteration", key.Iteration)
	r.observeKey(group, sender.String())
}

// handleSenderKeyMessage decrypts one <enc type="skmsg"> child of a group
// stanza: verify the member's signature, derive the iteration's keys, open
// the ciphertext, and publish it in the group chat.
func (r *Receiver) handleSenderKeyMessage(ctx context.Context, node *binary.Node, group, participant stanza.JID) {
	enc := encChildOfCarrier(node, stanza.CarrierSKMsg)
	r.logger.DebugContext(ctx, "group ciphertext", "group", group.String(), "sender", participant.String(), "found", enc != nil)
	if enc == nil {
		return
	}
	message, err := signal.ParseSenderKeyMessage(enc.Bytes)
	if err != nil {
		r.logger.WarnContext(ctx, "unreadable group message", "group", group.String(), "sender", participant.String(), "error", err)
		return
	}
	key, ok := r.SenderKey(group.String(), participant.String())
	if !ok {
		// The distribution rides a separate 1:1 child of the same stanza and
		// may not have been processed yet (or at all, on a device that just
		// joined). The message is recoverable: sender keys are re-distributed
		// and the server keeps group traffic it has no receipt for.
		r.logger.WarnContext(ctx, "group message without a sender key", "group", group.String(), "sender", participant.String(), "iteration", message.Iteration)
		return
	}
	if message.ID != key.ID {
		r.logger.WarnContext(ctx, "group message for an unknown sender key id", "group", group.String(), "sender", participant.String(), "want", key.ID, "got", message.ID)
		return
	}
	if err := message.Verify(key.SigningKey); err != nil {
		r.logger.WarnContext(ctx, "group message signature refused", "group", group.String(), "sender", participant.String(), "error", err)
		return
	}
	chain := signal.SenderChain{Iteration: key.Iteration, Key: key.ChainKey}
	advanced, err := chain.Advance(message.Iteration)
	if err != nil {
		r.logger.WarnContext(ctx, "group message iteration refused", "group", group.String(), "sender", participant.String(), "iteration", message.Iteration, "stored", key.Iteration, "error", err)
		return
	}
	iv, cipherKey, err := advanced.MessageKey()
	if err != nil {
		r.logger.WarnContext(ctx, "group message key derivation failed", "error", err)
		return
	}
	plaintext, err := message.Decrypt(iv, cipherKey)
	if err != nil {
		r.logger.WarnContext(ctx, "group message did not open", "group", group.String(), "sender", participant.String(), "error", err)
		return
	}
	next := advanced.Next()
	advancedKey := *key
	advancedKey.Iteration = next.Iteration
	advancedKey.ChainKey = next.Key
	if err := r.SetSenderKey(group.String(), participant.String(), &advancedKey); err != nil {
		r.logger.WarnContext(ctx, "could not advance sender key", "error", err)
	} else {
		r.observeKey(group.String(), participant.String())
	}

	if plaintext, err = stanza.UnpadMessage(plaintext, "2"); err != nil {
		r.logger.WarnContext(ctx, "group message padding refused", "group", group.String(), "error", err)
		return
	}
	payload, err := stanza.DecodePayload(plaintext)
	if err != nil {
		r.logger.InfoContext(ctx, "group message carries no usable payload", "group", group.String(), "error", err)
		return
	}
	if payload.SenderKey != nil {
		r.storeSenderKey(ctx, participant, payload.SenderKey)
	}
	if payload.Kind == stanza.PayloadSenderKey {
		return
	}
	r.publishIncoming(ctx, node.Attrs["id"], participant, group, timestampOf(node), payload)
}

// encChildOfCarrier returns the first <enc> child with the given carrier.
func encChildOfCarrier(node *binary.Node, carrier string) *binary.Node {
	for i := range node.Children {
		if node.Children[i].Tag == "enc" && node.Children[i].Attrs["type"] == carrier {
			return &node.Children[i]
		}
	}
	return nil
}
