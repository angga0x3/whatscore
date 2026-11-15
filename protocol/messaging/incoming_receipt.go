package messaging

import (
	"fmt"
	"strconv"
	"time"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// IncomingReceipt is a receipt received from a peer or group participant.
type IncomingReceipt struct {
	ID        string
	From      JID
	Type      string
	Timestamp time.Time
}

// ParseIncomingReceipt parses a single-id <receipt from id [type] [t]>.
func ParseIncomingReceipt(node *binary.Node) (*IncomingReceipt, error) {
	receipts, err := ParseIncomingReceipts(node)
	if err != nil {
		return nil, err
	}
	return &receipts[0], nil
}

// ParseIncomingReceipts parses a receipt stanza, including batched ids in a
// <list><item id=.../></list> child.
func ParseIncomingReceipts(node *binary.Node) ([]IncomingReceipt, error) {
	if node == nil || node.Tag != tagReceipt {
		return nil, fmt.Errorf("%w: expected %q, got %s", ErrInvalidReceipt, tagReceipt, tagOf(node))
	}
	from, err := ParseJID(node.Attrs["from"])
	if err != nil {
		return nil, fmt.Errorf("%w: from: %w", ErrInvalidReceipt, err)
	}
	if from.User == "" {
		return nil, fmt.Errorf("%w: from %q has no user", ErrInvalidReceipt, from)
	}

	base := IncomingReceipt{From: from, Type: node.Attrs["type"]}
	if raw := node.Attrs["t"]; raw != "" {
		seconds, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: t %q is not unix seconds", ErrInvalidReceipt, raw)
		}
		base.Timestamp = time.Unix(seconds, 0).UTC()
	}

	ids := make([]string, 0, 2)
	if id := node.Attrs["id"]; id != "" {
		if err := validateMessageID(id); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidReceipt, err)
		}
		ids = append(ids, id)
	}
	if list := firstChild(node, tagList); list != nil {
		for i := range list.Children {
			item := &list.Children[i]
			if item.Tag != "item" {
				continue
			}
			id := item.Attrs["id"]
			if err := validateMessageID(id); err != nil {
				return nil, fmt.Errorf("%w: list item: %w", ErrInvalidReceipt, err)
			}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: receipt has no id", ErrInvalidReceipt)
	}

	receipts := make([]IncomingReceipt, 0, len(ids))
	for _, id := range ids {
		receipt := base
		receipt.ID = id
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}
