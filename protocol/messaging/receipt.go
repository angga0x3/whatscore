package messaging

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/angga0x3/whatscore/protocol/binary"
)

const (
	tagReceipt = "receipt"
	tagList    = "list"
	attrT      = "t"
)

// Receipt type values (PF-035). ReceiptTypeDelivered is the empty string: the
// reference omits the type attribute for plain delivery receipts.
const (
	ReceiptTypeDelivered   = ""
	ReceiptTypeSender      = "sender"
	ReceiptTypeRetry       = "retry"
	ReceiptTypeRead        = "read"
	ReceiptTypeReadSelf    = "read-self"
	ReceiptTypePlayed      = "played"
	ReceiptTypePlayedSelf  = "played-self"
	ReceiptTypeServerError = "server-error"
	ReceiptTypeInactive    = "inactive"
	ReceiptTypePeerMsg     = "peer_msg"
	ReceiptTypeHistorySync = "hist_sync"
)

// ErrInvalidReceipt is returned for malformed receipt stanzas.
var ErrInvalidReceipt = errors.New("messaging: invalid receipt stanza")

// Receipt is a <receipt id type to> stanza (PF-035).
//
// Type is written only when non-empty. Participant is written only when set
// (group receipts). Timestamp is written as the unix-seconds "t" attribute
// when non-zero and is parsed back in UTC.
type Receipt struct {
	ID          string
	To          JID
	Type        string
	Participant JID
	Timestamp   time.Time
}

// BuildReceipt builds the outbound receipt stanza. ID and To are required;
// every other field is optional.
func BuildReceipt(r Receipt) (*binary.Node, error) {
	if err := r.To.validateAddress(); err != nil {
		return nil, fmt.Errorf("%w: to: %w", ErrInvalidReceipt, err)
	}
	if r.ID == "" {
		return nil, fmt.Errorf("%w: empty id", ErrInvalidReceipt)
	}

	attrs := binary.Attrs{"id": r.ID, "to": r.To.String()}
	if r.Type != "" {
		attrs["type"] = r.Type
	}
	if !r.Participant.IsEmpty() {
		if err := r.Participant.validateAddress(); err != nil {
			return nil, fmt.Errorf("%w: participant: %w", ErrInvalidReceipt, err)
		}
		attrs["participant"] = r.Participant.String()
	}
	if !r.Timestamp.IsZero() {
		attrs[attrT] = strconv.FormatInt(r.Timestamp.Unix(), 10)
	}
	return &binary.Node{Tag: tagReceipt, Attrs: attrs}, nil
}

// ParseReceipt reads a receipt stanza produced by BuildReceipt.
//
// The reference batches additional message IDs in a <list> child; that form
// is refused rather than silently truncated. Receipts received from the
// server carry "from" instead of "to" and belong to the event layer, not
// this parser.
func ParseReceipt(node *binary.Node) (*Receipt, error) {
	if node == nil || node.Tag != tagReceipt {
		return nil, fmt.Errorf("%w: expected %q, got %s", ErrInvalidReceipt, tagReceipt, tagOf(node))
	}
	if list := firstChild(node, tagList); list != nil {
		return nil, fmt.Errorf("%w: batched receipt with %d extra ids", ErrInvalidReceipt, len(list.Children))
	}

	id := node.Attrs["id"]
	if id == "" {
		return nil, fmt.Errorf("%w: empty id", ErrInvalidReceipt)
	}
	to, err := ParseJID(node.Attrs["to"])
	if err != nil {
		return nil, fmt.Errorf("%w: to: %w", ErrInvalidReceipt, err)
	}
	if to.User == "" {
		return nil, fmt.Errorf("%w: to %q has no user", ErrInvalidReceipt, to)
	}

	receipt := &Receipt{ID: id, To: to, Type: node.Attrs["type"]}

	if participant := node.Attrs["participant"]; participant != "" {
		receipt.Participant, err = ParseJID(participant)
		if err != nil {
			return nil, fmt.Errorf("%w: participant: %w", ErrInvalidReceipt, err)
		}
		if receipt.Participant.User == "" {
			return nil, fmt.Errorf("%w: participant %q has no user", ErrInvalidReceipt, participant)
		}
	}

	if raw := node.Attrs[attrT]; raw != "" {
		seconds, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: t %q is not unix seconds", ErrInvalidReceipt, raw)
		}
		receipt.Timestamp = time.Unix(seconds, 0).UTC()
	}

	return receipt, nil
}
