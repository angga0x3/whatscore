package engine

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/angga0x3/whatscore/protocol/binary"
)

// Stanza tags of the post-handshake auth outcome (PF-028, PF-029). The tags
// and attributes are the ones the reference client dispatches in
// whatsmeow's nodeHandlers map (client.go): "success", "failure", and
// "stream:error".
const (
	tagSuccess     = "success"
	tagFailure     = "failure"
	tagStreamError = "stream:error"

	// tagAck is the only stanza WaitAuth skips. whatsmeow's frame dispatcher
	// has no handler for "ack" and deliberately does not log it as
	// unhandled, i.e. an ack may legitimately arrive at any point and carries
	// nothing this package needs.
	tagAck = "ack"
)

// maxServerTextLen caps every server-provided string (a <failure> message or
// code, a <stream:error> code, an unexpected tag) before it reaches an error
// or a log line. The server controls that text, so it is treated as untrusted
// data: truncated, with control characters stripped.
const maxServerTextLen = 120

// AuthError is the typed <failure> outcome of WaitAuth (PF-029). It unwraps
// to ErrAuthFailed, so errors.Is(err, ErrAuthFailed) keeps working while
// errors.As recovers the server's reason.
type AuthError struct {
	// Reason is the decimal value of the failure's reason attribute, or 0
	// when the attribute is absent or not a decimal integer (ReasonRaw then
	// carries the raw value). whatsmeow maps this to ConnectFailureReason.
	Reason int

	// ReasonRaw is the reason attribute as received, sanitized and capped.
	ReasonRaw string

	// Code is the secondary code attribute. whatsmeow reads it together with
	// expire for temporary-ban failures; it is empty when the server omits it.
	Code string

	// Message is the server's message attribute, sanitized and capped by
	// maxServerTextLen. It is diagnostic text, never protocol data.
	Message string
}

// Error implements error.
func (e *AuthError) Error() string {
	var b strings.Builder
	b.WriteString("engine: authentication failed")
	switch {
	case e.Reason != 0:
		fmt.Fprintf(&b, ": reason=%d", e.Reason)
	case e.ReasonRaw != "":
		fmt.Fprintf(&b, ": reason=%q", e.ReasonRaw)
	}
	if e.Code != "" {
		fmt.Fprintf(&b, " code=%s", e.Code)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, " message=%q", e.Message)
	}
	return b.String()
}

// Unwrap reports the sentinel callers match with errors.Is.
func (e *AuthError) Unwrap() error { return ErrAuthFailed }

// StreamError is the typed <stream:error> outcome of WaitAuth (PF-029). It
// unwraps to ErrStreamError.
type StreamError struct {
	// Code is the stream:error code attribute, sanitized and capped. The
	// reference client compares it as a string ("401", "503", "515").
	Code string

	// ConflictType is the type attribute of a <conflict> child, the only
	// child whatsmeow inspects (for example "device_removed" or "replaced").
	// It is empty when there is no conflict child.
	ConflictType string
}

// Error implements error.
func (e *StreamError) Error() string {
	var b strings.Builder
	b.WriteString("engine: stream error")
	if e.Code != "" {
		fmt.Fprintf(&b, ": code=%q", e.Code)
	}
	if e.ConflictType != "" {
		fmt.Fprintf(&b, " conflict=%q", e.ConflictType)
	}
	return b.String()
}

// Unwrap reports the sentinel callers match with errors.Is.
func (e *StreamError) Unwrap() error { return ErrStreamError }

// WaitAuth reads the server's answer to the ClientPayload sent inside the
// Noise handshake and returns nil only when the server accepted the
// connection (PF-028, PF-029). Connect succeeding means the encrypted channel
// is up; WaitAuth is the step that says whether the device was authenticated:
//
//	server stanza                          result
//	<success/>                             nil
//	<failure reason=… code=… message=…/>   *AuthError  (errors.Is → ErrAuthFailed)
//	<stream:error code=…><conflict …/>     *StreamError (errors.Is → ErrStreamError)
//	<ack/>                                 skipped, keep waiting
//	anything else                          ErrUnexpectedStanza
//
// Policy for anything else: fail closed. A stanza that is not a known auth
// outcome and not the documented benign ack is reported as
// ErrUnexpectedStanza instead of being skipped, because the alternative —
// silently consuming it — would lose a stanza that another reader needs. A
// registration session, for example, receives <iq><pair-device> here, and
// StartPairing must be the one to read it. The reference client routes every
// tag to its handler queue instead; this package has one reader at a time, so
// it refuses rather than guessing. The offending stanza is consumed; only the
// result is reported, so callers treat this error as fatal for the connection.
//
// WaitAuth claims the single reader slot for its duration (ErrReaderBusy
// otherwise) and releases it before returning, so Pump, ReadNode, or
// StartPairing can take over afterwards. A transport or context failure is
// returned as-is (ctx.Err() when the context ended), not as ErrAuthFailed.
func (c *Conn) WaitAuth(ctx context.Context) error {
	if err := c.beginRead("auth"); err != nil {
		return err
	}
	defer c.endRead()

	for {
		frame, err := c.sc.ReadFrame(ctx)
		if err != nil {
			// Normalize the context deadline/cancel case: transports report
			// it as a close or a wrapped I/O error, but callers need
			// errors.Is(err, context.DeadlineExceeded) to hold.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("engine: waiting for the auth outcome: %w", err)
		}

		node, err := c.codec.Decode(bytes.NewReader(frame))
		if err != nil {
			// A frame that cannot be decoded while the server is answering
			// the payload means the stream is not trustworthy; fail closed.
			return fmt.Errorf("%w: undecodable frame before the auth outcome: %w", ErrUnexpectedStanza, err)
		}

		switch node.Tag {
		case tagSuccess:
			c.logger.DebugContext(ctx, "engine: server accepted the connection",
				"session", c.engine.cfg.SessionID,
				// <success> carries lid and t (PF-028); neither is surfaced
				// by this method yet.
				"lid", sanitizeServerText(node.Attrs["lid"]),
			)
			return nil
		case tagFailure:
			failure := parseFailure(node)
			// Log the machine-readable fields only; the free-form message
			// stays in the error, capped.
			c.logger.WarnContext(ctx, "engine: server rejected the connection",
				"session", c.engine.cfg.SessionID,
				"reason", failure.Reason,
				"code", failure.Code,
			)
			return failure
		case tagStreamError:
			streamErr := parseStreamError(node)
			c.logger.WarnContext(ctx, "engine: server sent a stream error",
				"session", c.engine.cfg.SessionID,
				"code", streamErr.Code,
				"conflict", streamErr.ConflictType,
			)
			return streamErr
		case tagAck:
			continue
		default:
			return fmt.Errorf("%w: %q arrived before the auth outcome",
				ErrUnexpectedStanza, sanitizeServerText(node.Tag))
		}
	}
}

// parseFailure extracts the documented attributes of a <failure> stanza
// (PF-029): reason, code, message. Unknown attributes are ignored.
func parseFailure(node *binary.Node) *AuthError {
	raw := node.Attrs["reason"]
	failure := &AuthError{
		ReasonRaw: sanitizeServerText(raw),
		Code:      sanitizeServerText(node.Attrs["code"]),
		Message:   sanitizeServerText(node.Attrs["message"]),
	}
	if reason, err := strconv.Atoi(raw); err == nil {
		failure.Reason = reason
	}
	return failure
}

// parseStreamError extracts the code attribute and the optional <conflict>
// child's type from a <stream:error> stanza (PF-029). Other children are
// ignored: their tags are unverified (see docs/protocol/auth.md).
func parseStreamError(node *binary.Node) *StreamError {
	streamErr := &StreamError{Code: sanitizeServerText(node.Attrs["code"])}
	if conflict := childOf(node, "conflict"); conflict != nil {
		streamErr.ConflictType = sanitizeServerText(conflict.Attrs["type"])
	}
	return streamErr
}

// sanitizeServerText makes server-provided text safe to put in an error or a
// log line: control characters become spaces (or '?' when unprintable) and
// the result is truncated to maxServerTextLen runes with an explicit marker.
func sanitizeServerText(s string) string {
	if s == "" {
		return ""
	}
	runes := []rune(s)
	truncated := len(runes) > maxServerTextLen
	if truncated {
		runes = runes[:maxServerTextLen]
	}
	var b strings.Builder
	b.Grow(len(runes) + 3)
	for _, r := range runes {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	if truncated {
		b.WriteString("...")
	}
	return b.String()
}
