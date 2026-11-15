package api

// Server-Sent Events streams: one for QR pairing, one for normalized session
// events. Both read from the shared *events.Bus and never inspect protocol
// types.
//
// Wire format:
//
//	event: <name>
//	data: <json>
//	<blank line>
//
// each followed by a flush. Heartbeats use the same frame shape with the
// "heartbeat" name so intermediaries that ignore comments still see traffic.
//
// Slow clients: each connection owns a small bounded queue drained by a
// writer goroutine. When the queue is full, the newest frame is dropped for
// that connection only; the publisher and other subscribers are unaffected
// (the bus already guarantees the same for its own buffers).
//
// The streams stop when the request context is cancelled (client disconnect or
// server shutdown), when the bus closes, or, for /qr, after the session
// reports a successful connection.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/angga0x3/whatscore/core/events"
)

const (
	// DefaultHeartbeatInterval is how often an idle SSE connection receives a
	// heartbeat frame.
	DefaultHeartbeatInterval = 15 * time.Second
	// sseQueueSize bounds frames waiting for a slow client.
	sseQueueSize = 64
	// sseWriteTimeout bounds one frame write, so a stalled client cannot pin
	// the connection's writer goroutine forever.
	sseWriteTimeout = 5 * time.Second
)

// sseFrame is one rendered frame waiting for the connection's writer.
type sseFrame struct {
	event string
	data  []byte
}

// heartbeatInterval resolves the heartbeat period, letting tests shorten it.
func (h *Handler) heartbeatInterval() time.Duration {
	if h.heartbeat > 0 {
		return h.heartbeat
	}
	return DefaultHeartbeatInterval
}

// busReady guards direct handler calls. Mount only registers the streams when
// a bus is configured, so normally /api/v1 falls back to 501.
func (h *Handler) busReady(w http.ResponseWriter) bool {
	if h.bus != nil {
		return true
	}
	writeError(w, http.StatusNotImplemented, "not_implemented", "event streaming is not configured")
	return false
}

// streamQR serves GET /api/v1/sessions/{sessionId}/qr.
func (h *Handler) streamQR(w http.ResponseWriter, r *http.Request) {
	if !h.busReady(w) {
		return
	}
	sessionID := chi.URLParam(r, "sessionId")
	session, err := h.service.GetSession(r.Context(), sessionID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	// The OpenAPI contract answers 409 when the session is already paired.
	if session.Status == "CONNECTED" {
		writeError(w, http.StatusConflict, "already_connected", "the session is already authenticated; there is no QR code to stream")
		return
	}

	h.stream(w, r, func(ev events.Event) (sseFrame, bool, bool) {
		if ev.SessionID != sessionID {
			return sseFrame{}, false, false
		}
		switch ev.Type {
		case events.TypePairingCode:
			if ev.PairingCode == nil {
				return sseFrame{}, false, false
			}
			data, err := json.Marshal(struct {
				QR        string    `json:"qr"`
				ExpiresAt time.Time `json:"expires_at"`
			}{QR: ev.PairingCode.Code, ExpiresAt: ev.PairingCode.Expires})
			if err != nil {
				return sseFrame{}, false, false
			}
			return sseFrame{event: "qr", data: data}, true, false
		case events.TypeConnected:
			data := []byte(`{"status":"CONNECTED"}`)
			// The OpenAPI contract ends the QR stream once pairing succeeds.
			return sseFrame{event: "connected", data: data}, true, true
		case events.TypeDisconnected:
			payload := struct {
				Status        string `json:"status"`
				WillReconnect bool   `json:"will_reconnect"`
			}{Status: "DISCONNECTED"}
			if ev.Disconnected != nil {
				payload.WillReconnect = ev.Disconnected.WillReconnect
			}
			data, err := json.Marshal(payload)
			if err != nil {
				return sseFrame{}, false, false
			}
			return sseFrame{event: "disconnected", data: data}, true, false
		case events.TypeError:
			frame, ok := renderEvent(ev)
			if !ok {
				return sseFrame{}, false, false
			}
			return frame, true, false
		default:
			return sseFrame{}, false, false
		}
	})
}

// streamEvents serves GET /api/v1/sessions/{sessionId}/events.
func (h *Handler) streamEvents(w http.ResponseWriter, r *http.Request) {
	if !h.busReady(w) {
		return
	}
	sessionID := chi.URLParam(r, "sessionId")
	if _, err := h.service.GetSession(r.Context(), sessionID); err != nil {
		h.writeServiceError(w, err)
		return
	}

	h.stream(w, r, func(ev events.Event) (sseFrame, bool, bool) {
		if ev.SessionID != sessionID {
			return sseFrame{}, false, false
		}
		frame, ok := renderEvent(ev)
		if !ok {
			return sseFrame{}, false, false
		}
		return frame, true, false
	})
}

// stream runs the shared SSE loop. render returns the frame to send, whether
// to send it, and whether the stream should end after sending it.
func (h *Handler) stream(w http.ResponseWriter, r *http.Request, render func(events.Event) (sseFrame, bool, bool)) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal_error", "streaming is not supported by this server")
		return
	}

	sub := h.bus.Subscribe()
	defer sub.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	queue := make(chan sseFrame, sseQueueSize)
	writerDone := make(chan struct{})
	writeFailed := make(chan struct{})
	go func() {
		defer close(writerDone)
		for frame := range queue {
			// Bound each write: a client that stops reading must not pin this
			// goroutine (and the handler waiting for it) forever. Servers that
			// cannot set deadlines just ignore the error.
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(sseWriteTimeout))
			if _, err := w.Write(frame.bytes()); err != nil {
				close(writeFailed)
				return
			}
			flusher.Flush()
		}
	}()

	heartbeat := time.NewTicker(h.heartbeatInterval())
	defer heartbeat.Stop()

	ctx := r.Context()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-writeFailed:
			// The client is gone; stop reading the bus for it.
			break loop
		case ev, open := <-sub.C:
			if !open {
				break loop
			}
			frame, send, stop := render(ev)
			if send {
				// A full queue drops the frame for this connection only.
				enqueue(queue, frame)
			}
			if stop {
				break loop
			}
		case now := <-heartbeat.C:
			data, err := json.Marshal(struct {
				Timestamp time.Time `json:"timestamp"`
			}{Timestamp: now.UTC()})
			if err != nil {
				continue
			}
			enqueue(queue, sseFrame{event: "heartbeat", data: data})
		}
	}

	// Close the queue so the writer can exit. A cancelled request does not
	// need the frames still waiting: drop them so the handler waits for at
	// most the in-flight write (bounded by sseWriteTimeout). A completed
	// stream (stop) does drain them, so the final "connected" frame arrives.
	if ctx.Err() != nil {
		for len(queue) > 0 {
			<-queue
		}
	}
	close(queue)
	<-writerDone
}

// enqueue offers frame to the writer without blocking. It reports false when
// the connection's queue is full.
func enqueue(queue chan<- sseFrame, frame sseFrame) bool {
	select {
	case queue <- frame:
		return true
	default:
		return false
	}
}

func (f sseFrame) bytes() []byte {
	return []byte("event: " + f.event + "\ndata: " + string(f.data) + "\n\n")
}

// renderEvent maps a normalized event onto the REST event catalog and its
// JSON payload. The catalog names come from the OpenAPI EventType enum;
// receipt "played" and group updates have no enum member yet, so they use
// message.receipt and group.update.
func renderEvent(ev events.Event) (sseFrame, bool) {
	name := catalogEventName(ev)
	payload, ok := eventData(ev)
	if !ok {
		return sseFrame{}, false
	}
	envelope := struct {
		ID        string    `json:"id"`
		Event     string    `json:"event"`
		SessionID string    `json:"session_id"`
		Timestamp time.Time `json:"timestamp"`
		Seq       uint64    `json:"seq"`
		Data      any       `json:"data"`
	}{
		ID:        fmt.Sprintf("evt_%d", ev.Seq),
		Event:     name,
		SessionID: ev.SessionID,
		Timestamp: ev.Timestamp.UTC(),
		Seq:       ev.Seq,
		Data:      payload,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return sseFrame{}, false
	}
	return sseFrame{event: name, data: data}, true
}

func catalogEventName(ev events.Event) string {
	switch ev.Type {
	case events.TypeConnected:
		return "session.connected"
	case events.TypeDisconnected:
		return "session.disconnected"
	case events.TypePairingCode:
		return "session.qr"
	case events.TypeMessage:
		if ev.Message != nil && ev.Message.Direction == events.DirectionOutgoing {
			return "message.sent"
		}
		return "message.received"
	case events.TypeReceipt:
		if ev.Receipt != nil {
			switch ev.Receipt.Status {
			case events.ReceiptDelivered:
				return "message.delivered"
			case events.ReceiptRead:
				return "message.read"
			}
		}
		return "message.receipt"
	case events.TypeGroupUpdate:
		return "group.update"
	default:
		return "error"
	}
}

func eventData(ev events.Event) (any, bool) {
	switch ev.Type {
	case events.TypeConnected:
		reconnected := false
		if ev.Connected != nil {
			reconnected = ev.Connected.Reconnected
		}
		return map[string]any{"status": "CONNECTED", "reconnected": reconnected}, true
	case events.TypeDisconnected:
		payload := map[string]any{"status": "DISCONNECTED", "will_reconnect": false}
		if ev.Disconnected != nil {
			payload["will_reconnect"] = ev.Disconnected.WillReconnect
			if ev.Disconnected.Reason != nil {
				payload["reason"] = ev.Disconnected.Reason.Error()
			}
		}
		return payload, true
	case events.TypePairingCode:
		if ev.PairingCode == nil {
			return nil, false
		}
		return map[string]any{"qr": ev.PairingCode.Code, "expires_at": ev.PairingCode.Expires.UTC()}, true
	case events.TypeMessage:
		if ev.Message == nil {
			return nil, false
		}
		direction := DirectionInbound
		if ev.Message.Direction == events.DirectionOutgoing {
			direction = DirectionOutbound
		}
		return struct {
			MessageID string    `json:"message_id"`
			ChatID    string    `json:"chat_id"`
			Sender    string    `json:"sender,omitempty"`
			Direction string    `json:"direction"`
			Type      string    `json:"type"`
			Text      string    `json:"text"`
			IsGroup   bool      `json:"is_group"`
			Timestamp time.Time `json:"timestamp"`
		}{
			MessageID: ev.Message.ID,
			ChatID:    ev.Message.Chat,
			Sender:    ev.Message.Sender,
			Direction: direction,
			Type:      MessageTypeText,
			Text:      ev.Message.Text,
			IsGroup:   ev.Message.IsGroup,
			Timestamp: ev.Message.Timestamp.UTC(),
		}, true
	case events.TypeReceipt:
		if ev.Receipt == nil {
			return nil, false
		}
		return struct {
			MessageID string    `json:"message_id"`
			ChatID    string    `json:"chat_id"`
			Sender    string    `json:"sender,omitempty"`
			Status    string    `json:"status"`
			Timestamp time.Time `json:"timestamp"`
		}{
			MessageID: ev.Receipt.MessageID,
			ChatID:    ev.Receipt.Chat,
			Sender:    ev.Receipt.Sender,
			Status:    string(ev.Receipt.Status),
			Timestamp: ev.Receipt.Timestamp.UTC(),
		}, true
	case events.TypeGroupUpdate:
		if ev.GroupUpdate == nil {
			return nil, false
		}
		return struct {
			GroupID      string   `json:"group_id"`
			Change       string   `json:"change"`
			Actor        string   `json:"actor,omitempty"`
			Participants []string `json:"participants,omitempty"`
		}{
			GroupID:      ev.GroupUpdate.GroupID,
			Change:       string(ev.GroupUpdate.Change),
			Actor:        ev.GroupUpdate.Actor,
			Participants: ev.GroupUpdate.Participants,
		}, true
	case events.TypeError:
		if ev.Error == nil {
			return nil, true
		}
		payload := map[string]any{"op": ev.Error.Op, "fatal": ev.Error.Fatal}
		if ev.Error.Err != nil {
			payload["message"] = ev.Error.Err.Error()
		}
		return payload, true
	default:
		return nil, true
	}
}
