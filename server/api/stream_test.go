package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/angga0x3/whatscore/core/events"
)

const testHeartbeat = 25 * time.Millisecond

type streamFixture struct {
	server  *httptest.Server
	handler *Handler
	manager *Manager
	bus     *events.Bus
	session SessionView
}

func newStreamFixture(t *testing.T, withBus bool) *streamFixture {
	t.Helper()

	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(manager)
	if err != nil {
		t.Fatal(err)
	}
	var bus *events.Bus
	if withBus {
		bus = events.NewBus(events.WithBuffer(16))
		handler.SetBus(bus)
		handler.SetHeartbeatInterval(testHeartbeat)
		t.Cleanup(bus.Close)
	}

	session, err := manager.CreateSession(t.Context(), "streamer")
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(newV1Router(handler))
	t.Cleanup(server.Close)

	return &streamFixture{server: server, handler: handler, manager: manager, bus: bus, session: session}
}

// sseEvent is one decoded SSE frame.
type sseEvent struct {
	Event string
	Data  string
}

// openStream starts a GET and returns the response plus a frame reader. The
// caller must cancel and close the body.
func openStream(t *testing.T, f *streamFixture, path string) (*http.Response, *bufio.Reader, func()) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	return resp, bufio.NewReader(resp.Body), func() {
		_ = resp.Body.Close()
	}
}

// readFrame blocks until one SSE frame is decoded or the timeout elapses.
func readFrame(t *testing.T, r *bufio.Reader, timeout time.Duration) (sseEvent, error) {
	t.Helper()

	type result struct {
		event sseEvent
		err   error
	}
	done := make(chan result, 1)
	go func() {
		var ev sseEvent
		line, err := r.ReadString('\n')
		if err != nil {
			done <- result{err: err}
			return
		}
		if !strings.HasPrefix(line, "event: ") {
			done <- result{err: errUnexpectedLine(line)}
			return
		}
		ev.Event = strings.TrimSuffix(strings.TrimPrefix(line, "event: "), "\n")

		data, err := r.ReadString('\n')
		if err != nil {
			done <- result{err: err}
			return
		}
		if !strings.HasPrefix(data, "data: ") {
			done <- result{err: errUnexpectedLine(data)}
			return
		}
		ev.Data = strings.TrimSuffix(strings.TrimPrefix(data, "data: "), "\n")

		blank, err := r.ReadString('\n')
		if err != nil {
			done <- result{err: err}
			return
		}
		if blank != "\n" {
			done <- result{err: errUnexpectedLine(blank)}
			return
		}
		done <- result{event: ev}
	}()

	select {
	case res := <-done:
		return res.event, res.err
	case <-time.After(timeout):
		return sseEvent{}, errTimeout{}
	}
}

type errUnexpectedLine string

func (e errUnexpectedLine) Error() string { return "unexpected SSE line: " + string(e) }

type errTimeout struct{}

func (errTimeout) Error() string { return "timed out waiting for an SSE frame" }

// awaitEvent reads frames until one with the wanted name arrives, skipping
// heartbeats. Every frame read is validated for shape by readFrame.
func awaitEvent(t *testing.T, r *bufio.Reader, want string) sseEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ev, err := readFrame(t, r, time.Until(deadline))
		if err != nil {
			t.Fatalf("waiting for %q: %v", want, err)
		}
		if ev.Event == "heartbeat" {
			continue
		}
		if ev.Event != want {
			t.Fatalf("event = %q, want %q (data %s)", ev.Event, want, ev.Data)
		}
		return ev
	}
	t.Fatalf("no %q event before deadline", want)
	return sseEvent{}
}

func TestStreamEventsHeadersAndFrames(t *testing.T) {
	f := newStreamFixture(t, true)
	resp, reader, closeStream := openStream(t, f, "/api/v1/sessions/"+f.session.ID+"/events")
	defer closeStream()

	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		t.Fatalf("X-Accel-Buffering = %q", got)
	}

	// Another session's event must not appear on this stream.
	f.bus.Publish(events.Event{
		Type:      events.TypeMessage,
		SessionID: "other-session",
		Message:   &events.Message{ID: "m0", Chat: "a@b", Text: "not mine"},
	})
	f.bus.Publish(events.Event{
		Type:      events.TypeMessage,
		SessionID: f.session.ID,
		Message: &events.Message{
			ID:        "ABC123",
			Chat:      "6281234567890@s.whatsapp.net",
			Sender:    "6281234567890",
			Direction: events.DirectionIncoming,
			Text:      "Halo WhatsCore!",
		},
	})

	ev := awaitEvent(t, reader, "message.received")
	var envelope struct {
		ID        string `json:"id"`
		Event     string `json:"event"`
		SessionID string `json:"session_id"`
		Timestamp string `json:"timestamp"`
		Seq       uint64 `json:"seq"`
		Data      struct {
			MessageID string `json:"message_id"`
			ChatID    string `json:"chat_id"`
			Direction string `json:"direction"`
			Type      string `json:"type"`
			Text      string `json:"text"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(ev.Data), &envelope); err != nil {
		t.Fatalf("data is not JSON (%v): %s", err, ev.Data)
	}
	if envelope.Event != "message.received" || envelope.SessionID != f.session.ID {
		t.Fatalf("envelope = %#v", envelope)
	}
	if envelope.ID == "" || envelope.Seq == 0 || envelope.Timestamp == "" {
		t.Fatalf("missing envelope fields: %#v", envelope)
	}
	if envelope.Data.MessageID != "ABC123" ||
		envelope.Data.ChatID != "6281234567890@s.whatsapp.net" ||
		envelope.Data.Direction != DirectionInbound ||
		envelope.Data.Type != MessageTypeText ||
		envelope.Data.Text != "Halo WhatsCore!" {
		t.Fatalf("data = %#v", envelope.Data)
	}
}

func TestStreamEventsHeartbeat(t *testing.T) {
	f := newStreamFixture(t, true)
	_, reader, closeStream := openStream(t, f, "/api/v1/sessions/"+f.session.ID+"/events")
	defer closeStream()

	ev, err := readFrame(t, reader, time.Second)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if ev.Event != "heartbeat" {
		t.Fatalf("event = %q, want heartbeat", ev.Event)
	}
	var payload struct {
		Timestamp time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal([]byte(ev.Data), &payload); err != nil {
		t.Fatalf("heartbeat data: %v (%s)", err, ev.Data)
	}
	if payload.Timestamp.IsZero() {
		t.Fatalf("heartbeat timestamp = zero")
	}
}

func TestStreamEventsStopsOnCancel(t *testing.T) {
	f := newStreamFixture(t, true)

	ctx, cancel := context.WithCancel(t.Context())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.server.URL+"/api/v1/sessions/"+f.session.ID+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one heartbeat to prove the stream is live, then cancel.
	reader := bufio.NewReader(resp.Body)
	if _, err := readFrame(t, reader, time.Second); err != nil {
		t.Fatalf("first frame: %v", err)
	}
	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := readFrame(t, reader, time.Until(deadline))
		if err != nil {
			if _, timedOut := err.(errTimeout); timedOut {
				t.Fatalf("stream did not end after cancel: %v", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream did not end after cancel")
		}
	}

	// After the client is gone, publishing must not block or panic.
	f.bus.Publish(events.Event{Type: events.TypeConnected, SessionID: f.session.ID})
}

func TestStreamQR(t *testing.T) {
	f := newStreamFixture(t, true)
	resp, reader, closeStream := openStream(t, f, "/api/v1/sessions/"+f.session.ID+"/qr")
	defer closeStream()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	expiry := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	f.bus.Publish(events.Event{
		Type:        events.TypePairingCode,
		SessionID:   f.session.ID,
		PairingCode: &events.PairingCode{Code: "2@abc,def,ghi", Expires: expiry},
	})

	ev := awaitEvent(t, reader, "qr")
	var payload struct {
		QR        string    `json:"qr"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(ev.Data), &payload); err != nil {
		t.Fatalf("qr data: %v (%s)", err, ev.Data)
	}
	if payload.QR != "2@abc,def,ghi" || !payload.ExpiresAt.Equal(expiry) {
		t.Fatalf("payload = %#v", payload)
	}

	f.bus.Publish(events.Event{Type: events.TypeConnected, SessionID: f.session.ID})
	ev = awaitEvent(t, reader, "connected")
	if !strings.Contains(ev.Data, `"CONNECTED"`) {
		t.Fatalf("connected data = %s", ev.Data)
	}

	// The contract ends the stream after pairing: the server closes the body.
	body := make([]byte, 1)
	if _, err := resp.Body.Read(body); err == nil {
		t.Fatal("stream still open after connected")
	}
}

func TestStreamQRRejectsConnectedSession(t *testing.T) {
	f := newStreamFixture(t, true)
	if err := f.manager.ConnectSession(t.Context(), f.session.ID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+f.session.ID+"/qr", nil)
	f.router().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
}

func TestStreamUnknownSession(t *testing.T) {
	f := newStreamFixture(t, true)
	for _, path := range []string{"/api/v1/sessions/nope/events", "/api/v1/sessions/nope/qr"} {
		rec := httptest.NewRecorder()
		f.router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, body %s", path, rec.Code, rec.Body)
		}
	}
}

func TestStreamsNotImplementedWithoutBus(t *testing.T) {
	f := newStreamFixture(t, false)
	for _, path := range []string{"/api/v1/sessions/" + f.session.ID + "/events", "/api/v1/sessions/" + f.session.ID + "/qr"} {
		rec := httptest.NewRecorder()
		f.router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s status = %d, body %s", path, rec.Code, rec.Body)
		}
		if code := errorCode(t, rec); code != "not_implemented" {
			t.Fatalf("%s code = %q", path, code)
		}
	}
}

func TestStreamDropsForSlowClient(t *testing.T) {
	queue := make(chan sseFrame, 1)
	if !enqueue(queue, sseFrame{event: "a"}) {
		t.Fatal("first frame must be queued")
	}
	if enqueue(queue, sseFrame{event: "b"}) {
		t.Fatal("second frame must be dropped when the queue is full")
	}
}

func TestRenderEventCatalog(t *testing.T) {
	cases := []struct {
		name string
		ev   events.Event
		want string
	}{
		{"connected", events.Event{Type: events.TypeConnected, Connected: &events.Connected{}}, "session.connected"},
		{"disconnected", events.Event{Type: events.TypeDisconnected, Disconnected: &events.Disconnected{}}, "session.disconnected"},
		{"pairing", events.Event{Type: events.TypePairingCode, PairingCode: &events.PairingCode{Code: "x"}}, "session.qr"},
		{"incoming", events.Event{Type: events.TypeMessage, Message: &events.Message{Direction: events.DirectionIncoming}}, "message.received"},
		{"outgoing", events.Event{Type: events.TypeMessage, Message: &events.Message{Direction: events.DirectionOutgoing}}, "message.sent"},
		{"delivered", events.Event{Type: events.TypeReceipt, Receipt: &events.Receipt{Status: events.ReceiptDelivered}}, "message.delivered"},
		{"read", events.Event{Type: events.TypeReceipt, Receipt: &events.Receipt{Status: events.ReceiptRead}}, "message.read"},
		{"failed", events.Event{Type: events.TypeError, Error: &events.SessionError{Op: "read"}}, "error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame, ok := renderEvent(tc.ev)
			if !ok {
				t.Fatal("renderEvent returned no frame")
			}
			if frame.event != tc.want {
				t.Fatalf("event = %q, want %q", frame.event, tc.want)
			}
			if !json.Valid(frame.data) {
				t.Fatalf("data is not JSON: %s", frame.data)
			}
			if !strings.Contains(string(frame.bytes()), "event: "+tc.want+"\ndata: ") {
				t.Fatalf("frame = %q", frame.bytes())
			}
			if !strings.HasSuffix(string(frame.bytes()), "\n\n") {
				t.Fatalf("frame does not end with a blank line: %q", frame.bytes())
			}
		})
	}

	// A payload-less event is skipped instead of panicking.
	if _, ok := renderEvent(events.Event{Type: events.TypeMessage}); ok {
		t.Fatal("nil message payload must not render")
	}
}

// router returns the recorder-friendly router with the same wiring as the
// fixture's httptest server.
func (f *streamFixture) router() http.Handler {
	return newV1Router(f.handler)
}
