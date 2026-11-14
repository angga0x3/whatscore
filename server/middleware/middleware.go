// Package middleware provides WhatsCore-specific HTTP middleware on top of
// the chi built-ins: request logging and panic recovery, both wired to slog.
package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// responseRecorder records the status code and size written by handlers.
// It also forwards http.Flusher so streaming handlers (SSE in upcoming
// milestones) keep working under the logging middleware.
type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w, status: http.StatusOK}
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.wrote {
		return
	}
	r.status = status
	r.wrote = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Logger logs one line per request with the fields operators need to trace
// traffic: method, path, status, latency, request id, and client IP.
func Logger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := newResponseRecorder(w)
			// chi's RequestID middleware only stores the id in the request
			// context; echo it back so clients and log queries can correlate.
			if reqID := chimw.GetReqID(r.Context()); reqID != "" {
				rec.Header().Set("X-Request-Id", reqID)
			}

			next.ServeHTTP(rec, r)

			logger.LogAttrs(r.Context(), slog.LevelInfo, "http_request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.status),
				slog.Int("bytes", rec.bytes),
				slog.Duration("duration", time.Since(start)),
				slog.String("request_id", chimw.GetReqID(r.Context())),
				slog.String("remote_ip", r.RemoteAddr),
			)
		})
	}
}

// Recover converts panics from downstream handlers into JSON 500 responses
// instead of crashed connections, and logs the stack trace.
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil && rec != http.ErrAbortHandler {
					logger.Error("panic recovered",
						"error", rec,
						"method", r.Method,
						"path", r.URL.Path,
						"request_id", chimw.GetReqID(r.Context()),
						"stack", string(debug.Stack()),
					)
					writePanicResponse(w)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func writePanicResponse(w http.ResponseWriter) {
	if rec, ok := w.(*responseRecorder); ok && rec.wrote {
		return // Response already started; nothing safe left to send.
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`{"error":{"code":"internal_error","message":"an unexpected error occurred"}}`))
}
