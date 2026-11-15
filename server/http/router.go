// Package httpapi assembles the Chi router, middleware chain, and all
// endpoint handlers. Handlers never import the WhatsApp engine directly;
// everything arrives here through application services (architectural rule
// #1 and #2 in docs/architecture/overview.md).
package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/angga0x3/whatscore/buildinfo"
	"github.com/angga0x3/whatscore/server/http/handlers"
	"github.com/angga0x3/whatscore/server/middleware"
)

// Deps carries everything the router needs, wired by cmd/whatscore.
type Deps struct {
	Logger *slog.Logger
	// AppName is reported by /version (from APP_NAME).
	AppName string
	// Build carries ldflags-injected build information.
	Build buildinfo.Info
	// Readiness lists dependency checks surfaced by /ready.
	Readiness []handlers.Checker
	// IsShuttingDown must return true once the process started draining;
	// nil is treated as "never".
	IsShuttingDown func() bool
	// API optionally mounts the versioned REST routes.
	API interface{}
	// RateLimit, when non-nil, throttles /api/v1 requests. The system
	// probes (/health, /ready, /version) are never limited so monitoring
	// cannot be locked out by a busy API client.
	RateLimit *middleware.RateLimiter
}

// NewRouter builds the full HTTP handler.
func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	// RealIP is deliberately omitted: it trusts spoofable X-Forwarded-For
	// headers (GHSA-3fxj-6jh8-hvhx). Deployments behind a reverse proxy
	// should add a middleware that only trusts configured proxy addresses.
	r.Use(middleware.Logger(deps.Logger))
	r.Use(middleware.Recover(deps.Logger))

	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		handlers.WriteError(w, http.StatusNotFound, "not_found", "the requested resource does not exist")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		handlers.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the HTTP method is not allowed for this resource")
	})

	// System endpoints live at the root so probes and monitors do not need
	// to know the API version.
	r.Get("/health", handlers.NewHealthHandler().ServeHTTP)
	r.Get("/ready", handlers.NewReadinessHandler(deps.Readiness, deps.IsShuttingDown).ServeHTTP)
	r.Get("/version", handlers.NewVersionHandler(deps.AppName, deps.Build).ServeHTTP)

	// Versioned REST API. This router owns the /api/v1 prefix; the API
	// handler only adds routes under it. Paths that are not mounted yet keep
	// answering 501 so clients can tell "not shipped yet" apart from "wrong
	// URL".
	v1 := chi.NewRouter()
	if deps.API != nil {
		if mounter, ok := deps.API.(interface{ Mount(chi.Router) }); ok {
			mounter.Mount(v1)
		}
	}
	v1.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		handlers.WriteError(w, http.StatusNotImplemented, "not_implemented",
			"this endpoint is defined by the v1 API contract (docs/api/openapi.yaml) and ships in an upcoming milestone")
	})
	v1.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		handlers.WriteError(w, http.StatusNotImplemented, "not_implemented",
			"this endpoint is defined by the v1 API contract (docs/api/openapi.yaml) and ships in an upcoming milestone")
	})

	// Rate limiting is scoped to the versioned API on purpose: probes and
	// version checks must keep answering while a client is throttled. The
	// limiter wraps the mounted handler rather than using v1.Use so it also
	// covers the 501 catch-all — chi skips a subrouter's own middleware when
	// that subrouter has no routes registered.
	var apiHandler http.Handler = v1
	if deps.RateLimit != nil {
		apiHandler = deps.RateLimit.Middleware()(v1)
	}
	r.Mount("/api/v1", apiHandler)

	return r
}
