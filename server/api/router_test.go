package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// chiNewRouter mounts the handler under /api/v1, mirroring the server wiring:
// the prefix is owned by the caller, not by Mount.
func chiNewRouter(h *Handler) *chi.Mux {
	router := chi.NewRouter()
	router.Route("/api/v1", func(v1 chi.Router) {
		if h != nil {
			h.Mount(v1)
		}
	})
	return router
}

var _ = http.MethodGet
