package api

import "github.com/go-chi/chi/v5"

// chiNewRouter isolates the router type so handler tests can mount routes
// without depending on the server wiring.
func chiNewRouter() *chi.Mux { return chi.NewRouter() }
