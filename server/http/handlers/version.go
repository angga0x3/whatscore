package handlers

import (
	"net/http"
	"runtime"

	"github.com/angga0x3/whatscore/buildinfo"
)

// versionResponse is the /version response body.
type versionResponse struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuiltAt   string `json:"built_at"`
	GoVersion string `json:"go_version"`
}

// VersionHandler reports build information for support and diagnostics.
type VersionHandler struct {
	appName string
	build   buildinfo.Info
}

// NewVersionHandler constructs the version handler.
func NewVersionHandler(appName string, build buildinfo.Info) *VersionHandler {
	return &VersionHandler{appName: appName, build: build}
}

// ServeHTTP implements http.Handler.
func (h *VersionHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, versionResponse{
		Name:      h.appName,
		Version:   h.build.Version,
		Commit:    h.build.Commit,
		BuiltAt:   h.build.Date,
		GoVersion: runtime.Version(),
	})
}
