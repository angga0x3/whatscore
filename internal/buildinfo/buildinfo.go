// Package buildinfo carries version information injected at build time via
// -ldflags (see Makefile and deployments/docker/Dockerfile).
package buildinfo

// Info describes one build of the WhatsCore binary.
type Info struct {
	Version string
	Commit  string
	Date    string
}

// String renders the info for logs and the /version endpoint fallback.
func (i Info) String() string {
	return i.Version + " (" + i.Commit + ", " + i.Date + ")"
}
