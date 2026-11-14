// Package migrations embeds the SQL migration files so the WhatsCore binary
// is self-contained and can bring its own schema up to date on startup.
package migrations

import (
	"embed"
	"io/fs"
)

// FS contains all *.sql migration files paired with this package.
//
// The naming convention is golang-migrate's:
//
//	NNNNNN_description.up.sql
//	NNNNNN_description.down.sql
//
// New migrations must be appended with the next sequential version number;
// existing files are immutable once released.
func FS() fs.FS {
	return embedded
}

//go:embed *.sql
var embedded embed.FS
