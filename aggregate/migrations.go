package aggregate

import (
	"embed"
	"io/fs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrations returns the filesystem of aggregate-side SQL migrations,
// rooted at the migrations/ directory. Consumed by pgmigrate.Run.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		// embed.FS rooted inside the package; this can't fail at runtime.
		panic(err)
	}
	return sub
}
