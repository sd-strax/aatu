package knowledge

import (
	"embed"
	"io/fs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrations returns the filesystem of knowledge-side SQL migrations,
// rooted at the migrations/ directory. Consumed by pgmigrate.Run.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}
