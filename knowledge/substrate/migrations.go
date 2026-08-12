package substrate

import (
	"embed"
	"io/fs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrations returns the substrate's SQL migrations rooted at migrations/.
// The substrate never applies them itself — hosts apply with their own
// tooling (§7: an embedded supervisor, a k8s job, the service binary's
// migrate subcommand), which keeps this package free of host imports.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}
