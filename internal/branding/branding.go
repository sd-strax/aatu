// Package branding holds the single source of truth for user-facing
// product names. The engine's *internal* name (the Go module path, the
// repo, package directories) is "reckon" and is stable. The strings in
// this package are what an end-user sees: the CLI binary name, the
// data directory under $HOME, the pidfile name, the version-output
// prefix.
//
// When the product is rebranded (e.g., "reckon" → "pivot"), only the
// constants in this file change. Internal identifiers stay put.
package branding

const (
	// CLI is the binary / command users type. Appears in version output,
	// usage strings, log prefixes that surface to the user.
	CLI = "reckon"

	// DataDir is the dotfile directory under $HOME where the supervisor
	// stores Pg data, Keycloak state, downloaded binaries, logs, and
	// the pidfile. Includes the leading dot.
	DataDir = ".reckon"

	// PidName is the filename of the supervisor pidfile inside DataDir.
	PidName = "reckon.pid"
)
