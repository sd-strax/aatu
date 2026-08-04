// Package bundledadapters is the registry of first-party adapters that ship
// with reckon, so `reckon adapter install <name>` places them without the
// operator doing mkdir/cp/go-build by hand. The manifest travels embedded in the
// reckon binary; the adapter executable is built alongside reckon (make build)
// and resolved as a sibling of the running reckon binary at install time.
//
// This is the friction-removal counterpart to internal/adapterruntime: install
// places the adapter, setup provisions its runtime + logs in — two `reckon
// adapter …` commands, no shell plumbing.
package bundledadapters

import (
	_ "embed"
	"sort"
)

//go:embed manifests/okta.yaml
var oktaManifest []byte

// Bundled is one first-party adapter reckon can install.
type Bundled struct {
	Name string
	// Manifest is the embedded manifest.yaml written into the install dir.
	Manifest []byte
	// Binary is the adapter executable name, built by `make build` next to the
	// reckon binary and copied into the install dir at install time.
	Binary string
}

var registry = map[string]Bundled{
	"okta": {Name: "okta", Manifest: oktaManifest, Binary: "reckon-adapter-okta"},
}

// Get returns the bundled adapter for a name.
func Get(name string) (Bundled, bool) {
	b, ok := registry[name]
	return b, ok
}

// Names lists the bundled adapter names, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
