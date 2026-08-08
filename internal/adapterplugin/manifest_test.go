package adapterplugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sd-strax/reckon/capability"
)

// writeManifest lays down <root>/<dir>/manifest.yaml with the given body.
func writeManifest(t *testing.T, root, dir, body string) {
	t.Helper()
	d := filepath.Join(root, dir)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "manifest.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanAdaptersHappyPath(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "okta", `
manifest_version: 1
name: okta
version: 0.3.1
protocol_versions: [1]
class: MCP
exec: ["./reckon-adapter-okta"]
summary:
  verbs: [get_entity_context]
  action_types: [account.disable]
`)
	installed, problems := ScanAdapters(root)
	if len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
	}
	got, ok := installed["okta"]
	if !ok {
		t.Fatalf("okta not installed: %+v", installed)
	}
	if class, _ := got.Manifest.AdapterClass(); class != capability.ClassMCP {
		t.Fatalf("class = %q, want mcp", class)
	}
}

func TestScanAdaptersDropsMalformed(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "bad-yaml", "not: [valid")
	writeManifest(t, root, "no-overlap", `
manifest_version: 1
name: future
protocol_versions: [2]
class: MCP
exec: ["./x"]
`)
	writeManifest(t, root, "unknown-class", `
manifest_version: 1
name: weird
protocol_versions: [1]
class: TELEPATHY
exec: ["./x"]
`)
	installed, problems := ScanAdapters(root)
	if len(installed) != 0 {
		t.Fatalf("installed = %+v, want none (all malformed)", installed)
	}
	if len(problems) != 3 {
		t.Fatalf("problems = %v, want 3", problems)
	}
}

func TestScanAdaptersDuplicateNameDropsBoth(t *testing.T) {
	root := t.TempDir()
	base := `
manifest_version: 1
name: dup
protocol_versions: [1]
class: NATIVE_API
exec: ["./x"]
`
	writeManifest(t, root, "instance-a", base)
	writeManifest(t, root, "instance-b", base)
	installed, problems := ScanAdapters(root)
	if _, ok := installed["dup"]; ok {
		t.Fatal("duplicate name should be dropped, not resolved to a winner")
	}
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want 1 duplicate report", problems)
	}
}

func TestScanAdaptersMissingRootIsClean(t *testing.T) {
	installed, problems := ScanAdapters(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(installed) != 0 || len(problems) != 0 {
		t.Fatalf("missing root should be clean: installed=%v problems=%v", installed, problems)
	}
}

// TestHostRescanPicksUpNewInstall: an adapter installed AFTER the host booted
// becomes visible on Rescan — the hot-reload path for `adapter setup <new>`
// (a scan-once cache otherwise forces a restart while setup reports success).
func TestHostRescanPicksUpNewInstall(t *testing.T) {
	root := t.TempDir()
	h := NewHost(root, "test", nil)
	if len(h.Installed()) != 0 {
		t.Fatalf("fresh empty root should have no installs: %+v", h.Installed())
	}

	// Install arrives after boot (what `adapter setup servicenow` does).
	writeManifest(t, root, "servicenow", `
manifest_version: 1
name: servicenow
version: 0.1.0
protocol_versions: [1]
class: NATIVE_API
exec: ["./reckon-adapter-servicenow"]
summary:
  action_types: [ticket.create]
`)
	if _, ok := h.Installed()["servicenow"]; ok {
		t.Fatal("pre-rescan visibility would mean the cache isn't a cache")
	}
	if problems := h.Rescan(); len(problems) != 0 {
		t.Fatalf("rescan problems = %v, want none", problems)
	}
	if _, ok := h.Installed()["servicenow"]; !ok {
		t.Fatalf("servicenow not visible after Rescan: %+v", h.Installed())
	}
}
