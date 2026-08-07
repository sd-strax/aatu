package adapterruntime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNodeTargetKnownPlatform(t *testing.T) {
	// Runs on a supported platform in CI/dev; the mapping must resolve.
	if _, err := nodeTarget(); err != nil {
		t.Fatalf("nodeTarget on this platform: %v", err)
	}
}

func TestNodeEntrypointPath(t *testing.T) {
	want := filepath.Join(nodeModulesDir, ".bin", "greynoise-mcp-server")
	if got := NodeEntrypointPath("greynoise-mcp-server"); got != want {
		t.Fatalf("NodeEntrypointPath = %q, want %q", got, want)
	}
}

func TestNodeProvisionedMarker(t *testing.T) {
	dir := t.TempDir()
	if NodeProvisioned(dir, "@greynoise/greynoise-mcp-server", "1.2.3") {
		t.Fatal("empty dir must not read as provisioned")
	}
	if err := os.MkdirAll(filepath.Join(dir, nodeModulesDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, nodeProvisionMarker), []byte("node @greynoise/greynoise-mcp-server@1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !NodeProvisioned(dir, "@greynoise/greynoise-mcp-server", "1.2.3") {
		t.Error("matching spec must read as provisioned")
	}
	if NodeProvisioned(dir, "@greynoise/greynoise-mcp-server", "1.3.0") {
		t.Error("a version bump must invalidate the marker")
	}
}

func TestSymlinkStaysInside(t *testing.T) {
	root := filepath.Join("/tmp", "node")
	// A node-style relative link (bin/npm -> ../lib/node_modules/...) stays inside.
	if !symlinkStaysInside(filepath.Join(root, "bin", "npm"), "../lib/node_modules/npm/bin/npm-cli.js", root) {
		t.Error("relative in-tree link should be allowed")
	}
	// An escaping link must be refused.
	if symlinkStaysInside(filepath.Join(root, "bin", "evil"), "../../../../etc/passwd", root) {
		t.Error("escaping link must be refused")
	}
}
