package adapterruntime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUvTargetKnownPlatform(t *testing.T) {
	// The dev/CI platforms (darwin, linux) must resolve to a uv target.
	if _, err := uvTarget(); err != nil {
		t.Fatalf("uvTarget on this platform: %v", err)
	}
}

func TestProvisionedMarker(t *testing.T) {
	dir := t.TempDir()
	if Provisioned(dir, "3.13", "okta-mcp-server", "1.2.3") {
		t.Fatal("empty dir should not be provisioned")
	}
	// Simulate a completed provision of an exact spec.
	if err := os.MkdirAll(filepath.Join(dir, VenvDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, provisionMarker), []byte("3.13 okta-mcp-server==1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Provisioned(dir, "3.13", "okta-mcp-server", "1.2.3") {
		t.Fatal("matching spec should read as provisioned")
	}
	// A version bump invalidates the marker (re-provision).
	if Provisioned(dir, "3.13", "okta-mcp-server", "1.3.0") {
		t.Fatal("a changed version must not read as provisioned")
	}
	// A python bump too.
	if Provisioned(dir, "3.14", "okta-mcp-server", "1.2.3") {
		t.Fatal("a changed python must not read as provisioned")
	}
}

func TestEntrypointPath(t *testing.T) {
	if got := EntrypointPath("okta-mcp-server"); got != filepath.Join(".venv", "bin", "okta-mcp-server") {
		t.Fatalf("EntrypointPath = %q", got)
	}
}
