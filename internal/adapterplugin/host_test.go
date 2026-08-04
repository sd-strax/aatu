package adapterplugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// installEcho writes a manifest under <root>/echo pointing at the compiled echo
// binary, so a Host scan discovers one installed adapter.
func installEcho(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "echo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	man := "manifest_version: 1\nname: echo\nversion: 0.0.1\nprotocol_versions: [1]\nclass: CUSTOM\nexec: [\"" + echoBin + "\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(man), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestHostSharesOneProcessPerInstance(t *testing.T) {
	host := NewHost(installEcho(t), "test-engine", silentLogger())
	t.Cleanup(host.Close)
	if len(host.Problems()) != 0 {
		t.Fatalf("problems = %v", host.Problems())
	}

	p1, err := host.Plugin("echo", "", nil)
	if err != nil {
		t.Fatalf("Plugin: %v", err)
	}
	p2, err := host.Plugin("echo", "echo", nil)
	if err != nil {
		t.Fatalf("Plugin (2): %v", err)
	}
	if p1 != p2 {
		t.Fatal("Host returned two Plugins for one instance; a read+write vendor would spawn twice")
	}
	// The shared handle actually works.
	if _, err := p1.Invoke(context.Background(), "get_host_context", nil); err != nil {
		t.Fatalf("Invoke via shared plugin: %v", err)
	}
}

func TestHostUnknownInstallIsAnError(t *testing.T) {
	host := NewHost(installEcho(t), "test-engine", silentLogger())
	t.Cleanup(host.Close)
	if _, err := host.Plugin("okta", "okta", nil); err == nil {
		t.Fatal("Plugin for an uninstalled adapter should error")
	}
}

func TestHostRefusesLiteralSecret(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "echo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A manifest whose config_schema marks client_secret x-secret.
	man := "manifest_version: 1\nname: echo\nversion: 0.0.1\nprotocol_versions: [1]\nclass: CUSTOM\n" +
		"exec: [\"" + echoBin + "\"]\n" +
		"config_schema:\n  type: object\n  properties:\n    client_secret:\n      type: string\n      x-secret: true\n"
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(man), 0o644); err != nil {
		t.Fatal(err)
	}
	host := NewHost(root, "test-engine", silentLogger())
	t.Cleanup(host.Close)
	// A literal in the x-secret field is refused before any spawn (11 §4.3).
	_, err := host.Plugin("echo", "", map[string]any{"client_secret": "raw-plaintext"})
	if err == nil {
		t.Fatal("Host.Plugin accepted a plaintext x-secret value; the literal-refusal wiring is missing")
	}
}

func TestHostMissingRootIsUsableEmpty(t *testing.T) {
	host := NewHost(filepath.Join(t.TempDir(), "none"), "test-engine", silentLogger())
	t.Cleanup(host.Close)
	if len(host.Installed()) != 0 || len(host.Problems()) != 0 {
		t.Fatalf("missing root should be clean: installed=%v problems=%v", host.Installed(), host.Problems())
	}
}
