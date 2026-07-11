package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sd-strax/reckon/config"
)

// withConfigEnv points config resolution at a temp file for the duration of the
// test, so Init writes there instead of the user's real ~/.reckon/config.yaml.
func withConfigEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	envVar := "RECKON_CONFIG"
	t.Setenv(envVar, path)
	// Sanity: config resolves to exactly the path we set.
	if got, err := config.DefaultPath(); err != nil || got != path {
		t.Fatalf("DefaultPath() = %q, %v; want %q (env %s)", got, err, path, envVar)
	}
	return path
}

// TestInit_FreshWritesConfigAndNamespace: a first init writes a parseable config
// at the resolved path, with a freshly minted (non-default) identity namespace.
func TestInit_FreshWritesConfigAndNamespace(t *testing.T) {
	path := withConfigEnv(t)

	res, err := Init()
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if res.AlreadyExisted {
		t.Error("fresh init reported AlreadyExisted")
	}
	if res.ConfigPath != path {
		t.Errorf("config path = %q; want %q", res.ConfigPath, path)
	}
	if res.TenantNamespace == "" {
		t.Fatal("no namespace minted")
	}
	// The minted namespace must NOT be the shared fixed default — a real install
	// gets its own.
	if res.TenantNamespace == config.Default().Capability.TenantNamespace {
		t.Error("init reused the fixed default namespace instead of minting a fresh one")
	}

	// The written file parses and carries the minted namespace.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config not written: %v", err)
	}
	loaded, err := config.Load()
	if err != nil {
		t.Fatalf("load written config: %v", err)
	}
	if loaded.Capability.TenantNamespace != res.TenantNamespace {
		t.Errorf("persisted namespace = %q; want %q", loaded.Capability.TenantNamespace, res.TenantNamespace)
	}
}

// TestInit_Idempotent: re-running init against an existing config never
// clobbers it — the namespace stays put and AlreadyExisted is reported.
func TestInit_Idempotent(t *testing.T) {
	withConfigEnv(t)

	first, err := Init()
	if err != nil {
		t.Fatalf("first Init: %v", err)
	}
	second, err := Init()
	if err != nil {
		t.Fatalf("second Init: %v", err)
	}
	if !second.AlreadyExisted {
		t.Error("second init did not report AlreadyExisted")
	}
	if second.TenantNamespace != first.TenantNamespace {
		t.Errorf("namespace changed on re-init: %q → %q (must be immutable)", first.TenantNamespace, second.TenantNamespace)
	}
}

// TestInit_UniquePerInstall: two independent installs mint distinct namespaces.
func TestInit_UniquePerInstall(t *testing.T) {
	withConfigEnv(t)
	a, err := Init()
	if err != nil {
		t.Fatal(err)
	}
	// Point at a second, separate config location.
	dir := t.TempDir()
	t.Setenv("RECKON_CONFIG", filepath.Join(dir, "config.yaml"))
	b, err := Init()
	if err != nil {
		t.Fatal(err)
	}
	if a.TenantNamespace == b.TenantNamespace {
		t.Errorf("two installs minted the same namespace %q", a.TenantNamespace)
	}
}
