package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnsureValue_HonorsSuppliedThenImmutable: a supplied value is stored, and a
// later different supplied value is ignored (provisioning never rotates).
func TestEnsureValue_HonorsSuppliedThenImmutable(t *testing.T) {
	store := Open(t.TempDir())

	v, created, err := store.EnsureValue(NameKeycloakAdmin, "chosen")
	if err != nil || !created || v != "chosen" {
		t.Fatalf("EnsureValue = %q,%v,%v; want chosen,true,nil", v, created, err)
	}

	v2, created2, err := store.EnsureValue(NameKeycloakAdmin, "different")
	if err != nil {
		t.Fatal(err)
	}
	if created2 || v2 != "chosen" {
		t.Errorf("EnsureValue rotated to %q (created=%v); an existing secret must be immutable", v2, created2)
	}
}

// TestStore_FilePermsAre0600: the secret file must not be world/group readable.
func TestStore_FilePermsAre0600(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	if _, _, err := store.EnsureValue(NameKeycloakAdmin, "x"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "secrets", NameKeycloakAdmin))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("secret file mode = %o; want 600", perm)
	}
}

// TestResolve_EnvOverridesStore: the env override wins over the stored value,
// and Resolve falls through to the store (then to not-found) when env is unset.
func TestResolve_EnvOverridesStore(t *testing.T) {
	store := Open(t.TempDir())
	if _, _, err := store.EnsureValue(NameKeycloakAdmin, "from-store"); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvKeycloakAdmin, "from-env")
	if v, ok, err := store.Resolve(EnvKeycloakAdmin, NameKeycloakAdmin); err != nil || !ok || v != "from-env" {
		t.Fatalf("with env set, Resolve = %q,%v,%v; want from-env,true,nil", v, ok, err)
	}

	t.Setenv(EnvKeycloakAdmin, "")
	if v, ok, err := store.Resolve(EnvKeycloakAdmin, NameKeycloakAdmin); err != nil || !ok || v != "from-store" {
		t.Fatalf("with env empty, Resolve = %q,%v,%v; want from-store,true,nil", v, ok, err)
	}

	// Neither env nor store → not found (fail-fast territory for consumers).
	empty := Open(t.TempDir())
	if v, ok, err := empty.Resolve(EnvKeycloakAdmin, NameKeycloakAdmin); err != nil || ok || v != "" {
		t.Fatalf("with neither, Resolve = %q,%v,%v; want \"\",false,nil", v, ok, err)
	}
}

// TestGet_AbsentIsNotAnError: a not-yet-provisioned secret reads as (‚"",false)
// without error, so callers can distinguish "unset" from "broken".
func TestGet_AbsentIsNotAnError(t *testing.T) {
	store := Open(t.TempDir())
	v, ok, err := store.Get(NameKeycloakAdmin)
	if err != nil {
		t.Fatalf("Get on absent: unexpected error %v", err)
	}
	if ok || v != "" {
		t.Errorf("absent secret = %q,%v; want \"\",false", v, ok)
	}
}
