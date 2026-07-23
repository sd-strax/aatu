package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnsureRandom_GeneratesThenReuses: the first call generates and persists a
// strong secret; the second returns it unchanged (idempotent, never rotates).
func TestEnsureRandom_GeneratesThenReuses(t *testing.T) {
	store := Open(t.TempDir())

	v1, created1, err := store.EnsureRandom(NameKeycloakAdmin)
	if err != nil {
		t.Fatalf("EnsureRandom: %v", err)
	}
	if !created1 {
		t.Error("first EnsureRandom did not report created")
	}
	if len(v1) < 24 {
		t.Errorf("secret %q looks too short to be a strong random value", v1)
	}

	v2, created2, err := store.EnsureRandom(NameKeycloakAdmin)
	if err != nil {
		t.Fatalf("EnsureRandom again: %v", err)
	}
	if created2 {
		t.Error("second EnsureRandom rotated the secret; it must reuse")
	}
	if v2 != v1 {
		t.Errorf("secret changed on reuse: %q → %q", v1, v2)
	}
}

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
