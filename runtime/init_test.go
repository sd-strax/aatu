package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/secrets"
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

	res, err := Init(InitOptions{})
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
// clobbers it — the namespace stays put, the provisioned admin secret is
// unchanged (never rotated), and AlreadyExisted is reported.
func TestInit_Idempotent(t *testing.T) {
	withConfigEnv(t)

	first, err := Init(InitOptions{})
	if err != nil {
		t.Fatalf("first Init: %v", err)
	}
	second, err := Init(InitOptions{})
	if err != nil {
		t.Fatalf("second Init: %v", err)
	}
	if !second.AlreadyExisted {
		t.Error("second init did not report AlreadyExisted")
	}
	if second.TenantNamespace != first.TenantNamespace {
		t.Errorf("namespace changed on re-init: %q → %q (must be immutable)", first.TenantNamespace, second.TenantNamespace)
	}
	if second.KeycloakAdminGenerated {
		t.Error("re-init reported the admin secret as generated; it must be reused, not rotated")
	}
	if second.KeycloakAdminPassword != first.KeycloakAdminPassword {
		t.Error("admin secret changed on re-init (must be immutable once provisioned)")
	}
}

// TestInit_ProvisionsAdminSecret: a fresh init generates and persists a strong
// admin password (not a hardcoded default), and a supplied value is honored.
func TestInit_ProvisionsAdminSecret(t *testing.T) {
	withConfigEnv(t)
	res, err := Init(InitOptions{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !res.KeycloakAdminGenerated {
		t.Error("fresh init did not generate an admin secret")
	}
	if res.KeycloakAdminPassword == "" || res.KeycloakAdminPassword == "admin" {
		t.Errorf("weak/empty admin password %q; want a generated strong secret", res.KeycloakAdminPassword)
	}
	if !res.PostgresProvisioned {
		t.Error("fresh init did not provision the postgres role password")
	}
	// The postgres secret is a real strong value in the store, not a hardcoded default.
	if pg, ok, err := secrets.Open(filepath.Dir(res.ConfigPath)).Get(secrets.NamePostgres); err != nil || !ok {
		t.Fatalf("postgres secret not in store: ok=%v err=%v", ok, err)
	} else if pg == "" || pg == "reckon" {
		t.Errorf("weak/empty postgres password %q; want a generated strong secret", pg)
	}

	// A supplied password is honored on a fresh install.
	dir := t.TempDir()
	t.Setenv("RECKON_CONFIG", filepath.Join(dir, "config.yaml"))
	supplied, err := Init(InitOptions{KeycloakAdminPassword: "operator-chosen"})
	if err != nil {
		t.Fatalf("Init supplied: %v", err)
	}
	if supplied.KeycloakAdminPassword != "operator-chosen" {
		t.Errorf("supplied password not honored: got %q", supplied.KeycloakAdminPassword)
	}
	// A supplied value is "set from input", NOT "generated" — so the CLI labels
	// it correctly and never echoes a password the operator already chose.
	if supplied.KeycloakAdminGenerated {
		t.Error("a supplied password must not be reported as generated")
	}
	if !supplied.KeycloakAdminSetFromInput {
		t.Error("a supplied password on a fresh store should report set-from-input")
	}
}

// TestInit_ExternalSecretNotPersisted: an env-injected (External) secret must
// NOT be written to the store — the vault/operator path leaves nothing on disk.
func TestInit_ExternalSecretNotPersisted(t *testing.T) {
	withConfigEnv(t)
	res, err := Init(InitOptions{
		KeycloakAdminExternal: true,
		PostgresExternal:      true,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !res.KeycloakAdminExternal || !res.PostgresExternal {
		t.Error("external flags not reported back")
	}
	if res.KeycloakAdminGenerated {
		t.Error("an external KC admin secret must not be reported as generated")
	}
	if res.PostgresProvisioned {
		t.Error("an external Postgres secret must not be reported as provisioned")
	}
	// Nothing written to the store for either secret.
	store := secrets.Open(filepath.Dir(res.ConfigPath))
	for _, name := range []string{secrets.NameKeycloakAdmin, secrets.NamePostgres} {
		if _, ok, err := store.Get(name); err != nil || ok {
			t.Errorf("external secret %q was persisted (ok=%v err=%v); it must stay off disk", name, ok, err)
		}
	}
}

// TestInit_UniquePerInstall: two independent installs mint distinct namespaces.
func TestInit_UniquePerInstall(t *testing.T) {
	withConfigEnv(t)
	a, err := Init(InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Point at a second, separate config location.
	dir := t.TempDir()
	t.Setenv("RECKON_CONFIG", filepath.Join(dir, "config.yaml"))
	b, err := Init(InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a.TenantNamespace == b.TenantNamespace {
		t.Errorf("two installs minted the same namespace %q", a.TenantNamespace)
	}
}

// TestInit_SeedsWiredDemo: a fresh init materializes the demo scenario + a
// merged tenant config, points the config at them, and that config is consumable
// by BOTH the capability (read) and action (write) loaders — the "runs out of
// the box" contract. Verified end-to-end: BuildResolver produces available verbs
// and BuildActionResolver produces write bindings, both against the seeded files.
func TestInit_SeedsWiredDemo(t *testing.T) {
	withConfigEnv(t)
	res, err := Init(InitOptions{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if res.SeededScenario == "" || res.CapabilityConfig == "" || res.FixtureRoot == "" {
		t.Fatalf("seed result incomplete: %+v", res)
	}

	// The config Load returns points at the seeded files (not the empty default).
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Capability.ConfigPath != res.CapabilityConfig || cfg.Capability.FixtureRoot != res.FixtureRoot {
		t.Fatalf("config not wired at seed: config_path=%q fixture_root=%q",
			cfg.Capability.ConfigPath, cfg.Capability.FixtureRoot)
	}

	// The fixture scenario JSON landed under the fixture root.
	if entries, err := os.ReadDir(filepath.Join(res.FixtureRoot, res.SeededScenario)); err != nil || len(entries) == 0 {
		t.Fatalf("fixture scenario not seeded (%v, %d files)", err, len(entries))
	}

	// The merged config is consumable by the READ loader — verbs light up.
	tc, err := capability.LoadTenantConfig(res.CapabilityConfig)
	if err != nil {
		t.Fatalf("capability.LoadTenantConfig on seeded config: %v", err)
	}
	resolver, catalog, err := capability.BuildResolver(tc, res.FixtureRoot, uuid.New())
	if err != nil {
		t.Fatalf("BuildResolver on seeded config: %v", err)
	}
	if got := len(resolver.AvailableVerbs(catalog)); got == 0 {
		t.Error("seeded capability config exposes no available verbs")
	}

	// ...and by the WRITE loader — action bindings are present.
	ac, err := action.LoadActionConfig(res.CapabilityConfig)
	if err != nil {
		t.Fatalf("action.LoadActionConfig on seeded config: %v", err)
	}
	if len(ac.Bindings) == 0 {
		t.Error("seeded merged config carries no action bindings (write path would be dark)")
	}
	if _, _, err := action.BuildActionResolver(ac, res.FixtureRoot); err != nil {
		t.Fatalf("BuildActionResolver on seeded config: %v", err)
	}
}
