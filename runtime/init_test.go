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

// promptStub returns InitOptions whose PromptForSecret answers with a strong
// per-secret value, standing in for the CLI's interactive no-echo prompt so
// tests can exercise the (never-auto-generated) prompt source without a TTY.
func promptStub() InitOptions {
	return InitOptions{PromptForSecret: func(name, _ string) (string, error) {
		return "prompted-" + name + "-pw", nil
	}}
}

// TestInit_FreshWritesConfigAndNamespace: a first init writes a parseable config
// at the resolved path, with a freshly minted (non-default) identity namespace.
func TestInit_FreshWritesConfigAndNamespace(t *testing.T) {
	path := withConfigEnv(t)

	res, err := Init(promptStub())
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
// unchanged (never rotated OR re-prompted), and AlreadyExisted is reported.
func TestInit_Idempotent(t *testing.T) {
	withConfigEnv(t)

	// A prompter that fails the test if called a second time — proves re-init
	// reuses the stored secret rather than re-prompting.
	calls := 0
	opts := InitOptions{PromptForSecret: func(name, _ string) (string, error) {
		calls++
		return "prompted-" + name + "-pw", nil
	}}

	first, err := Init(opts)
	if err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if !first.KeycloakAdminSetFromInput {
		t.Error("fresh init did not report the admin secret set from input")
	}
	callsAfterFirst := calls

	second, err := Init(opts)
	if err != nil {
		t.Fatalf("second Init: %v", err)
	}
	if !second.AlreadyExisted {
		t.Error("second init did not report AlreadyExisted")
	}
	if second.TenantNamespace != first.TenantNamespace {
		t.Errorf("namespace changed on re-init: %q → %q (must be immutable)", first.TenantNamespace, second.TenantNamespace)
	}
	if second.KeycloakAdminSetFromInput {
		t.Error("re-init re-set the admin secret; it must be reused, not re-prompted or rotated")
	}
	if calls != callsAfterFirst {
		t.Errorf("re-init prompted again (%d → %d calls); a provisioned secret must not re-prompt", callsAfterFirst, calls)
	}
	if second.KeycloakAdminPassword != first.KeycloakAdminPassword {
		t.Error("admin secret changed on re-init (must be immutable once provisioned)")
	}
}

// TestInit_ProvisionsAdminSecret: a fresh init persists the operator's chosen
// admin + postgres passwords (never a hardcoded default, never auto-generated),
// via either the interactive prompt or an explicit flag value.
func TestInit_ProvisionsAdminSecret(t *testing.T) {
	withConfigEnv(t)
	res, err := Init(promptStub())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !res.KeycloakAdminSetFromInput {
		t.Error("fresh init did not set the admin secret from input")
	}
	if res.KeycloakAdminPassword == "" || res.KeycloakAdminPassword == "admin" {
		t.Errorf("weak/empty admin password %q; want the operator-provided secret", res.KeycloakAdminPassword)
	}
	if !res.PostgresProvisioned {
		t.Error("fresh init did not provision the postgres role password")
	}
	// The postgres secret is the operator-provided value in the store, not a hardcoded default.
	if pg, ok, err := secrets.Open(filepath.Dir(res.ConfigPath)).Get(secrets.NamePostgres); err != nil || !ok {
		t.Fatalf("postgres secret not in store: ok=%v err=%v", ok, err)
	} else if pg == "" || pg == "reckon" {
		t.Errorf("weak/empty postgres password %q; want the operator-provided secret", pg)
	}

	// Explicit flag values are honored on a fresh install (no prompt needed).
	dir := t.TempDir()
	t.Setenv("RECKON_CONFIG", filepath.Join(dir, "config.yaml"))
	supplied, err := Init(InitOptions{KeycloakAdminPassword: "operator-chosen", PostgresPassword: "pg-chosen"})
	if err != nil {
		t.Fatalf("Init supplied: %v", err)
	}
	if supplied.KeycloakAdminPassword != "operator-chosen" {
		t.Errorf("supplied password not honored: got %q", supplied.KeycloakAdminPassword)
	}
	if !supplied.KeycloakAdminSetFromInput {
		t.Error("a supplied password on a fresh store should report set-from-input")
	}
}

// TestInit_NoSourceFailsFast: with no flag, no env, and no prompter (the
// non-interactive path), init must FAIL rather than auto-generate a credential —
// and must not leave a config behind, so the install stays cleanly re-runnable.
func TestInit_NoSourceFailsFast(t *testing.T) {
	path := withConfigEnv(t)
	if _, err := Init(InitOptions{}); err == nil {
		t.Fatal("init with no secret source and no prompter must fail fast, not auto-generate")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a failed no-source init left a config at %s (stat err=%v); secrets are provisioned first so nothing should be written", path, err)
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
	if res.KeycloakAdminSetFromInput {
		t.Error("an external KC admin secret must not be reported as set-from-input")
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
	a, err := Init(promptStub())
	if err != nil {
		t.Fatal(err)
	}
	// Point at a second, separate config location.
	dir := t.TempDir()
	t.Setenv("RECKON_CONFIG", filepath.Join(dir, "config.yaml"))
	b, err := Init(promptStub())
	if err != nil {
		t.Fatal(err)
	}
	if a.TenantNamespace == b.TenantNamespace {
		t.Errorf("two installs minted the same namespace %q", a.TenantNamespace)
	}
}

// TestInit_FixtureFree: a plain init wires NO capability layer — Capability
// .ConfigPath stays empty and demo.enabled is false — so a fresh install never
// runs fixtures. The demo world is opt-in via `reckon demo seed` (SeedDemo).
func TestInit_FixtureFree(t *testing.T) {
	withConfigEnv(t)
	if _, err := Init(promptStub()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Capability.ConfigPath != "" {
		t.Errorf("a plain init wired a capability config_path %q — the demo must be opt-in", cfg.Capability.ConfigPath)
	}
	if cfg.Demo.Enabled {
		t.Error("a plain init set demo.enabled — the demo must be opt-in")
	}
}

// TestSeedDemo_WiredDemo: SeedDemo materializes the demo scenario + a merged
// tenant config that is consumable by BOTH the capability (read) and action
// (write) loaders — the demo "runs out of the box" contract, now behind
// `reckon demo seed` rather than init. BuildResolver produces available verbs
// and BuildActionResolver produces write bindings, both against the seeded files
// (with demo=true, since the fixture guard requires it).
func TestSeedDemo_WiredDemo(t *testing.T) {
	base := t.TempDir()
	res, err := SeedDemo(base)
	if err != nil {
		t.Fatalf("SeedDemo: %v", err)
	}
	if res.Scenario == "" || res.CapabilityConfig == "" || res.FixtureRoot == "" {
		t.Fatalf("seed result incomplete: %+v", res)
	}

	// The fixture scenario JSON landed under the fixture root.
	if entries, err := os.ReadDir(filepath.Join(res.FixtureRoot, res.Scenario)); err != nil || len(entries) == 0 {
		t.Fatalf("fixture scenario not seeded (%v, %d files)", err, len(entries))
	}

	// The merged config is consumable by the READ loader — verbs light up.
	tc, err := capability.LoadTenantConfig(res.CapabilityConfig)
	if err != nil {
		t.Fatalf("capability.LoadTenantConfig on seeded config: %v", err)
	}
	resolver, catalog, err := capability.BuildResolver(tc, res.FixtureRoot, uuid.New(), true)
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
	if _, _, err := action.BuildActionResolver(ac, res.FixtureRoot, true); err != nil {
		t.Fatalf("BuildActionResolver on seeded config: %v", err)
	}

	// The fixture guard bites without demo mode: the same seeded config must be
	// refused when demo=false, so a real install can't run these fixtures.
	if _, _, err := capability.BuildResolver(tc, res.FixtureRoot, uuid.New(), false); err == nil {
		t.Error("BuildResolver accepted a fixture binding with demo=false — the guard is not enforced")
	}
	if _, _, err := action.BuildActionResolver(ac, res.FixtureRoot, false); err == nil {
		t.Error("BuildActionResolver accepted a fixture binding with demo=false — the guard is not enforced")
	}
}
