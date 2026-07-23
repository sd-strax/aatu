package runtime

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/secrets"
)

// InitOptions parameterizes the deployer step. For each secret: an explicit
// value is persisted to the store; empty generates a strong random one; the
// External flag means "injected at runtime via env — do NOT persist" (the
// vault/operator path, so nothing rests on disk). Supplied values are applied
// only when the secret is absent — init never rotates.
type InitOptions struct {
	// KeycloakAdminPassword is an explicit master-admin password to persist.
	KeycloakAdminPassword string
	// KeycloakAdminExternal skips persisting the master-admin password (env-injected).
	KeycloakAdminExternal bool
	// PostgresPassword is an explicit Postgres role password to persist.
	PostgresPassword string
	// PostgresExternal skips persisting the Postgres password (env-injected).
	PostgresExternal bool
}

// InitResult reports what `reckon init` wrote, so the CLI can print a first-run
// summary + next steps.
type InitResult struct {
	ConfigPath      string
	TenantNamespace string
	DataDir         string
	AlreadyExisted  bool // true when a config was already present and left untouched

	// SeededScenario is the demo fixture scenario materialized on a fresh init
	// (empty when AlreadyExisted, since seeding rides the fresh-config path).
	// CapabilityConfig is the merged read+write tenant config the config now
	// points at; FixtureRoot is where the fixture JSON was written.
	SeededScenario   string
	CapabilityConfig string
	FixtureRoot      string

	// KeycloakAdminPassword is the effective master-admin password in the install
	// secret store after init. KeycloakAdminGenerated is true only when THIS run
	// GENERATED a random one (the CLI echoes it once — the only way to learn it);
	// KeycloakAdminSetFromInput is true when this run set it from an operator-
	// supplied value (never echoed — the operator already has it). Both false
	// means the secret already existed (idempotent no-op).
	KeycloakAdminPassword     string
	KeycloakAdminGenerated    bool
	KeycloakAdminSetFromInput bool

	// PostgresProvisioned is true when the Postgres role password now exists in
	// the store (generated this run or already present). Its value is internal —
	// only the stack consumes it — so it is not surfaced for printing.
	PostgresProvisioned bool

	// KeycloakAdminExternal / PostgresExternal are true when that secret is
	// env-injected at runtime and deliberately NOT persisted to the store, so
	// the CLI reports it as such rather than as provisioned.
	KeycloakAdminExternal bool
	PostgresExternal      bool
}

// Init performs first-run setup: it writes a default config to the resolved
// config path (the same path `reckon start` will read), minting a FRESH tenant
// identity namespace (03 §7.1) unique to this install rather than the shared
// fixed default — so deterministic STIX ids computed here never collide with
// another install's. It refuses to clobber an existing config (returns it with
// AlreadyExisted set), so re-running init is a safe no-op.
//
// It also seeds the bundled demo: the fixture scenario JSON and a merged
// capability+action tenant config are materialized under the config directory,
// and the config is pointed at them, so a fresh install serves /api/capabilities
// and can run the fixture action path with no further setup. Seeding writes only
// its own files (never the config.yaml Save guards) and lands beside the config,
// so it is isolated from other installs.
//
// Interactive Keycloak login is the surface's job; this owns the deterministic,
// testable core (config + namespace + demo content) the login builds on.
func Init(opts InitOptions) (InitResult, error) {
	path, err := config.DefaultPath()
	if err != nil {
		return InitResult{}, err
	}

	// Idempotent: an existing config is left untouched (never clobber a config a
	// user may have hand-edited), reported back so the CLI can say so. Secret
	// provisioning still runs on this path — an install predating the secret
	// store (or with a wiped secrets dir) gets its admin password established
	// without re-initializing everything else.
	if _, err := os.Stat(path); err == nil {
		cfg, perr := config.Load()
		if perr != nil {
			return InitResult{}, fmt.Errorf("a config exists at %s but does not parse: %w", path, perr)
		}
		p, serr := provisionSecrets(filepath.Dir(path), opts)
		if serr != nil {
			return InitResult{}, serr
		}
		return InitResult{
			ConfigPath:             path,
			TenantNamespace:        cfg.Capability.TenantNamespace,
			DataDir:                cfg.Data.Dir,
			AlreadyExisted:            true,
			KeycloakAdminPassword:     p.kcAdmin,
			KeycloakAdminGenerated:    p.kcGenerated,
			KeycloakAdminSetFromInput: p.kcSetFromInput,
			KeycloakAdminExternal:     opts.KeycloakAdminExternal,
			PostgresProvisioned:       p.pgProvisioned,
			PostgresExternal:          opts.PostgresExternal,
		}, nil
	} else if !os.IsNotExist(err) {
		return InitResult{}, fmt.Errorf("stat config %s: %w", path, err)
	}

	cfg := config.Default()
	// A unique per-install identity namespace. The default config carries a
	// fixed OSS namespace (fine for fixtures/tests); a real install gets its own
	// immutable one so ids are stable here yet distinct from other installs.
	namespace := uuid.New().String()
	cfg.Capability.TenantNamespace = namespace

	// Seed the demo content beside the config (filepath.Dir(path) is the install's
	// config directory, ~/<data>/ in production) and wire the config at it, so the
	// bundled scenario runs out of the box. Isolated per-install because it lands
	// next to the resolved config path, which tests point at a temp dir.
	seed, err := seedDemoContent(filepath.Dir(path))
	if err != nil {
		return InitResult{}, fmt.Errorf("seed demo content: %w", err)
	}
	cfg.Capability.FixtureRoot = seed.FixtureRoot
	cfg.Capability.ConfigPath = seed.CapabilityConfig

	if err := config.Save(cfg, path); err != nil {
		return InitResult{}, fmt.Errorf("write config: %w", err)
	}

	// Establish this install's secrets (the deployer step's job): the Keycloak
	// master-admin and Postgres role passwords land beside the config in
	// <install>/secrets, 0600 — never in the config file. The install dir is the
	// config's directory (the same anchor the demo content uses), which equals
	// Data.Dir in the default layout and stays isolated under an explicit config
	// path.
	p, err := provisionSecrets(filepath.Dir(path), opts)
	if err != nil {
		return InitResult{}, err
	}

	return InitResult{
		ConfigPath:             path,
		TenantNamespace:        namespace,
		DataDir:                cfg.Data.Dir,
		SeededScenario:            seed.Scenario,
		CapabilityConfig:          seed.CapabilityConfig,
		FixtureRoot:               seed.FixtureRoot,
		KeycloakAdminPassword:     p.kcAdmin,
		KeycloakAdminGenerated:    p.kcGenerated,
		KeycloakAdminSetFromInput: p.kcSetFromInput,
		KeycloakAdminExternal:     opts.KeycloakAdminExternal,
		PostgresProvisioned:       p.pgProvisioned,
		PostgresExternal:          opts.PostgresExternal,
	}, nil
}

// provisioned reports the outcome of establishing the install's secrets.
type provisioned struct {
	kcAdmin        string
	kcGenerated    bool // a random KC admin password was generated this run
	kcSetFromInput bool // the KC admin password was set from a supplied value this run
	pgProvisioned  bool // the Postgres password now lives in the store
}

// provisionSecrets establishes the install's secrets idempotently under
// installDir. An External secret is left unpersisted (env-injected at runtime).
// Otherwise a supplied value wins when the secret is absent, else a strong
// random one is generated. An already-provisioned secret is returned unchanged —
// re-running init never rotates.
func provisionSecrets(installDir string, opts InitOptions) (provisioned, error) {
	store := secrets.Open(installDir)

	kcAdmin, kcCreated, err := ensureSecret(store, secrets.NameKeycloakAdmin, opts.KeycloakAdminPassword, opts.KeycloakAdminExternal)
	if err != nil {
		return provisioned{}, err
	}
	if _, _, err := ensureSecret(store, secrets.NamePostgres, opts.PostgresPassword, opts.PostgresExternal); err != nil {
		return provisioned{}, err
	}

	return provisioned{
		kcAdmin:        kcAdmin,
		kcGenerated:    kcCreated && opts.KeycloakAdminPassword == "" && !opts.KeycloakAdminExternal,
		kcSetFromInput: kcCreated && opts.KeycloakAdminPassword != "",
		pgProvisioned:  !opts.PostgresExternal,
	}, nil
}

// ensureSecret provisions name unless it is external (env-injected — left
// unpersisted). Otherwise a supplied value is written when absent, else a strong
// random one is generated. Returns the effective value and whether THIS call
// created it (both zero for an external secret).
func ensureSecret(store *secrets.Store, name, supplied string, external bool) (value string, created bool, err error) {
	if external {
		return "", false, nil
	}
	if supplied != "" {
		return store.EnsureValue(name, supplied)
	}
	return store.EnsureRandom(name)
}
