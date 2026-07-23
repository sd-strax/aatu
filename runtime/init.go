package runtime

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/secrets"
)

// InitOptions parameterizes the deployer step. A credential is NEVER
// auto-generated — it enters only by an explicit act. For each secret, in
// precedence order: an explicit value (flag) is persisted to the store; the
// External flag means "injected at runtime via env — do NOT persist" (the
// vault/operator path, so nothing rests on disk); otherwise, if the secret is
// absent and PromptForSecret is set, the operator is prompted and that value is
// persisted. A secret with none of these (and not already provisioned) is a
// fail-fast error. Supplied/prompted values are applied only when the secret is
// absent — init never rotates.
type InitOptions struct {
	// KeycloakAdminPassword is an explicit master-admin password to persist.
	KeycloakAdminPassword string
	// KeycloakAdminExternal skips persisting the master-admin password (env-injected).
	KeycloakAdminExternal bool
	// PostgresPassword is an explicit Postgres role password to persist.
	PostgresPassword string
	// PostgresExternal skips persisting the Postgres password (env-injected).
	PostgresExternal bool

	// PromptForSecret, when non-nil, supplies a password for a secret that is
	// absent and has no other source (no flag, no env). The CLI wires this to a
	// no-echo TTY prompt; it is the ONLY interactive path and the reason init
	// never needs to auto-generate. Nil (tests, non-interactive `init`) turns a
	// no-source secret into a fail-fast error instead. name is the well-known
	// secrets.Name*; label is a human phrase for the prompt.
	PromptForSecret func(name, label string) (string, error)
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
	// secret store after init. KeycloakAdminSetFromInput is true when THIS run set
	// it from operator input (a --kc-admin-password flag or the interactive
	// prompt) — never echoed, the operator already has it. False means the secret
	// already existed (idempotent no-op) or is External. Nothing is ever generated.
	KeycloakAdminPassword     string
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
			ConfigPath:                path,
			TenantNamespace:           cfg.Capability.TenantNamespace,
			DataDir:                   cfg.Data.Dir,
			AlreadyExisted:            true,
			KeycloakAdminPassword:     p.kcAdmin,
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

	// Establish this install's secrets FIRST (the deployer step's job): the
	// Keycloak master-admin and Postgres role passwords land beside the config in
	// <install>/secrets, 0600 — never in the config file. The install dir is the
	// config's directory (the same anchor the demo content uses), which equals
	// Data.Dir in the default layout and stays isolated under an explicit config
	// path. Doing it before the config/demo writes means a cancelled interactive
	// prompt (the no-auto-generate path) commits NOTHING — the install stays fresh
	// and re-runnable rather than half-written.
	p, err := provisionSecrets(filepath.Dir(path), opts)
	if err != nil {
		return InitResult{}, err
	}

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

	return InitResult{
		ConfigPath:                path,
		TenantNamespace:           namespace,
		DataDir:                   cfg.Data.Dir,
		SeededScenario:            seed.Scenario,
		CapabilityConfig:          seed.CapabilityConfig,
		FixtureRoot:               seed.FixtureRoot,
		KeycloakAdminPassword:     p.kcAdmin,
		KeycloakAdminSetFromInput: p.kcSetFromInput,
		KeycloakAdminExternal:     opts.KeycloakAdminExternal,
		PostgresProvisioned:       p.pgProvisioned,
		PostgresExternal:          opts.PostgresExternal,
	}, nil
}

// provisioned reports the outcome of establishing the install's secrets.
type provisioned struct {
	kcAdmin        string
	kcSetFromInput bool // the KC admin password was set from operator input this run (flag or prompt)
	pgProvisioned  bool // the Postgres password now lives in the store
}

// provisionSecrets establishes the install's secrets idempotently under
// installDir. Nothing is auto-generated: for each secret, an External one is
// left unpersisted (env-injected at runtime); otherwise a supplied value, else
// an interactive prompt (opts.PromptForSecret), establishes it — and with none
// of these it is a fail-fast error. An already-provisioned secret is returned
// unchanged — re-running init never rotates.
func provisionSecrets(installDir string, opts InitOptions) (provisioned, error) {
	store := secrets.Open(installDir)

	kcAdmin, kcCreated, err := ensureSecret(store, secretSpec{
		name:     secrets.NameKeycloakAdmin,
		envVar:   secrets.EnvKeycloakAdmin,
		flag:     "--kc-admin-password",
		label:    "Keycloak master-admin password",
		supplied: opts.KeycloakAdminPassword,
		external: opts.KeycloakAdminExternal,
	}, opts.PromptForSecret)
	if err != nil {
		return provisioned{}, err
	}
	if _, _, err := ensureSecret(store, secretSpec{
		name:     secrets.NamePostgres,
		envVar:   secrets.EnvPostgres,
		flag:     "--postgres-password",
		label:    "Postgres role password",
		supplied: opts.PostgresPassword,
		external: opts.PostgresExternal,
	}, opts.PromptForSecret); err != nil {
		return provisioned{}, err
	}

	return provisioned{
		kcAdmin:        kcAdmin,
		kcSetFromInput: kcCreated,
		pgProvisioned:  !opts.PostgresExternal,
	}, nil
}

// secretSpec names one install secret and every way it may be sourced, so
// ensureSecret can both establish it and emit a precise fail-fast message.
type secretSpec struct {
	name     string // secrets.Name* (store basename)
	envVar   string // secrets.Env* (runtime injection var)
	flag     string // the `reckon init` flag that persists an explicit value
	label    string // human phrase for the interactive prompt
	supplied string // explicit value from the flag ("" if not given)
	external bool    // env-injected: do not persist
}

// ensureSecret establishes one secret, NEVER auto-generating it. Precedence:
// external (env-injected → left unpersisted); a supplied flag value (persisted
// when absent); already provisioned (returned unchanged — idempotent); an
// interactive prompt when one is available; otherwise a fail-fast error naming
// every source. Returns the effective value and whether THIS call set it from
// operator input (flag or prompt). Both zero for external or already-present.
func ensureSecret(store *secrets.Store, spec secretSpec, prompt func(name, label string) (string, error)) (value string, setFromInput bool, err error) {
	if spec.external {
		return "", false, nil
	}
	if spec.supplied != "" {
		v, created, err := store.EnsureValue(spec.name, spec.supplied)
		return v, created, err
	}
	// Already provisioned? Reuse it — init never rotates and never re-prompts.
	if existing, ok, err := store.Get(spec.name); err != nil {
		return "", false, err
	} else if ok {
		return existing, false, nil
	}
	// Absent with no flag/env source. Prompt if we can; never generate.
	if prompt == nil {
		return "", false, fmt.Errorf(
			"no password for %q and none can be prompted (non-interactive): set %s, pass %s, or run `reckon init` from a terminal — no credential is ever auto-generated",
			spec.name, spec.envVar, spec.flag)
	}
	v, err := prompt(spec.name, spec.label)
	if err != nil {
		return "", false, fmt.Errorf("prompt for %q: %w", spec.name, err)
	}
	if v == "" {
		return "", false, fmt.Errorf("empty password entered for %q", spec.name)
	}
	stored, created, err := store.EnsureValue(spec.name, v)
	return stored, created, err
}
