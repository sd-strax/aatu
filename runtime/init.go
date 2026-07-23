package runtime

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/secrets"
)

// InitOptions parameterizes the deployer step.
type InitOptions struct {
	// KeycloakAdminPassword, when non-empty, is provisioned as the Keycloak
	// master-admin password (operator/IaC supplied). Empty generates a strong
	// random one. Applied only when the secret is absent — init never rotates.
	KeycloakAdminPassword string
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
	// secret store after init; KeycloakAdminGenerated is true when THIS run
	// generated it (so the CLI prints it exactly once, on creation).
	KeycloakAdminPassword  string
	KeycloakAdminGenerated bool
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
		pw, generated, serr := provisionSecrets(filepath.Dir(path), opts)
		if serr != nil {
			return InitResult{}, serr
		}
		return InitResult{
			ConfigPath:             path,
			TenantNamespace:        cfg.Capability.TenantNamespace,
			DataDir:                cfg.Data.Dir,
			AlreadyExisted:         true,
			KeycloakAdminPassword:  pw,
			KeycloakAdminGenerated: generated,
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
	// master-admin password lands beside the config in <install>/secrets, 0600 —
	// never in the config file. The install dir is the config's directory (the
	// same anchor the demo content uses), which equals Data.Dir in the default
	// layout and stays isolated under an explicit config path.
	pw, generated, err := provisionSecrets(filepath.Dir(path), opts)
	if err != nil {
		return InitResult{}, err
	}

	return InitResult{
		ConfigPath:             path,
		TenantNamespace:        namespace,
		DataDir:                cfg.Data.Dir,
		SeededScenario:         seed.Scenario,
		CapabilityConfig:       seed.CapabilityConfig,
		FixtureRoot:            seed.FixtureRoot,
		KeycloakAdminPassword:  pw,
		KeycloakAdminGenerated: generated,
	}, nil
}

// provisionSecrets establishes the install's secrets idempotently under
// installDir. Supplied values win when the secret is absent; otherwise a strong
// random one is generated. An already-provisioned secret is returned unchanged
// (created=false) — re-running init never rotates.
func provisionSecrets(installDir string, opts InitOptions) (kcAdmin string, generated bool, err error) {
	store := secrets.Open(installDir)
	if opts.KeycloakAdminPassword != "" {
		pw, created, verr := store.EnsureValue(secrets.NameKeycloakAdmin, opts.KeycloakAdminPassword)
		// A supplied value on an already-provisioned store is a no-op, not a
		// generated secret — so created is false and the CLI won't echo it.
		return pw, created, verr
	}
	return store.EnsureRandom(secrets.NameKeycloakAdmin)
}
