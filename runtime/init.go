package runtime

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/config"
)

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
func Init() (InitResult, error) {
	path, err := config.DefaultPath()
	if err != nil {
		return InitResult{}, err
	}

	// Idempotent: an existing config is left untouched (never clobber a config a
	// user may have hand-edited), reported back so the CLI can say so.
	if _, err := os.Stat(path); err == nil {
		cfg, perr := config.Load()
		if perr != nil {
			return InitResult{}, fmt.Errorf("a config exists at %s but does not parse: %w", path, perr)
		}
		return InitResult{
			ConfigPath:      path,
			TenantNamespace: cfg.Capability.TenantNamespace,
			DataDir:         cfg.Data.Dir,
			AlreadyExisted:  true,
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
	return InitResult{
		ConfigPath:       path,
		TenantNamespace:  namespace,
		DataDir:          cfg.Data.Dir,
		SeededScenario:   seed.Scenario,
		CapabilityConfig: seed.CapabilityConfig,
		FixtureRoot:      seed.FixtureRoot,
	}, nil
}
