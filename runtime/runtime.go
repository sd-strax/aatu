package runtime

import (
	"fmt"
	"log"

	"github.com/sd-strax/aatu/config"
	"github.com/sd-strax/aatu/module"
)

// Config is the runtime configuration passed to a ModuleBuilder. Today it
// is the full deployment config; a future refactor may split runtime-only
// concerns (logging, metrics, supervisor options) from the deployment shape.
type Config = config.Config

// ModuleBuilder constructs the module Registry from a loaded Config.
//
// Both binaries inject one. The OSS binary returns disabled stubs
// unconditionally; the paid binary inspects cfg.Paid.* and returns real
// implementations when enabled, stubs when not. This is the only place where
// OSS and paid main packages diverge.
type ModuleBuilder func(Config) module.Registry

// Run loads configuration, builds the module registry, and (in future
// commits) starts the supervisor + server. Today it logs the activation
// shape and returns nil — proof the seam works end-to-end.
//
// Errors from config loading propagate; ModuleBuilder is assumed to be
// total (panics escape).
func Run(build ModuleBuilder) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	reg := build(cfg)

	// Warn if paid keys are set but the registry has no real paid module —
	// this is an OSS binary running against a config that wants paid behavior.
	if cfg.Paid.Tenancy.Enabled && !reg.Tenancy.Enabled() {
		log.Println("WARN: paid.tenancy.enabled set but no paid tenancy module loaded (OSS binary)")
	}
	if cfg.Paid.Governance.Enabled && !reg.Governance.Enabled() {
		log.Println("WARN: paid.governance.enabled set but no paid governance module loaded (OSS binary)")
	}

	log.Printf("aatu engine ready, tenancy=%v governance=%v",
		reg.Tenancy.Enabled(), reg.Governance.Enabled())
	return nil
}
