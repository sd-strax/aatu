package action

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/sd-strax/reckon/capability"
)

// TenantActionConfig is the write-side tenant config (08 §4): which write
// adapters are enabled and how each action type binds to them. It can live in
// its own file or share the capability config file (unknown keys are ignored),
// under the action_adapters / action_bindings keys.
type TenantActionConfig struct {
	Adapters map[string]ActionAdapterSpec `yaml:"action_adapters"`
	Bindings map[string][]ActionBinding   `yaml:"action_bindings"`
}

// ActionAdapterSpec configures one write-adapter instance. The fixture class
// replays declared WriteResults; every other class is an out-of-process plugin
// (11 §2) reached through the injected plugin host. The enablement fields
// (11 §5) are ignored for the fixture class. Writes take NO wildcard — every
// action operation is named individually (11 §5, the read/write asymmetry).
type ActionAdapterSpec struct {
	Class   capability.AdapterClass `yaml:"class"`
	Enabled bool                    `yaml:"enabled"`
	// Scenario is the fixture scenario directory (fixture class only).
	Scenario string `yaml:"scenario"`
	// Adapter is the installed plugin this instance runs (11 §5 named
	// instances); defaults to the stanza key. Plugin classes only.
	Adapter string `yaml:"adapter"`
	// Config is delivered to the plugin's `configure` handshake (11 §4.3).
	Config map[string]any `yaml:"config"`
	// Actions is the per-op write allowlist (11 §5): the action operations this
	// instance may dispatch. No wildcard. Plugin classes only.
	Actions []string `yaml:"actions"`
	// Scope is the optional source scope (03 §3.5): the organization whose
	// credentials this instance holds. Empty means unscoped. A scoped instance
	// dispatches only for investigations carrying the identical scope; its
	// bindings inherit it.
	Scope string `yaml:"scope"`
}

// LoadActionConfig reads and parses a write-side tenant config file.
func LoadActionConfig(path string) (TenantActionConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TenantActionConfig{}, fmt.Errorf("read action config %s: %w", path, err)
	}
	var cfg TenantActionConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return TenantActionConfig{}, fmt.Errorf("parse action config %s: %w", path, err)
	}
	return cfg, nil
}

// BuildActionResolver constructs the action resolver + catalog from a tenant
// config against the fixture layer only. It is the no-plugins case of
// BuildActionResolverWithAdapters.
func BuildActionResolver(cfg TenantActionConfig, fixtureRoot string) (*ActionResolver, *ActionCatalog, error) {
	return BuildActionResolverWithAdapters(cfg, fixtureRoot, nil)
}

// BuildActionResolverWithAdapters constructs the action resolver + catalog from
// a tenant config. fixtureRoot is where write-fixture scenarios live. plugins
// supplies the already-constructed out-of-process write facades keyed by
// instance name (11 §2) — the fixture class is built here, every other class is
// looked up there. Only enabled adapters are wired; binding templates are
// validated up front (08 §4).
func BuildActionResolverWithAdapters(cfg TenantActionConfig, fixtureRoot string, plugins map[string]WriteAdapter) (*ActionResolver, *ActionCatalog, error) {
	adapters := make(map[string]WriteAdapter)
	for name, spec := range cfg.Adapters {
		if !spec.Enabled {
			continue
		}
		switch spec.Class {
		case capability.ClassFixture:
			adapters[name] = NewFixtureWriteAdapter(fixtureRoot, spec.Scenario)
		default:
			p, ok := plugins[name]
			if !ok {
				return nil, nil, fmt.Errorf("write adapter %q: class %q is an out-of-process plugin but no adapter was provided — is it installed under <data>/adapters and enabled? (11 §2)", name, spec.Class)
			}
			adapters[name] = p
		}
	}
	if err := ValidateActionBindings(cfg.Bindings); err != nil {
		return nil, nil, err
	}
	// Each binding inherits its instance's source scope (03 §3.5): scope lives on
	// the instance, never in binding YAML (the field is yaml:"-"), so we stamp it
	// from the ActionAdapterSpec here.
	bindings := make(map[string][]ActionBinding, len(cfg.Bindings))
	for at, bs := range cfg.Bindings {
		scoped := make([]ActionBinding, len(bs))
		for i, b := range bs {
			b.Scope = cfg.Adapters[b.Adapter].Scope
			scoped[i] = b
		}
		bindings[at] = scoped
	}
	return NewActionResolver(bindings, adapters), DefaultActionCatalog(), nil
}
