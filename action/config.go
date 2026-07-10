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

// ActionAdapterSpec configures one write-adapter instance. v0 supports only the
// fixture class; real vendor write adapters land in Phase F.
type ActionAdapterSpec struct {
	Class    capability.AdapterClass `yaml:"class"`
	Enabled  bool                    `yaml:"enabled"`
	Scenario string                  `yaml:"scenario"` // fixture: the scenario directory
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
// config. fixtureRoot is where write-fixture scenarios live. Only enabled
// adapters are instantiated; a non-fixture class is rejected in v0. Binding
// templates are validated up front (08 §4).
func BuildActionResolver(cfg TenantActionConfig, fixtureRoot string) (*ActionResolver, *ActionCatalog, error) {
	adapters := make(map[string]WriteAdapter)
	for name, spec := range cfg.Adapters {
		if !spec.Enabled {
			continue
		}
		switch spec.Class {
		case capability.ClassFixture:
			adapters[name] = NewFixtureWriteAdapter(fixtureRoot, spec.Scenario)
		default:
			return nil, nil, fmt.Errorf("write adapter %q: class %q not supported in v0 (fixture only)", name, spec.Class)
		}
	}
	if err := ValidateActionBindings(cfg.Bindings); err != nil {
		return nil, nil, err
	}
	return NewActionResolver(cfg.Bindings, adapters), DefaultActionCatalog(), nil
}
