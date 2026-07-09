package capability

import (
	"fmt"
	"os"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/sd-strax/reckon/identity"
)

// TenantConfig is the per-tenant capability configuration (§3.2): which adapters
// are enabled and how each verb binds to them. Loaded from YAML at startup.
type TenantConfig struct {
	Tenant   string                   `yaml:"tenant"`
	Adapters map[string]AdapterSpec   `yaml:"adapters"`
	Bindings map[string][]BindingSpec `yaml:"bindings"`
	Policies map[string]any           `yaml:"policies"`
}

// AdapterSpec configures one adapter instance. v0 supports only the fixture
// class; native_api/mcp/custom carry connection fields consumed in later phases.
type AdapterSpec struct {
	Class    AdapterClass `yaml:"class"`
	Enabled  bool         `yaml:"enabled"`
	Scenario string       `yaml:"scenario"` // fixture: the scenario directory
}

// BindingSpec is the YAML shape of a Binding.
type BindingSpec struct {
	Adapter   string         `yaml:"adapter"`
	Operation string         `yaml:"operation"`
	Priority  int            `yaml:"priority"`
	Params    map[string]any `yaml:"params"`
	FanOut    bool           `yaml:"fanout"`
}

// LoadTenantConfig reads and parses a tenant capability config file.
func LoadTenantConfig(path string) (TenantConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TenantConfig{}, fmt.Errorf("read capability config %s: %w", path, err)
	}
	var cfg TenantConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return TenantConfig{}, fmt.Errorf("parse capability config %s: %w", path, err)
	}
	return cfg, nil
}

// BuildResolver constructs a Resolver, its normalizer Registry, and the verb
// Catalog from a tenant config. fixtureRoot is the directory fixture scenarios
// live under; namespace is the tenant's identity namespace (§7.1). Only enabled
// adapters are instantiated; a non-fixture class is rejected in v0. Binding
// templates are validated up front (§3.3.4).
func BuildResolver(cfg TenantConfig, fixtureRoot string, namespace uuid.UUID) (*Resolver, *Catalog, error) {
	adapters := make(map[string]Adapter)
	for name, spec := range cfg.Adapters {
		if !spec.Enabled {
			continue
		}
		switch spec.Class {
		case ClassFixture:
			adapters[name] = NewFixtureAdapter(fixtureRoot, spec.Scenario)
		default:
			return nil, nil, fmt.Errorf("adapter %q: class %q not supported in v0 (fixture only)", name, spec.Class)
		}
	}

	bindings := make(map[string][]Binding, len(cfg.Bindings))
	for verb, specs := range cfg.Bindings {
		for _, s := range specs {
			// BindingSpec and Binding share their fields (the spec adds only YAML
			// tags), so a direct conversion keeps them in lockstep.
			bindings[verb] = append(bindings[verb], Binding(s))
		}
	}
	if err := ValidateBindings(bindings); err != nil {
		return nil, nil, err
	}

	resolver := NewResolver(
		TenantContext{Name: cfg.Tenant, Policies: cfg.Policies},
		bindings,
		adapters,
		NewRegistry(identity.NewResolver(namespace)),
	)
	return resolver, DefaultCatalog(), nil
}
