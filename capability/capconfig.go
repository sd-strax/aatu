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

// AdapterSpec configures one adapter instance. The fixture class replays local
// scenario data; every other class is an out-of-process plugin (11 §2) reached
// through the injected plugin host. The enablement fields (11 §5) — the
// instance→install mapping, per-instance config, and the per-op reads list —
// are ignored for the fixture class.
type AdapterSpec struct {
	Class   AdapterClass `yaml:"class"`
	Enabled bool         `yaml:"enabled"`
	// Scenario is the fixture scenario directory (fixture class only).
	Scenario string `yaml:"scenario"`
	// Adapter is the installed plugin this instance runs (11 §5 named
	// instances); defaults to the stanza key. Plugin classes only.
	Adapter string `yaml:"adapter"`
	// Config is the instance configuration delivered to the plugin's `configure`
	// handshake (11 §4.3); x-secret fields carry secret references, never
	// literals. Plugin classes only.
	Config map[string]any `yaml:"config"`
	// Reads is the per-op read allowlist (11 §5): the operations this instance
	// may serve. `["all"]` is the one wildcard the read side permits. Plugin
	// classes only.
	Reads []string `yaml:"reads"`
	// Scope is the optional source scope (03 §3.5): the organization whose
	// credentials this instance holds. Empty means unscoped — the instance serves
	// every investigation (single-organization deployments and genuinely shared
	// tools like threat intel). A non-empty scope restricts the instance to
	// investigations carrying the identical scope, and its bindings inherit it.
	Scope string `yaml:"scope"`
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
// Catalog from a tenant config against the fixture layer only. It is the
// no-plugins case of BuildResolverWithAdapters.
func BuildResolver(cfg TenantConfig, fixtureRoot string, namespace uuid.UUID) (*Resolver, *Catalog, error) {
	return BuildResolverWithAdapters(cfg, fixtureRoot, namespace, nil)
}

// BuildResolverWithAdapters constructs the read resolver, its normalizer
// Registry, and the verb Catalog from a tenant config. fixtureRoot is the
// directory fixture scenarios live under; namespace is the tenant's identity
// namespace (§7.1). plugins supplies the already-constructed out-of-process
// adapter facades keyed by instance name (11 §2) — the fixture class is built
// here, every other class is looked up there. Only enabled adapters are wired;
// binding templates are validated up front (§3.3.4).
func BuildResolverWithAdapters(cfg TenantConfig, fixtureRoot string, namespace uuid.UUID, plugins map[string]Adapter) (*Resolver, *Catalog, error) {
	adapters := make(map[string]Adapter)
	for name, spec := range cfg.Adapters {
		if !spec.Enabled {
			continue
		}
		switch spec.Class {
		case ClassFixture:
			adapters[name] = NewFixtureAdapter(fixtureRoot, spec.Scenario)
		default:
			p, ok := plugins[name]
			if !ok {
				return nil, nil, fmt.Errorf("adapter %q: class %q is an out-of-process plugin but no adapter was provided — is it installed under <data>/adapters and enabled? (11 §2)", name, spec.Class)
			}
			adapters[name] = p
		}
	}

	bindings := make(map[string][]Binding, len(cfg.Bindings))
	for verb, specs := range cfg.Bindings {
		for _, s := range specs {
			// A binding inherits its instance's source scope (03 §3.5): scope lives
			// on the instance (it holds one organization's credentials), never in
			// binding YAML. cfg.Adapters[s.Adapter].Scope is the empty string for
			// an unscoped instance or an unknown adapter (which fails elsewhere).
			bindings[verb] = append(bindings[verb], Binding{
				Adapter:   s.Adapter,
				Operation: s.Operation,
				Priority:  s.Priority,
				Params:    s.Params,
				FanOut:    s.FanOut,
				Scope:     cfg.Adapters[s.Adapter].Scope,
			})
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
