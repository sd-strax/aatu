package capability

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

const sampleTenantYAML = `
tenant: acme
adapters:
  fixture:
    class: fixture
    enabled: true
    scenario: s
  crowdstrike:
    class: native_api
    enabled: false
bindings:
  enumerate_logons:
    - adapter: fixture
      operation: replay
      priority: 100
      params:
        target:
          hostname: "${entity.host.hostname}"
        outcome: SUCCESS
policies:
  default_window:
    investigation: PT24H
`

// TestLoadAndBuildResolver parses a tenant config, builds the resolver against a
// fixture scenario on disk, and resolves a verb end to end.
func TestLoadAndBuildResolver(t *testing.T) {
	root := writeScenario(t, "s", twoLogonsPlusOther)

	cfgPath := filepath.Join(t.TempDir(), "cap.yaml")
	if err := os.WriteFile(cfgPath, []byte(sampleTenantYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadTenantConfig(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Tenant != "acme" {
		t.Errorf("tenant = %q; want acme", cfg.Tenant)
	}

	res, catalog, err := BuildResolver(cfg, root, uuid.New(), true)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// The disabled native_api adapter must not be instantiated (would error in
	// v0); only fixture is present, so enumerate_logons is available.
	if got := res.AvailableVerbs(catalog); len(got) != 1 || got[0] != "enumerate_logons" {
		t.Errorf("available verbs = %v; want [enumerate_logons]", got)
	}

	out, err := res.Resolve(context.Background(), "enumerate_logons", CallInput{
		Entity: map[string]any{"host": map[string]any{"hostname": "WIN-FILE01"}},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out.Coverage != CoverageComplete || len(out.ObservedDataRefs) != 2 {
		t.Errorf("resolve: coverage=%q refs=%d; want COMPLETE/2", out.Coverage, len(out.ObservedDataRefs))
	}
}

// TestBuildResolverRejectsUnbackedPlugin: an enabled plugin-class adapter with
// no injected process is a config error (the install is missing or disabled),
// not a silent skip.
func TestBuildResolverRejectsUnbackedPlugin(t *testing.T) {
	cfg := TenantConfig{
		Adapters: map[string]AdapterSpec{"cs": {Class: ClassNativeAPI, Enabled: true}},
	}
	if _, _, err := BuildResolver(cfg, t.TempDir(), uuid.New(), true); err == nil {
		t.Error("BuildResolver accepted a plugin-class adapter with no backing process")
	}
}

// TestBuildResolverWithInjectedPlugin: a plugin-class adapter provided in the
// injected map is wired without the resolver trying to build it as a fixture
// (the out-of-process wiring seam, 11 §2).
func TestBuildResolverWithInjectedPlugin(t *testing.T) {
	cfg := TenantConfig{
		Adapters: map[string]AdapterSpec{"cs": {Class: ClassNativeAPI, Enabled: true, Reads: []string{"op"}}},
	}
	plugins := map[string]Adapter{"cs": healthyStub("cs")}
	if _, _, err := BuildResolverWithAdapters(cfg, t.TempDir(), uuid.New(), plugins, true); err != nil {
		t.Fatalf("BuildResolverWithAdapters with an injected plugin: %v", err)
	}
}

// TestBuildResolverValidatesTemplates: a bad binding template fails the build.
func TestBuildResolverValidatesTemplates(t *testing.T) {
	cfg := TenantConfig{
		Bindings: map[string][]BindingSpec{
			"v": {{Adapter: "fixture", Params: map[string]any{"x": "${entity.a | bogus}"}}},
		},
	}
	if _, _, err := BuildResolver(cfg, t.TempDir(), uuid.New(), true); err == nil {
		t.Error("BuildResolver accepted an unknown transform")
	}
}
