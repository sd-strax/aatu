package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sd-strax/reckon/internal/branding"
)

func TestDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Deployment.Mode != "oss" {
		t.Errorf("default mode = %q; want %q", cfg.Deployment.Mode, "oss")
	}
	if cfg.Paid.Tenancy.Enabled || cfg.Paid.Governance.Enabled {
		t.Errorf("default paid modules enabled: %+v", cfg.Paid)
	}
	if cfg.Paid.Governance.Mode != "lightweight" {
		t.Errorf("default governance mode = %q; want %q", cfg.Paid.Governance.Mode, "lightweight")
	}
	if cfg.Postgres.Port != 5435 {
		t.Errorf("default postgres port = %d; want 5435", cfg.Postgres.Port)
	}
	if cfg.Data.Dir == "" {
		t.Errorf("default data dir is empty")
	}
	if cfg.Temporal.FrontendPort != 7233 {
		t.Errorf("default temporal frontend port = %d; want 7233", cfg.Temporal.FrontendPort)
	}
	if !cfg.Temporal.UIEnabled {
		t.Errorf("default temporal UIEnabled = false; want true")
	}
	if cfg.Temporal.Namespace != "default" {
		t.Errorf("default temporal namespace = %q; want %q", cfg.Temporal.Namespace, "default")
	}
	if cfg.Keycloak.HTTPPort != 8543 {
		t.Errorf("default keycloak http port = %d; want 8543", cfg.Keycloak.HTTPPort)
	}
	if cfg.Keycloak.ManagementPort != 9543 {
		t.Errorf("default keycloak management port = %d; want 9543", cfg.Keycloak.ManagementPort)
	}
	if cfg.Keycloak.Realm != branding.CLI {
		t.Errorf("default keycloak realm = %q; want %q", cfg.Keycloak.Realm, branding.CLI)
	}
	if cfg.Backend.HTTPPort != 8080 {
		t.Errorf("default backend port = %d; want 8080", cfg.Backend.HTTPPort)
	}
	if cfg.Demo.Enabled {
		t.Errorf("default demo.enabled = true; want false (demo is opt-in via `reckon demo seed`)")
	}
}

func TestUnmarshalDataAndPostgres(t *testing.T) {
	yamlData := []byte(`
data:
  dir: /custom/path
postgres:
  port: 6543
`)
	cfg := Default()
	if err := yaml.Unmarshal(yamlData, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Data.Dir != "/custom/path" {
		t.Errorf("data.dir = %q", cfg.Data.Dir)
	}
	if cfg.Postgres.Port != 6543 {
		t.Errorf("postgres.port = %d", cfg.Postgres.Port)
	}
}

func TestUnmarshalPaidActivation(t *testing.T) {
	yamlData := []byte(`
deployment:
  mode: paid
paid:
  tenancy:
    enabled: true
  governance:
    enabled: true
    mode: gated
`)
	cfg := Default()
	if err := yaml.Unmarshal(yamlData, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Deployment.Mode != "paid" {
		t.Errorf("mode = %q", cfg.Deployment.Mode)
	}
	if !cfg.Paid.Tenancy.Enabled {
		t.Errorf("tenancy not enabled")
	}
	if !cfg.Paid.Governance.Enabled {
		t.Errorf("governance not enabled")
	}
	if cfg.Paid.Governance.Mode != "gated" {
		t.Errorf("governance mode = %q", cfg.Paid.Governance.Mode)
	}
}

// TestLoadExplicitPathMissingErrors: a $<CLI>_CONFIG pointing at a
// nonexistent file must error — a typo'd explicit path silently booting
// defaults is the failure mode this guards against.
func TestLoadExplicitPathMissingErrors(t *testing.T) {
	t.Setenv(configEnvVar(), filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if _, err := Load(); err == nil {
		t.Fatal("expected error for explicit missing config path; got nil")
	}
}

// TestLoadExplicitPathParses: an explicit config overlays Default().
func TestLoadExplicitPathParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yamlData := "deployment:\n  mode: paid\nkeycloak:\n  client_id: reckon\n"
	if err := os.WriteFile(path, []byte(yamlData), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(configEnvVar(), path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Deployment.Mode != "paid" {
		t.Errorf("deployment.mode = %q; want paid", cfg.Deployment.Mode)
	}
	if cfg.Keycloak.ClientID != "reckon" {
		t.Errorf("keycloak.client_id = %q; want reckon", cfg.Keycloak.ClientID)
	}
	// Unset keys keep their defaults.
	if cfg.Postgres.Port != 5435 {
		t.Errorf("postgres.port = %d; want default 5435", cfg.Postgres.Port)
	}
}

// TestLoadMalformedYAMLErrors: broken YAML is an error, never a silent
// fallback to defaults.
func TestLoadMalformedYAMLErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("deployment: [broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(configEnvVar(), path)
	_, err := Load()
	if err == nil {
		t.Fatal("expected YAML parse error; got nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q should name the offending file", err)
	}
}

func TestKnowledgeInjectionPosture(t *testing.T) {
	cases := []struct {
		in    string
		valid bool
		eff   string
	}{
		{"", true, KnowledgeInjectionOptIn},   // default
		{"opt_in", true, KnowledgeInjectionOptIn},
		{"auto", true, KnowledgeInjectionAuto},
		{"always", false, "always"},
	}
	for _, c := range cases {
		k := Knowledge{Injection: c.in}
		if k.ValidInjection() != c.valid {
			t.Errorf("ValidInjection(%q) = %v; want %v", c.in, k.ValidInjection(), c.valid)
		}
		if k.InjectionOrDefault() != c.eff {
			t.Errorf("InjectionOrDefault(%q) = %q; want %q", c.in, k.InjectionOrDefault(), c.eff)
		}
	}
}
