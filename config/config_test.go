package config

import (
	"testing"

	"gopkg.in/yaml.v3"
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
