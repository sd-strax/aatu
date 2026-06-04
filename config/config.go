package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the top-level deployment configuration.
type Config struct {
	Deployment Deployment `yaml:"deployment"`
	Data       Data       `yaml:"data"`
	Postgres   Postgres   `yaml:"postgres"`
	Temporal   Temporal   `yaml:"temporal"`
	Paid       Paid       `yaml:"paid"`
}

// Deployment names the distribution shape.
type Deployment struct {
	// Mode is "oss" or "paid". OSS binaries ignore the paid section
	// (with a warning when paid.*.enabled is true).
	Mode string `yaml:"mode"`
}

// Data names the root directory aatu uses for state (Pg data, logs, etc.).
type Data struct {
	// Dir defaults to ~/.aatu.
	Dir string `yaml:"dir"`
}

// Postgres configures the bundled embedded Postgres.
type Postgres struct {
	// Port defaults to 5435 (non-standard to avoid colliding with a system
	// Postgres on 5432 during dev).
	Port uint32 `yaml:"port"`
}

// Temporal configures the bundled Temporal dev server.
type Temporal struct {
	// FrontendPort is the gRPC port the dev-server frontend listens on.
	// Default 7233 (Temporal's standard).
	FrontendPort int `yaml:"frontend_port"`
	// UIEnabled controls whether the Temporal web UI is started.
	// Default true.
	UIEnabled bool `yaml:"ui_enabled"`
	// UIPort is the HTTP port for the web UI when UIEnabled.
	// Default 8233.
	UIPort int `yaml:"ui_port"`
	// Namespace is the default Temporal namespace pre-registered at startup.
	// Default "default".
	Namespace string `yaml:"namespace"`
}

// Paid groups the activation flags for paid modules. Ignored when the
// binary is OSS; consulted by the paid binary's registry builder.
type Paid struct {
	Tenancy    PaidTenancy    `yaml:"tenancy"`
	Governance PaidGovernance `yaml:"governance"`
}

// PaidTenancy configures the tenancy module.
type PaidTenancy struct {
	Enabled bool `yaml:"enabled"`
}

// PaidGovernance configures the governance module.
type PaidGovernance struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"` // "lightweight" or "gated"
}

// Default returns the zero-value config with deployment.mode = "oss",
// data.dir = ~/.aatu, postgres.port = 5435, and all paid modules disabled
// (governance.mode = "lightweight").
func Default() Config {
	dataDir := "~/.aatu"
	if home, err := os.UserHomeDir(); err == nil {
		dataDir = filepath.Join(home, ".aatu")
	}
	return Config{
		Deployment: Deployment{Mode: "oss"},
		Data:       Data{Dir: dataDir},
		Postgres:   Postgres{Port: 5435},
		Temporal: Temporal{
			FrontendPort: 7233,
			UIEnabled:    true,
			UIPort:       8233,
			Namespace:    "default",
		},
		Paid: Paid{
			Governance: PaidGovernance{Mode: "lightweight"},
		},
	}
}

// Load reads configuration from $AATU_CONFIG, ~/.aatu/config.yaml, or
// returns Default() if neither exists. Errors only on malformed YAML.
func Load() (Config, error) {
	path := os.Getenv("AATU_CONFIG")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Default(), nil
		}
		path = filepath.Join(home, ".aatu", "config.yaml")
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}
