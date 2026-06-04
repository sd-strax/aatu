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
	Paid       Paid       `yaml:"paid"`
}

// Deployment names the distribution shape.
type Deployment struct {
	// Mode is "oss" or "paid". OSS binaries ignore the paid section
	// (with a warning when paid.*.enabled is true).
	Mode string `yaml:"mode"`
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

// Default returns the zero-value config with deployment.mode = "oss"
// and all paid modules disabled. governance.mode defaults to "lightweight".
func Default() Config {
	return Config{
		Deployment: Deployment{Mode: "oss"},
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
