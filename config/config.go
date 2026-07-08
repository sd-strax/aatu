package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sd-strax/reckon/internal/branding"
)

// Config is the top-level deployment configuration.
type Config struct {
	Deployment Deployment `yaml:"deployment"`
	Data       Data       `yaml:"data"`
	Postgres   Postgres   `yaml:"postgres"`
	Temporal   Temporal   `yaml:"temporal"`
	Keycloak   Keycloak   `yaml:"keycloak"`
	Backend    Backend    `yaml:"backend"`
	Paid       Paid       `yaml:"paid"`
}

// Deployment names the distribution shape.
type Deployment struct {
	// Mode is "oss" or "paid". OSS binaries ignore the paid section
	// (with a warning when paid.*.enabled is true).
	Mode string `yaml:"mode"`
}

// Data names the root directory the supervisor uses for state (Pg data,
// logs, etc.).
type Data struct {
	// Dir defaults to ~/<branding.DataDir> (e.g. ~/.reckon).
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

// Keycloak configures the bundled Keycloak IdP.
type Keycloak struct {
	// HTTPPort is the Keycloak HTTP listener.
	// Default 8543 (non-standard to avoid colliding with the common 8080).
	HTTPPort int `yaml:"http_port"`
	// ManagementPort is the Keycloak health/metrics endpoint.
	// Default 9543.
	ManagementPort int `yaml:"management_port"`
	// Realm is the bootstrap realm imported on first start.
	// Default branding.CLI (e.g. "reckon").
	Realm string `yaml:"realm"`
	// ClientID, when set, locks the backend's JWT audience check to this
	// client: tokens whose aud claim does not include it are rejected.
	// Default empty = audience check off (dev/OSS-solo). The bundled realm's
	// "reckon" client carries an audience mapper so `client_id: reckon` works
	// out of the box on fresh installs; realms imported before the mapper
	// existed need the mapper added in the Keycloak admin console first.
	ClientID string `yaml:"client_id"`
}

// Backend configures the in-process backend.
type Backend struct {
	// HTTPPort is where the backend exposes /healthz and /status.
	// Default 8080.
	HTTPPort int `yaml:"http_port"`
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
// data.dir = ~/<branding.DataDir>, postgres.port = 5435, and all paid
// modules disabled (governance.mode = "lightweight").
func Default() Config {
	dataDir := "~/" + branding.DataDir
	if home, err := os.UserHomeDir(); err == nil {
		dataDir = filepath.Join(home, branding.DataDir)
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
		Keycloak: Keycloak{
			HTTPPort:       8543,
			ManagementPort: 9543,
			Realm:          branding.CLI,
		},
		Backend: Backend{
			HTTPPort: 8080,
		},
		Paid: Paid{
			Governance: PaidGovernance{Mode: "lightweight"},
		},
	}
}

// configEnvVar returns the environment variable name users set to point
// at a config file ("<UPPERCASE-CLI>_CONFIG", e.g. RECKON_CONFIG).
func configEnvVar() string {
	return strings.ToUpper(branding.CLI) + "_CONFIG"
}

// Load reads configuration from $<CLI>_CONFIG, ~/<branding.DataDir>/config.yaml,
// or returns Default() if neither exists.
//
// A missing file at the *default* path means "not configured" and yields
// Default(). A missing file at an *explicitly set* $<CLI>_CONFIG path is an
// error — a typo'd path silently booting defaults is exactly the failure a
// user can't see.
func Load() (Config, error) {
	explicit := false
	path := os.Getenv(configEnvVar())
	if path != "" {
		explicit = true
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return Default(), nil
		}
		path = filepath.Join(home, branding.DataDir, "config.yaml")
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if explicit {
			return Config{}, fmt.Errorf("%s points at %s, which does not exist", configEnvVar(), path)
		}
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
