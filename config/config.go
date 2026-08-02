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
	Telemetry  Telemetry  `yaml:"telemetry"`
	Capability Capability `yaml:"capability"`
	Export     Export     `yaml:"export"`
	Trust      Trust      `yaml:"trust"`
	Paid       Paid       `yaml:"paid"`
}

// Trust holds the tenant trust-posture dials (01-domain-model.md: trust
// posture is configuration, not a fixed property of the model).
type Trust struct {
	// AIVerdict opens the AI-verdict dial (01 §Verdict): when true, an
	// AI-delegated actor may record the investigation's disposition of record.
	// Default false — AI verdicts are denied by default; the door opens by
	// configuration, never by code change, and the enabling ref is recorded on
	// the verdict event.
	AIVerdict bool `yaml:"ai_verdict"`

	// AIReasoning opens the autonomous-reasoning dial (01 §Interpretation types):
	// when true, an AI-delegated actor may drive a hypothesis to an evidential
	// outcome (run tests / decide) without a human acknowledgment. Default false —
	// an AI-proposed hypothesis is PROPOSED and a human must Acknowledge it into
	// OPEN before any outcome is recorded; the door to full automation opens by
	// configuration, never by code change, and the enabling ref rides the event.
	AIReasoning bool `yaml:"ai_reasoning"`
}

// Export configures the post-conclusion export bundle (design 07). Tenant
// policy, not the requester, decides what a bundle may contain.
type Export struct {
	// IncludeSideStores controls whether the export bundle carries the Layer B
	// side stores — AI transcripts and tool-call payloads (07 §2.2). Default
	// true (complete bundles for solo); compliance deployments set it false so
	// prompt content never leaves the production system. This is a tenant
	// policy: the export requester cannot override it.
	IncludeSideStores bool `yaml:"include_side_stores"`

	// AutoOnConclude fires the post-conclusion pipeline automatically when an
	// investigation concludes (07 §2.3, "triggered automatically on
	// InvestigationConcluded; default on"). Set false to require an explicit
	// POST .../export instead.
	AutoOnConclude bool `yaml:"auto_on_conclude"`
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

	// SSLMode is the libpq sslmode for connections. Default "disable" — the
	// bundled instance is loopback-only. A networked/managed Postgres should set
	// "require" (or stricter). The role password is a provisioned install secret
	// (internal/secrets), never a config field.
	SSLMode string `yaml:"ssl_mode"`
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

// Telemetry configures structured logging, tracing, and metrics (Phase A.8).
type Telemetry struct {
	// LogLevel is the minimum slog level: "debug", "info", "warn", "error".
	// Default "info".
	LogLevel string `yaml:"log_level"`
	// LogFormat is "text" (human-readable) or "json" (machine-ingestible).
	// Default "text".
	LogFormat string `yaml:"log_format"`
	// LogToFile also writes rolling logs under <Data.Dir>/logs in addition to
	// stderr. Default true.
	LogToFile bool `yaml:"log_to_file"`
	// MetricsEnabled exposes the Prometheus /metrics endpoint on the backend.
	// Default true.
	MetricsEnabled bool `yaml:"metrics_enabled"`
}

// Capability configures the read-side capability layer (Phase B). Optional: an
// empty ConfigPath leaves the layer unwired and the backend serves no capability
// routes.
type Capability struct {
	// ConfigPath points at the tenant capability YAML (adapters + bindings +
	// policies, design/03 §3.2). Empty disables the capability layer.
	ConfigPath string `yaml:"config_path"`
	// FixtureRoot is the directory fixture scenarios live under. Default
	// "fixtures".
	FixtureRoot string `yaml:"fixture_root"`
	// TenantNamespace is the identity-namespace UUID for the (single, v0) tenant
	// (design/03 §7.1). Defaults to a fixed OSS namespace; multi-tenant
	// deployments assign a fresh UUID per tenant via the tenancy module.
	TenantNamespace string `yaml:"tenant_namespace"`
	// PolicyDir holds the Gate 2 auto-approval policies (*.policy.yaml,
	// design/04 §4). Empty means baseline-only (the non-deletable AI-no-T3 DENY
	// still applies; every other action falls through to manual approval).
	PolicyDir string `yaml:"policy_dir"`
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
		Postgres:   Postgres{Port: 5435, SSLMode: "disable"},
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
		Telemetry: Telemetry{
			LogLevel:       "info",
			LogFormat:      "text",
			LogToFile:      true,
			MetricsEnabled: true,
		},
		Capability: Capability{
			FixtureRoot: "fixtures",
			// Fixed namespace for the OSS default tenant; multi-tenant
			// deployments override per tenant.
			TenantNamespace: "6f1b2c3d-0000-4000-8000-000000000001",
		},
		Export: Export{
			// Solo default: complete bundles, auto-exported at conclusion.
			IncludeSideStores: true,
			AutoOnConclude:    true,
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

// DefaultPath returns the config path Load resolves to: $<CLI>_CONFIG when set,
// else ~/<branding.DataDir>/config.yaml. Used by `reckon init` to write the
// first-run config exactly where Load will later read it.
func DefaultPath() (string, error) {
	if p := os.Getenv(configEnvVar()); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, branding.DataDir, "config.yaml"), nil
}

// Save writes cfg as YAML to path, creating the parent directory. It refuses to
// overwrite an existing file — first-run bootstrap must never silently clobber a
// config a user may have hand-edited; the caller decides what to do when the
// file already exists.
func Save(cfg Config, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config already exists at %s", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
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
