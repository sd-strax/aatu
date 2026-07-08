package runtime

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/module"
)

// configEnv is the env var config.Load consults (e.g. RECKON_CONFIG).
func configEnv() string { return strings.ToUpper(branding.CLI) + "_CONFIG" }

// writeTestConfig writes YAML to a temp file and points $<CLI>_CONFIG at it
// for the duration of the test.
func writeTestConfig(t *testing.T, yaml string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(configEnv(), path)
}

// captureLog redirects the standard logger to a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func disabledBuilder(_ Config) module.Registry {
	return module.Registry{
		Tenancy:    module.DisabledTenancy{},
		Governance: module.DisabledGovernance{},
	}
}

// TestPreflightActivatesWithoutBooting is the OSS half of the A.1
// architectural-seam check: Preflight loads config and runs the builder —
// with no Postgres/Temporal/Keycloak anywhere in sight — and reports the
// activation shape.
func TestPreflightActivatesWithoutBooting(t *testing.T) {
	writeTestConfig(t, "deployment:\n  mode: oss\n")
	buf := captureLog(t)

	builderCalls := 0
	build := func(cfg Config) module.Registry {
		builderCalls++
		if cfg.Deployment.Mode != "oss" {
			t.Errorf("builder saw deployment.mode = %q; want oss", cfg.Deployment.Mode)
		}
		return disabledBuilder(cfg)
	}

	if err := Preflight(build); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if builderCalls != 1 {
		t.Errorf("builder called %d times; want 1", builderCalls)
	}
	if out := buf.String(); !strings.Contains(out, "tenancy=false") || !strings.Contains(out, "governance=false") {
		t.Errorf("ready-log missing module shape; got:\n%s", out)
	}
}

// TestPreflightWarnsOnPaidKeysAgainstOSSRegistry: paid.* flags against a
// registry with no paid modules warn and continue — the documented
// warn-and-continue behavior of the OSS binary.
func TestPreflightWarnsOnPaidKeysAgainstOSSRegistry(t *testing.T) {
	writeTestConfig(t, `
deployment:
  mode: oss
paid:
  tenancy:
    enabled: true
  governance:
    enabled: true
`)
	buf := captureLog(t)

	if err := Preflight(disabledBuilder); err != nil {
		t.Fatalf("Preflight should warn-and-continue, not error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "paid.tenancy.enabled set but no paid tenancy module") {
		t.Errorf("missing tenancy warn; got:\n%s", out)
	}
	if !strings.Contains(out, "paid.governance.enabled set but no paid governance module") {
		t.Errorf("missing governance warn; got:\n%s", out)
	}
}

// TestPreflightSurfacesConfigError: a malformed config file fails activation
// rather than silently booting defaults.
func TestPreflightSurfacesConfigError(t *testing.T) {
	writeTestConfig(t, "deployment: [not, a, mapping\n")
	if err := Preflight(disabledBuilder); err == nil {
		t.Fatal("expected config parse error; got nil")
	}
}
