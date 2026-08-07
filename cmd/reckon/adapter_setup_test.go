package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sd-strax/reckon/config"
)

func testSchema() map[string]any {
	return map[string]any{
		"required": []any{"api_key"},
		"properties": map[string]any{
			"api_key": map[string]any{"type": "string", "x-secret": true},
			"region":  map[string]any{"type": "string"},
		},
	}
}

// TestResolveAdapterConfigFlagsWin: an explicit --set satisfies a required
// field with no prompting; optional fields pass through.
func TestResolveAdapterConfigFlagsWin(t *testing.T) {
	got, missing := resolveAdapterConfig("gn", testSchema(), config.Config{}, "",
		map[string]string{"api_key": "env://GN_KEY", "region": "eu"}, false)
	if len(missing) != 0 {
		t.Fatalf("missing = %v, want none", missing)
	}
	if got["api_key"] != "env://GN_KEY" || got["region"] != "eu" {
		t.Errorf("got = %v", got)
	}
}

// TestResolveAdapterConfigTenantFill: an existing tenant-config stanza fills
// gaps; flags still win over it.
func TestResolveAdapterConfigTenantFill(t *testing.T) {
	dir := t.TempDir()
	tcPath := filepath.Join(dir, "tenant.yaml")
	if err := os.WriteFile(tcPath, []byte(`
tenant: t
adapters:
  gn:
    class: mcp
    enabled: true
    config:
      api_key: keychain://reckon/gn-api_key
      region: us
`), 0o644); err != nil {
		t.Fatal(err)
	}

	got, missing := resolveAdapterConfig("gn", testSchema(), config.Config{}, tcPath,
		map[string]string{"region": "eu"}, false)
	if len(missing) != 0 {
		t.Fatalf("missing = %v, want none (tenant config supplies api_key)", missing)
	}
	if got["api_key"] != "keychain://reckon/gn-api_key" {
		t.Errorf("api_key = %q, want the tenant-config reference", got["api_key"])
	}
	if got["region"] != "eu" {
		t.Errorf("region = %q, want the flag to win over the tenant config", got["region"])
	}
}

// TestResolveAdapterConfigMissingNonInteractive: with no source and no
// terminal, required fields report missing (the caller skips enablement with
// guidance — never an error, never a fabricated value).
func TestResolveAdapterConfigMissingNonInteractive(t *testing.T) {
	_, missing := resolveAdapterConfig("gn", testSchema(), config.Config{}, "", nil, false)
	if len(missing) != 1 || missing[0] != "api_key" {
		t.Fatalf("missing = %v, want [api_key]", missing)
	}
}

func TestEnvVarNameFor(t *testing.T) {
	if got := envVarNameFor("greynoise", "api_key"); got != "GREYNOISE_API_KEY" {
		t.Errorf("got %q", got)
	}
	if got := envVarNameFor("my-adapter", "some.field"); got != "MY_ADAPTER_SOME_FIELD" {
		t.Errorf("got %q", got)
	}
}

func TestKVFlags(t *testing.T) {
	kv := kvFlags{}
	if err := kv.Set("a=b"); err != nil {
		t.Fatal(err)
	}
	if err := kv.Set("c=d=e"); err != nil { // values may contain '='
		t.Fatal(err)
	}
	if kv["a"] != "b" || kv["c"] != "d=e" {
		t.Errorf("kv = %v", kv)
	}
	if err := kv.Set("noequals"); err == nil {
		t.Error("want error for missing '='")
	}
}
