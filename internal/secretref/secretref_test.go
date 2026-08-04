package secretref

import (
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/sd-strax/reckon/internal/branding"
)

func TestIsRef(t *testing.T) {
	for _, s := range []string{"keychain://reckon/x", "env://X", "vault://a/b"} {
		if !IsRef(s) {
			t.Errorf("IsRef(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"literal-secret", "https://x", ""} {
		if IsRef(s) {
			t.Errorf("IsRef(%q) = true, want false", s)
		}
	}
}

func TestResolveEnv(t *testing.T) {
	t.Setenv("RECKON_TEST_SECRET", "s3cr3t")
	got, err := Resolve("env://RECKON_TEST_SECRET")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "s3cr3t" {
		t.Fatalf("got %q", got)
	}
	if _, err := Resolve("env://RECKON_UNSET_VAR_XYZ"); err == nil {
		t.Error("resolving an unset env var should error")
	}
}

func TestResolveKeychain(t *testing.T) {
	keyring.MockInit()
	if err := keyring.Set(branding.CLI, "okta-client-secret", "kc-value"); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve("keychain://" + branding.CLI + "/okta-client-secret")
	if err != nil {
		t.Fatalf("Resolve keychain: %v", err)
	}
	if got != "kc-value" {
		t.Fatalf("got %q", got)
	}
	// Default service form (no explicit service).
	if got, err := Resolve("keychain://okta-client-secret"); err != nil || got != "kc-value" {
		t.Fatalf("default-service keychain: got %q err %v", got, err)
	}
}

func TestResolveVaultDeferred(t *testing.T) {
	if _, err := Resolve("vault://team/okta"); err == nil {
		t.Error("vault:// should error (deferred in v0), not silently resolve")
	}
}

func TestResolveConfigRefusesLiteralInSecretField(t *testing.T) {
	schema := map[string]any{
		"properties": map[string]any{
			"client_secret": map[string]any{"type": "string", "x-secret": true},
			"org_url":       map[string]any{"type": "string"},
		},
	}
	cfg := map[string]any{"client_secret": "raw-literal", "org_url": "https://acme.okta.com"}
	if _, err := ResolveConfig(schema, cfg); err == nil {
		t.Fatal("a literal in an x-secret field must be refused (11 §4.3)")
	}
}

func TestResolveConfigResolvesSecretPassesOthers(t *testing.T) {
	t.Setenv("OKTA_SECRET", "resolved-secret")
	schema := map[string]any{
		"properties": map[string]any{
			"client_secret": map[string]any{"type": "string", "x-secret": true},
			"org_url":       map[string]any{"type": "string"},
		},
	}
	cfg := map[string]any{
		"client_secret": "env://OKTA_SECRET",
		"org_url":       "https://acme.okta.com",
	}
	out, err := ResolveConfig(schema, cfg)
	if err != nil {
		t.Fatalf("ResolveConfig: %v", err)
	}
	if out["client_secret"] != "resolved-secret" {
		t.Errorf("secret not resolved: %v", out["client_secret"])
	}
	if out["org_url"] != "https://acme.okta.com" {
		t.Errorf("non-secret field altered: %v", out["org_url"])
	}
}

func TestResolveConfigNilSchemaPassesThrough(t *testing.T) {
	cfg := map[string]any{"anything": "value"}
	out, err := ResolveConfig(nil, cfg)
	if err != nil || out["anything"] != "value" {
		t.Fatalf("nil schema should pass through: out=%v err=%v", out, err)
	}
}
