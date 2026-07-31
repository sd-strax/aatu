package capability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestUpdateAdapterEnablement_RoundTrip: the YAML surgery flips exactly the
// targeted stanza, preserves the rest of the document (comments included —
// operators diff this file), and the result still builds a resolver.
func TestUpdateAdapterEnablement_RoundTrip(t *testing.T) {
	src, err := os.ReadFile("../examples/capability/lateral-movement.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tenant.yaml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := UpdateAdapterEnablement(path, "fixture_context", true, map[string]string{"scenario": "lateral-movement-via-rdp"}); err != nil {
		t.Fatalf("UpdateAdapterEnablement: %v", err)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Comments survive the round-trip: the file is the reviewed artifact.
	if !strings.Contains(string(out), "installed-not-enabled gap") {
		t.Error("comments were lost in the rewrite — the file must stay diff-reviewable")
	}

	cfg, err := LoadTenantConfig(path)
	if err != nil {
		t.Fatalf("rewritten config does not load: %v", err)
	}
	spec := cfg.Adapters["fixture_context"]
	if !spec.Enabled || spec.Scenario != "lateral-movement-via-rdp" {
		t.Errorf("stanza not updated: %+v", spec)
	}
	if !cfg.Adapters["fixture"].Enabled {
		t.Error("unrelated adapter stanza was disturbed")
	}

	res, catalog, err := BuildResolver(cfg, "../fixtures", uuid.New())
	if err != nil {
		t.Fatalf("rewritten config does not build: %v", err)
	}
	for _, v := range res.AvailableVerbs(catalog) {
		if v == "get_host_context" {
			return // the gap is closed
		}
	}
	t.Error("get_host_context still unavailable after enabling its adapter")
}

// TestUpdateAdapterEnablement_NeverInstalls: an adapter absent from the file
// is refused (11 §6.1 — enablement toggles installed capability only).
func TestUpdateAdapterEnablement_NeverInstalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tenant.yaml")
	if err := os.WriteFile(path, []byte("tenant: demo\nadapters:\n  fixture: {class: fixture, enabled: true, scenario: s}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpdateAdapterEnablement(path, "okta", true, nil); err == nil {
		t.Fatal("expected an error for a not-installed adapter")
	}
}

// TestAdapterConfigSchema_FixtureOnly: v0 serves a schema for the fixture
// class only; unknown classes get nil (no form, no guessing).
func TestAdapterConfigSchema_FixtureOnly(t *testing.T) {
	s := AdapterConfigSchema(ClassFixture)
	if s == nil {
		t.Fatal("fixture class must have a config schema")
	}
	props, _ := s["properties"].(map[string]any)
	if _, ok := props["scenario"]; !ok {
		t.Error("fixture schema missing the scenario field")
	}
	if AdapterConfigSchema(ClassNativeAPI) != nil {
		t.Error("non-fixture classes must serve no schema in v0")
	}
}
