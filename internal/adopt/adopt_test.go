package adopt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

func oktaDescribe() *adapterplugin.DescribeResult {
	return &adapterplugin.DescribeResult{
		DefaultReadBindings: []adapterplugin.ReadBinding{
			{Verb: "get_entity_context", Adapter: "okta", Operation: "get_user", Priority: 100, Params: map[string]any{"login": "${entity.user}"}},
			{Verb: "enumerate_logons", Adapter: "okta", Operation: "get_logs", Priority: 100, Params: map[string]any{"q": "${entity.user??}"}},
		},
		DefaultWriteBindings: []action.ActionBinding{
			{ActionType: "account.disable", Adapter: "okta", Operation: "deactivate_user", Priority: 100},
		},
	}
}

func TestAdoptRoundTripThroughLoaders(t *testing.T) {
	d := oktaDescribe()
	plan := PlanFrom(d, "okta", "okta", "mcp",
		map[string]string{"org_url": "https://acme.okta.com", "client_id": "0oaX"},
		[]string{"get_user", "get_logs"}, []string{"account.disable"})

	path := filepath.Join(t.TempDir(), "tenant.yaml")
	if err := Apply(path, plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	tc, err := capability.LoadTenantConfig(path)
	if err != nil {
		t.Fatalf("LoadTenantConfig: %v", err)
	}
	spec := tc.Adapters["okta"]
	if spec.Class != capability.ClassMCP || !spec.Enabled {
		t.Fatalf("adapter spec = %+v", spec)
	}
	if spec.Config["org_url"] != "https://acme.okta.com" {
		t.Errorf("config.org_url = %v", spec.Config["org_url"])
	}
	if len(spec.Reads) != 2 {
		t.Errorf("reads = %v", spec.Reads)
	}
	if len(tc.Bindings["get_entity_context"]) != 1 || tc.Bindings["get_entity_context"][0].Operation != "get_user" {
		t.Errorf("get_entity_context binding = %+v", tc.Bindings["get_entity_context"])
	}

	ac, err := action.LoadActionConfig(path)
	if err != nil {
		t.Fatalf("LoadActionConfig: %v", err)
	}
	if aspec := ac.Adapters["okta"]; !aspec.Enabled || len(aspec.Actions) != 1 || aspec.Actions[0] != "deactivate_user" {
		t.Errorf("action adapter spec = %+v", aspec)
	}
	if len(ac.Bindings["account.disable"]) != 1 || ac.Bindings["account.disable"][0].Operation != "deactivate_user" {
		t.Errorf("account.disable binding = %+v", ac.Bindings["account.disable"])
	}
}

func TestAdoptPreservesExistingContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tenant.yaml")
	existing := "# my tenant config\ntenant: demo\nadapters:\n  fixture:\n    class: fixture\n    enabled: true\n    scenario: lateral-movement-via-rdp\n"
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	plan := PlanFrom(oktaDescribe(), "okta", "okta", "mcp", map[string]string{"org_url": "https://acme.okta.com"}, []string{"get_user"}, nil)
	if err := Apply(path, plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	out, _ := os.ReadFile(path)
	s := string(out)
	if !strings.Contains(s, "# my tenant config") {
		t.Error("top comment not preserved")
	}
	if !strings.Contains(s, "fixture") || !strings.Contains(s, "lateral-movement-via-rdp") {
		t.Error("existing fixture adapter not preserved")
	}
	// And the new okta adapter is present + both parse.
	tc, err := capability.LoadTenantConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := tc.Adapters["okta"]; !ok {
		t.Error("okta adapter not added")
	}
	if _, ok := tc.Adapters["fixture"]; !ok {
		t.Error("fixture adapter lost")
	}
}

// TestAdoptMergesSharedVerbBinding: adopting a verb that another adapter already
// binds must KEEP the other adapter's binding, not clobber it. Re-adopting is
// idempotent (this instance's binding replaced, not duplicated).
func TestAdoptMergesSharedVerbBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tenant.yaml")
	existing := "tenant: demo\nbindings:\n  enumerate_logons:\n    - adapter: fixture\n      operation: replay\n      priority: 100\n"
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := PlanFrom(oktaDescribe(), "okta", "okta", "mcp", nil, []string{"get_logs"}, nil)

	// Apply twice — must be idempotent.
	for i := 0; i < 2; i++ {
		if err := Apply(path, plan); err != nil {
			t.Fatalf("Apply #%d: %v", i, err)
		}
	}
	tc, err := capability.LoadTenantConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	binds := tc.Bindings["enumerate_logons"]
	if len(binds) != 2 {
		t.Fatalf("enumerate_logons should have fixture + okta (once), got %d: %+v", len(binds), binds)
	}
	adapters := map[string]bool{binds[0].Adapter: true, binds[1].Adapter: true}
	if !adapters["fixture"] || !adapters["okta"] {
		t.Errorf("want both fixture and okta bindings, got %v", adapters)
	}
}

// TestAdoptWriteAsymmetry: with no action-types selected, no write stanza is
// written (writes are per-op explicit, §5).
func TestAdoptNoWritesWhenNoneSelected(t *testing.T) {
	plan := PlanFrom(oktaDescribe(), "okta", "okta", "mcp", nil, []string{"get_user"}, nil)
	if plan.WriteAdapter != nil {
		t.Error("no action-types selected but a write adapter stanza was planned")
	}
	if len(plan.Summary.ActionTypes) != 0 {
		t.Errorf("summary action types = %v", plan.Summary.ActionTypes)
	}
}
