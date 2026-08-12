package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/capability"
)

// buildTestCapability constructs a fixture-backed resolver + catalog with a
// single enumerate_logons binding, for exercising the /api/capabilities route.
func buildTestCapability(t *testing.T) (*capability.Resolver, *capability.Catalog) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "s")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fixture := `{
      "fixture_meta":{"scenario":"s","matches":{"verb":"enumerate_logons","params":{}},"delay_ms":0},
      "ocsf":{"class_uid":3002,"class_name":"Authentication","time":"2026-04-20T14:32:11Z","dst_endpoint":{"hostname":"H1"}}
    }`
	if err := os.WriteFile(filepath.Join(dir, "e1.json"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	tc := capability.TenantConfig{
		Tenant:   "t",
		Adapters: map[string]capability.AdapterSpec{"fixture": {Class: capability.ClassFixture, Enabled: true, Scenario: "s"}},
		Bindings: map[string][]capability.BindingSpec{
			"enumerate_logons": {{Adapter: "fixture", Operation: "replay", Priority: 100}},
		},
	}
	res, cat, err := capability.BuildResolver(tc, root, uuid.New(), true)
	if err != nil {
		t.Fatalf("BuildResolver: %v", err)
	}
	return res, cat
}

// TestCapabilitiesRoute: an authenticated GET returns the verb summaries, with
// the bound verb marked available.
func TestCapabilitiesRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t)
	b.cfg.CapabilityResolver, b.cfg.CapabilityCatalog = buildTestCapability(t)

	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/capabilities", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200; body = %s", resp.StatusCode, readBody(resp))
	}

	var body struct {
		Capabilities []capability.CapabilitySummary `json:"capabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var found bool
	for _, s := range body.Capabilities {
		if s.Descriptor.Verb == "enumerate_logons" {
			found = true
			if s.Status != capability.StatusAvailable {
				t.Errorf("enumerate_logons status = %q; want available", s.Status)
			}
		}
	}
	if !found {
		t.Error("enumerate_logons not present in capabilities response")
	}
}

// TestCapabilitiesRouteUnconfigured: without a capability layer the route is a
// clean 503, not a crash.
func TestCapabilitiesRouteUnconfigured(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t) // no CapabilityResolver
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/capabilities", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503", resp.StatusCode)
	}
}
