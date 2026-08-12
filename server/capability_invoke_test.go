package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/capability"
)

// buildInvokeCapability constructs a fixture-backed resolver + catalog with two
// bindings: enumerate_logons (no params — matches every call) and
// get_network_connections (templated on ${entity.host.hostname} — exercises the
// applicability path).
func buildInvokeCapability(t *testing.T) (*capability.Resolver, *capability.Catalog) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "s")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"logon.json": `{
	      "fixture_meta":{"scenario":"s","matches":{"verb":"enumerate_logons","params":{}},"delay_ms":0},
	      "ocsf":{"class_uid":3002,"class_name":"Authentication","time":"2026-04-20T14:32:11Z",
	              "actor":{"user":{"name":"jdoe"}},"dst_endpoint":{"hostname":"H1"},"status":"SUCCESS"}
	    }`,
		"conn.json": `{
	      "fixture_meta":{"scenario":"s","matches":{"verb":"get_network_connections","params":{"endpoint.hostname":"H1"}},"delay_ms":0},
	      "ocsf":{"class_uid":3002,"class_name":"Authentication","time":"2026-04-20T14:40:00Z",
	              "actor":{"user":{"name":"jdoe"}},"dst_endpoint":{"hostname":"H1"},"status":"SUCCESS"}
	    }`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tc := capability.TenantConfig{
		Tenant:   "t",
		Adapters: map[string]capability.AdapterSpec{"fixture": {Class: capability.ClassFixture, Enabled: true, Scenario: "s"}},
		Bindings: map[string][]capability.BindingSpec{
			"enumerate_logons": {{Adapter: "fixture", Operation: "replay", Priority: 100}},
			"get_network_connections": {{
				Adapter: "fixture", Operation: "replay", Priority: 100,
				Params: map[string]any{"endpoint": map[string]any{"hostname": "${entity.host.hostname}"}},
			}},
		},
	}
	res, cat, err := capability.BuildResolver(tc, root, uuid.New(), true)
	if err != nil {
		t.Fatalf("BuildResolver: %v", err)
	}
	return res, cat
}

func postCapability(t *testing.T, b *Backend, token, verb string, body CapabilityInvokeBody) (*http.Response, CapabilityInvokeResponse) {
	t.Helper()
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)

	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/capability/"+verb, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out CapabilityInvokeResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	return resp, out
}

// TestCapabilityInvoke_ResolvesFixture: invoking a bound verb replays the
// fixture and returns the full envelope — coverage, refs, telemetry payloads,
// and normalized interpretation-layer objects (which the caller must receive,
// since telemetry persistence is deferred at E.1).
func TestCapabilityInvoke_ResolvesFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t)
	b.cfg.CapabilityResolver, b.cfg.CapabilityCatalog = buildInvokeCapability(t)

	resp, out := postCapability(t, b, mintToken(t, nil), "enumerate_logons", CapabilityInvokeBody{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if out.Coverage != string(capability.CoverageComplete) {
		t.Errorf("coverage = %q; want COMPLETE (notes: %v)", out.Coverage, out.DegradationNotes)
	}
	if len(out.Events) == 0 || len(out.OcsfEventRefs) != len(out.Events) {
		t.Fatalf("events = %d, refs = %d; want matched non-zero", len(out.Events), len(out.OcsfEventRefs))
	}
	if out.Events[0].ClassUID != 3002 || out.Events[0].Payload == nil {
		t.Errorf("event not carried faithfully: %+v", out.Events[0])
	}
	if len(out.Normalized) == 0 || len(out.Normalized[0].SCOs) == 0 {
		t.Error("no normalized SCOs in envelope; the caller has no interpretation-layer objects")
	}
	if len(out.ObservedDataRefs) == 0 || len(out.EntityRefs) == 0 {
		t.Errorf("refs missing: observed=%d entities=%d", len(out.ObservedDataRefs), len(out.EntityRefs))
	}
}

// TestCapabilityInvoke_TemplatedEntity: a binding templated on
// ${entity.host.hostname} resolves when the entity is supplied, and reports
// UNAVAILABLE_TENANT (not an error) when the required input is absent — the
// envelope's coverage IS the result (03 §6.1).
func TestCapabilityInvoke_TemplatedEntity(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t)
	b.cfg.CapabilityResolver, b.cfg.CapabilityCatalog = buildInvokeCapability(t)
	token := mintToken(t, nil)

	resp, out := postCapability(t, b, token, "get_network_connections", CapabilityInvokeBody{
		Entity: map[string]any{"host": map[string]any{"hostname": "H1"}},
	})
	if resp.StatusCode != http.StatusOK || out.Coverage != string(capability.CoverageComplete) {
		t.Fatalf("with entity: status = %d coverage = %q; want 200 COMPLETE (notes: %v)",
			resp.StatusCode, out.Coverage, out.DegradationNotes)
	}

	resp, out = postCapability(t, b, token, "get_network_connections", CapabilityInvokeBody{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("without entity: status = %d; want 200", resp.StatusCode)
	}
	if out.Coverage != string(capability.CoverageUnavailableTenant) {
		t.Errorf("without entity: coverage = %q; want UNAVAILABLE_TENANT", out.Coverage)
	}
}

// TestCapabilityInvoke_UnknownVerb: a verb absent from the catalog is a 404.
func TestCapabilityInvoke_UnknownVerb(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t)
	b.cfg.CapabilityResolver, b.cfg.CapabilityCatalog = buildInvokeCapability(t)

	resp, _ := postCapability(t, b, mintToken(t, nil), "definitely_not_a_verb", CapabilityInvokeBody{})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d; want 404", resp.StatusCode)
	}
}

// TestCapabilityInvoke_Unconfigured: without a capability layer the route is a
// clean 503, matching GET /api/capabilities.
func TestCapabilityInvoke_Unconfigured(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t) // no resolver
	resp, _ := postCapability(t, b, mintToken(t, nil), "enumerate_logons", CapabilityInvokeBody{})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503", resp.StatusCode)
	}
}

// TestCapabilityInvoke_AnalystOnly: invocation causes outbound tool I/O —
// viewer tokens are rejected even though they may read the catalog.
func TestCapabilityInvoke_AnalystOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t)
	b.cfg.CapabilityResolver, b.cfg.CapabilityCatalog = buildInvokeCapability(t)

	viewer := mintToken(t, map[string]any{"realm_access": map[string]any{"roles": []string{"viewer"}}})
	resp, _ := postCapability(t, b, viewer, "enumerate_logons", CapabilityInvokeBody{})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d; want 403", resp.StatusCode)
	}
}

// TestCapabilityInvoke_MethodNotAllowed: only POST invokes.
func TestCapabilityInvoke_MethodNotAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t)
	b.cfg.CapabilityResolver, b.cfg.CapabilityCatalog = buildInvokeCapability(t)

	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/capability/enumerate_logons", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", resp.StatusCode)
	}
}

// TestCapabilityInvoke_BadBody: malformed JSON is a 400.
func TestCapabilityInvoke_BadBody(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b := newTestBackend(t)
	b.cfg.CapabilityResolver, b.cfg.CapabilityCatalog = buildInvokeCapability(t)

	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/capability/enumerate_logons", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", resp.StatusCode)
	}
}
