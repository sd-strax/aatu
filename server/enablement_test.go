package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func enablementBackend(t *testing.T) (*Backend, string) {
	t.Helper()
	src, err := os.ReadFile("../examples/capability/lateral-movement.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tenant.yaml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	b := newTestBackend(t)
	b.cfg.CapabilityConfigPath = path
	b.cfg.CapabilityFixtureRoot = "../fixtures"
	return b, path
}

// TestEnablement_GapAndApply: the shipped config's installed-not-enabled gap
// (fixture_context / get_host_context) is visible on GET, a human-confirmed
// POST closes it (file rewritten, capability surface hot-swapped, audit line
// appended), and the closed gap disappears from the view.
func TestEnablement_GapAndApply(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b, path := enablementBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	token := mintToken(t, nil)

	get := func() EnablementResponse {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/enablement", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/enablement = %d", resp.StatusCode)
		}
		var out EnablementResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	view := get()
	var gap *EnablementVerbView
	for i := range view.Verbs {
		if view.Verbs[i].Verb == "get_host_context" {
			gap = &view.Verbs[i]
		}
	}
	if gap == nil || gap.Enabled || len(gap.ClosableBy) == 0 || gap.ClosableBy[0] != "fixture_context" {
		t.Fatalf("shipped gap not visible: %+v", gap)
	}

	// The human confirm.
	body, _ := json.Marshal(ApplyEnablementBody{Enabled: true, Config: map[string]string{"scenario": "lateral-movement-via-rdp"}})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/enablement/adapters/fixture_context", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("apply = %d", resp.StatusCode)
	}

	// The gap is closed on the next view, and the hot-swapped surface serves
	// the verb as available.
	view = get()
	for _, v := range view.Verbs {
		if v.Verb == "get_host_context" && (!v.Enabled || v.ClosableBy != nil) {
			t.Errorf("gap not closed in view: %+v", v)
		}
	}
	resolver, catalog := b.capabilitySurface()
	if resolver == nil {
		t.Fatal("capability surface not hot-swapped")
	}
	available := false
	for _, v := range resolver.AvailableVerbs(catalog) {
		if v == "get_host_context" {
			available = true
		}
	}
	if !available {
		t.Error("get_host_context not available on the hot-swapped surface")
	}

	// The attributed audit line landed beside the file.
	audit, err := os.ReadFile(path + ".audit.jsonl")
	if err != nil {
		t.Fatalf("audit trail missing: %v", err)
	}
	var line struct {
		Principal string `json:"principal"`
		Adapter   string `json:"adapter"`
		Enabled   bool   `json:"enabled"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(audit), &line); err != nil {
		t.Fatalf("audit line unparsable: %v", err)
	}
	if line.Principal == "" || line.Adapter != "fixture_context" || !line.Enabled {
		t.Errorf("audit line = %+v; want attributed enable of fixture_context", line)
	}
}

// TestEnablement_AIDelegateCannotApply: the structural guarantee of 11 §5.1 —
// an AI-delegated token has no path to changing config, even with the analyst
// role. 403, and the file is untouched.
func TestEnablement_AIDelegateCannotApply(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b, path := enablementBackend(t)
	before, _ := os.ReadFile(path)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(ApplyEnablementBody{Enabled: true})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/enablement/adapters/fixture_context", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, map[string]any{"delegate_kind": "anthropic"}))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("delegate apply = %d; want 403", resp.StatusCode)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("the tenant config changed on a refused request")
	}
}

// TestEnablement_UnsupportedClassRefused: enabling a class v0 cannot spawn is
// a 422 with the honest diagnostic, not a config write that breaks boot.
func TestEnablement_UnsupportedClassRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	b, _ := enablementBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(ApplyEnablementBody{Enabled: true})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/enablement/adapters/crowdstrike_falcon", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported class apply = %d; want 422", resp.StatusCode)
	}
}
