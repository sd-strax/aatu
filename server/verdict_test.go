package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestVerdictFlow_EndToEnd drives the whole pin → verdict path through the
// HTTP seam: verdict refused before any pin; pin recorded; AI-delegated
// verdict 403s with the dial off (the default); human verdict records and
// surfaces on the investigation view; a revision replaces it; superseding the
// pin flips it in GET /pins.
func TestVerdictFlow_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)

	humanToken := mintToken(t, nil)
	aiToken := mintToken(t, map[string]any{"delegate_kind": "claude"})

	post := func(token, path string, body any) (*http.Response, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		return resp, out
	}
	get := func(token, path string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, resp.StatusCode)
		}
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	// 1. Verdict before any pin → the aggregate's pinned-evidence gate bites.
	resp, out := post(humanToken, "/api/interpretations", map[string]any{
		"investigation_ref":   invID.String(),
		"interpretation_type": "verdict",
		"verdict":             map[string]any{"disposition": "MALICIOUS"},
		"input_refs":          []string{"observed-data--od1"},
		"rationale":           "premature",
	})
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("verdict accepted with zero pins")
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "pinned evidence") {
		t.Errorf("error = %q; want the pinned-evidence reason surfaced", msg)
	}

	// 2. Pin the finding (AI may pin — annotate-tier).
	resp, out = post(aiToken, "/api/interpretations", map[string]any{
		"investigation_ref":   invID.String(),
		"interpretation_type": "evidence-pin",
		"input_refs":          []string{"observed-data--od1"},
		"rationale":           "first-seen ASN logon for this user",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("pin: %d %v", resp.StatusCode, out)
	}
	pinID, _ := out["interpretation_id"].(string)

	// 3. AI-delegated verdict with the dial off (default) → 403 with the reason.
	resp, out = post(aiToken, "/api/interpretations", map[string]any{
		"investigation_ref":   invID.String(),
		"interpretation_type": "verdict",
		"verdict":             map[string]any{"disposition": "MALICIOUS"},
		"input_refs":          []string{"observed-data--od1"},
		"rationale":           "the delegate judges",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AI verdict with dial off = %d; want 403", resp.StatusCode)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "trust.ai_verdict") {
		t.Errorf("error = %q; want the dial named", msg)
	}

	// 4. Human verdict records, and the view serves the fold.
	resp, out = post(humanToken, "/api/interpretations", map[string]any{
		"investigation_ref":   invID.String(),
		"interpretation_type": "verdict",
		"verdict":             map[string]any{"disposition": "SUSPICIOUS"},
		"input_refs":          []string{"observed-data--od1"},
		"rationale":           "anomalous but not yet confirmed hostile",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("human verdict: %d %v", resp.StatusCode, out)
	}
	view := get(humanToken, "/api/investigations/"+invID.String())
	verdict, _ := view["verdict"].(map[string]any)
	if verdict == nil || verdict["disposition"] != "SUSPICIOUS" {
		t.Fatalf("view verdict = %v; want SUSPICIOUS", view["verdict"])
	}

	// 5. Verdicts revise by appending — the fold takes the latest.
	if resp, out = post(humanToken, "/api/interpretations", map[string]any{
		"investigation_ref":   invID.String(),
		"interpretation_type": "verdict",
		"verdict":             map[string]any{"disposition": "MALICIOUS"},
		"input_refs":          []string{"observed-data--od1"},
		"rationale":           "encoded execution confirms hostility",
	}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("verdict revision: %d %v", resp.StatusCode, out)
	}
	view = get(humanToken, "/api/investigations/"+invID.String())
	verdict, _ = view["verdict"].(map[string]any)
	if verdict == nil || verdict["disposition"] != "MALICIOUS" {
		t.Fatalf("view verdict after revision = %v; want MALICIOUS", view["verdict"])
	}
	if verdict["rationale"] != "encoded execution confirms hostility" {
		t.Errorf("verdict rationale = %v; want the revision's", verdict["rationale"])
	}

	// 6. The pin list serves the pin; superseding it (un-pin) flags it.
	pins := get(humanToken, "/api/investigations/"+invID.String()+"/pins")
	list, _ := pins["pins"].([]any)
	if len(list) != 1 {
		t.Fatalf("pins = %v; want 1", pins)
	}
	row, _ := list[0].(map[string]any)
	if row["actor"] != "AI_DELEGATED" || row["superseded"] == true {
		t.Errorf("pin row = %v; want an active AI_DELEGATED pin", row)
	}

	if resp, out = post(humanToken, "/api/interpretations/"+pinID+"/supersede", map[string]any{
		"investigation_ref": invID.String(),
		"reason":            "wrong host — the logon was expected",
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("supersede: %d %v", resp.StatusCode, out)
	}
	pins = get(humanToken, "/api/investigations/"+invID.String()+"/pins")
	list, _ = pins["pins"].([]any)
	row, _ = list[0].(map[string]any)
	if row["superseded"] != true {
		t.Errorf("pin row after supersede = %v; want superseded=true (visible, struck — never absent)", row)
	}
}

// TestVerdictFlow_AIDialOn: flipping the tenant dial admits the AI verdict,
// and the enabling config ref lands in the event payload (the audit shows
// what authorized the delegate to judge).
func TestVerdictFlow_AIDialOn(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := newTestBackend(t)
	b.cfg.AllowAIVerdict = true
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)

	aiToken := mintToken(t, map[string]any{"delegate_kind": "claude"})
	post := func(body any) (*http.Response, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/interpretations", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+aiToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		return resp, out
	}

	if resp, out := post(map[string]any{
		"investigation_ref": invID.String(), "interpretation_type": "evidence-pin",
		"input_refs": []string{"observed-data--od1"}, "rationale": "finding",
	}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("pin: %d %v", resp.StatusCode, out)
	}
	resp, out := post(map[string]any{
		"investigation_ref": invID.String(), "interpretation_type": "verdict",
		"verdict":    map[string]any{"disposition": "MALICIOUS"},
		"input_refs": []string{"observed-data--od1"}, "rationale": "delegate-judged under the dial",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("AI verdict with dial on: %d %v", resp.StatusCode, out)
	}

	// The enabling config ref rides the event payload.
	var payload []byte
	if err := testDB.QueryRow(
		`SELECT payload FROM events WHERE aggregate_id=$1 AND event_type='interpretation.recorded' AND payload ? 'verdict' ORDER BY sequence_no DESC LIMIT 1`,
		invID).Scan(&payload); err != nil {
		t.Fatalf("query verdict event: %v", err)
	}
	var rec struct {
		Verdict struct {
			Disposition string `json:"disposition"`
			ConfigRef   string `json:"config_ref"`
		} `json:"verdict"`
	}
	_ = json.Unmarshal(payload, &rec)
	if rec.Verdict.Disposition != "MALICIOUS" || rec.Verdict.ConfigRef != "trust.ai_verdict" {
		t.Errorf("event verdict = %+v; want MALICIOUS with the enabling config ref recorded", rec.Verdict)
	}
}
