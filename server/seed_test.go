package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSeedsAppearancesProvenance_EndToEnd drives the blocker-batch surfaces
// through the HTTP seam: a seeded creation (the seed picker's contract), the
// seed on views and the list's triage line, ref appearances accumulating from
// seeds and interpretation citations across TWO investigations (the
// "appears in N other investigations" join), consulted-SOP provenance on the
// thread, and transcript-open.
func TestSeedsAppearancesProvenance_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	if _, err := testDB.Exec(`TRUNCATE ref_appearances`); err != nil {
		t.Fatal(err)
	}
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	token := mintToken(t, nil)

	post := func(path string, body any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	get := func(path string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	const entityRef = "x-host--e4c1b0a2-9f3d-5e88-b1c4-7a02d9f4e110"

	// 1. An entity-seeded investigation (the "have I seen this host" root).
	code, out := post("/api/investigations", map[string]any{
		"title": "WIN-FIN-04 lateral movement",
		"seed":  map[string]any{"type": "entity", "entity_ref": entityRef},
	})
	if code != http.StatusCreated {
		t.Fatalf("seeded create = %d %v", code, out)
	}
	invA, _ := out["aggregate_id"].(string)

	// A malformed seed is refused with the reason.
	if code, out = post("/api/investigations", map[string]any{
		"title": "bad", "seed": map[string]any{"type": "alert", "alert_id": "A-1"},
	}); code == http.StatusCreated {
		t.Fatal("alert seed without source accepted")
	} else if msg, _ := out["error"].(string); !strings.Contains(msg, "source") {
		t.Errorf("error = %q; want the missing field named", msg)
	}

	// 2. The view and the list carry the seed.
	if _, out = get("/api/investigations/" + invA); out["seed_summary"] != entityRef {
		t.Errorf("view seed_summary = %v; want the entity ref", out["seed_summary"])
	}
	_, lst := get("/api/investigations")
	rows, _ := lst["investigations"].([]any)
	found := false
	for _, r := range rows {
		row, _ := r.(map[string]any)
		if row["aggregate_id"] == invA && row["seed_summary"] == entityRef {
			found = true
		}
	}
	if !found {
		t.Error("list rows missing the seeded investigation's triage line")
	}

	// 3. A second investigation cites the same entity in a reasoning act (with
	// consulted-SOP provenance and a transcript).
	code, out = post("/api/investigations", map[string]any{"title": "second case"})
	if code != http.StatusCreated {
		t.Fatalf("create B = %d", code)
	}
	invB, _ := out["aggregate_id"].(string)
	code, out = post("/api/interpretations", map[string]any{
		"investigation_ref":   invB,
		"interpretation_type": "pivot",
		"input_refs":          []string{entityRef},
		"rationale":           "same host as the finance case",
		"consulted_sops": []map[string]any{
			{"sop_id": "sop-1", "title": "Lateral Movement Triage", "retrieval_score": 0.91, "used": true},
		},
		"transcript": map[string]any{"turn_id": "t1", "body": "assistant: pivoting on the shared host"},
	})
	if code != http.StatusCreated {
		t.Fatalf("interpretation = %d %v", code, out)
	}
	interpID, _ := out["interpretation_id"].(string)

	// 4. Appearances: the entity now appears in BOTH investigations — the seed
	// rooted one and the citing one.
	_, apps := get("/api/entities/" + entityRef + "/appearances")
	list, _ := apps["appearances"].([]any)
	if len(list) != 2 {
		t.Fatalf("appearances = %d (%v); want 2", len(list), apps)
	}

	// 5. The thread carries the knowledge provenance.
	_, thread := get("/api/investigations/" + invB + "/thread")
	entries, _ := thread["thread"].([]any)
	sawSOP := false
	for _, e := range entries {
		entry, _ := e.(map[string]any)
		if sops, ok := entry["consulted_sops"].([]any); ok && len(sops) == 1 {
			sop, _ := sops[0].(map[string]any)
			if sop["sop_id"] == "sop-1" && sop["used"] == true {
				sawSOP = true
			}
		}
	}
	if !sawSOP {
		t.Errorf("thread missing consulted-SOP provenance: %v", thread)
	}

	// 6. Transcript-open serves the committed bytes.
	code, tr := get("/api/interpretations/" + interpID + "/transcript")
	if code != http.StatusOK || tr["body"] != "assistant: pivoting on the shared host" {
		t.Errorf("transcript = %d %v; want the committed body", code, tr)
	}
	// An act with no transcript is an honest 404.
	code, out = post("/api/interpretations", map[string]any{
		"investigation_ref": invB, "interpretation_type": "pivot",
		"input_refs": []string{entityRef}, "rationale": "no transcript here",
	})
	if code != http.StatusCreated {
		t.Fatalf("bare interpretation = %d", code)
	}
	bare, _ := out["interpretation_id"].(string)
	if code, _ = get("/api/interpretations/" + bare + "/transcript"); code != http.StatusNotFound {
		t.Errorf("transcript of transcript-less act = %d; want 404", code)
	}
}
