package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestInvestigationThread_ReassemblesReasoning: reasoning acts recorded through
// the interpretations endpoint come back from GET /thread in sequence order
// with actor attribution intact — the "how did it get here" surface (13 §4).
// The lifecycle interpretation paired with the activation transition appears
// too, proving the thread covers domain transitions without a separate query.
func TestInvestigationThread_ReassemblesReasoning(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := newTestBackend(t)

	aiToken := mintToken(t, map[string]any{"delegate_kind": "claude"})
	if resp, _ := postInterpretation(t, b, aiToken, RecordInterpretationBody{
		InvestigationRef:   invID.String(),
		InterpretationType: "pivot",
		InputRefs:          []string{"process--1"},
		Rationale:          "beaconing consistent with C2",
		Confidence:         "MEDIUM",
		Transcript:         &TranscriptInput{TurnID: "t1", Body: "assistant: pivoting"},
		ToolCalls: []ToolCallInput{
			{CallID: "c1", ToolName: "list_processes", Args: json.RawMessage(`{"host":"WIN-A"}`)},
		},
	}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("record interpretation: %d", resp.StatusCode)
	}

	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/investigations/"+invID.String()+"/thread", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /thread = %d", resp.StatusCode)
	}
	var out struct {
		Thread []ThreadEntryView `json:"thread"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	// At least the activation's lifecycle interpretation + the pivot, in
	// sequence order.
	if len(out.Thread) < 2 {
		t.Fatalf("thread entries = %d; want >= 2 (lifecycle + pivot)", len(out.Thread))
	}
	for i := 1; i < len(out.Thread); i++ {
		if out.Thread[i].SequenceNo <= out.Thread[i-1].SequenceNo {
			t.Fatalf("thread out of order at %d: %+v", i, out.Thread)
		}
	}

	last := out.Thread[len(out.Thread)-1]
	if last.InterpretationType != "pivot" || last.Summary != "beaconing consistent with C2" {
		t.Errorf("last entry = %+v; want the pivot with its rationale", last)
	}
	if last.Actor.Kind != "AI_DELEGATED" || last.Actor.Principal == "" {
		t.Errorf("actor = %+v; want AI_DELEGATED with the human principal", last.Actor)
	}
	if last.Confidence != "MEDIUM" || last.ToolCalls != 1 || !last.HasTranscript {
		t.Errorf("provenance fields lost: %+v", last)
	}

	sawLifecycle := false
	for _, e := range out.Thread {
		if e.InterpretationType == "lifecycle" {
			sawLifecycle = true
		}
	}
	if !sawLifecycle {
		t.Error("no lifecycle interpretation — domain transitions missing from the thread")
	}
}
