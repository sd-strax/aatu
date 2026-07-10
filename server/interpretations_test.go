package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func postInterpretation(t *testing.T, b *Backend, token string, body RecordInterpretationBody) (*http.Response, RecordInterpretationResponse) {
	t.Helper()
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	t.Cleanup(srv.Close)

	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/interpretations", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out RecordInterpretationResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	return resp, out
}

// TestRecordInterpretation_Records: an AI-delegated agent (delegate_kind claim)
// posts a hypothesis interpretation with its transcript + tool call. The
// endpoint records the event and persists the side store — proving the agent is
// the legal author of x-interpretation through the HTTP seam (03 §1, 05 §3.4).
func TestRecordInterpretation_Records(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := newTestBackend(t)

	token := mintToken(t, map[string]any{"delegate_kind": "claude"})
	transcript := "assistant: proposing H1 from the beaconing pattern"
	resp, out := postInterpretation(t, b, token, RecordInterpretationBody{
		InvestigationRef:   invID.String(),
		InterpretationType: "hypothesis",
		InputRefs:          []string{"process--1"},
		OutputRefs:         []string{"x-hypothesis--1"},
		Rationale:          "beaconing consistent with C2",
		Confidence:         "MEDIUM",
		Transcript:         &TranscriptInput{TurnID: "t1", Body: transcript},
		ToolCalls: []ToolCallInput{
			{CallID: "c1", ToolName: "list_processes", Args: json.RawMessage(`{"host":"WIN-A"}`)},
		},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d; want 201", resp.StatusCode)
	}
	if out.InterpretationID == "" || out.SequenceNo == 0 {
		t.Fatalf("empty response: %+v", out)
	}

	// The transcript bytes are in the side store, and the tool call is logged
	// against this investigation.
	var n int
	if err := testDB.QueryRow(`SELECT count(*) FROM ai_transcripts WHERE body = $1`,
		[]byte(transcript)).Scan(&n); err != nil {
		t.Fatalf("query transcripts: %v", err)
	}
	if n != 1 {
		t.Errorf("ai_transcripts rows = %d; want 1", n)
	}
	if err := testDB.QueryRow(`SELECT count(*) FROM ai_tool_calls WHERE investigation_id = $1`,
		invID).Scan(&n); err != nil {
		t.Fatalf("query tool calls: %v", err)
	}
	if n != 1 {
		t.Errorf("ai_tool_calls rows = %d; want 1", n)
	}

	// The recorded event's actor is AI-delegated (derived from the JWT claim,
	// never the body) — the agent authored it as a delegate.
	var actorRaw []byte
	if err := testDB.QueryRow(`SELECT actor FROM events WHERE aggregate_id=$1 AND event_type='interpretation.recorded' ORDER BY sequence_no DESC LIMIT 1`,
		invID).Scan(&actorRaw); err != nil {
		t.Fatalf("query event actor: %v", err)
	}
	var actor struct {
		Kind     string `json:"kind"`
		Delegate *struct {
			Vendor string `json:"vendor"`
		} `json:"delegate"`
	}
	_ = json.Unmarshal(actorRaw, &actor)
	if actor.Kind != "AI_DELEGATED" || actor.Delegate == nil || actor.Delegate.Vendor != "claude" {
		t.Errorf("actor = %+v; want AI_DELEGATED/claude", actor)
	}
}

// TestRecordInterpretation_BadType: a lifecycle/action tag on the free-form
// reasoning path is rejected (422) — it would record a transition interpretation
// with no matching domain event.
func TestRecordInterpretation_BadType(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := newTestBackend(t)

	resp, _ := postInterpretation(t, b, mintToken(t, nil), RecordInterpretationBody{
		InvestigationRef:   invID.String(),
		InterpretationType: "action-approval",
		Rationale:          "trying to smuggle an approval",
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422", resp.StatusCode)
	}
}

// TestRecordInterpretation_BadTranscriptID: a malformed transcript_id is
// rejected (400), never silently replaced — a coerced fresh UUID would sever
// the turn from its conversation in the audit record.
func TestRecordInterpretation_BadTranscriptID(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := newTestBackend(t)

	resp, _ := postInterpretation(t, b, mintToken(t, nil), RecordInterpretationBody{
		InvestigationRef:   invID.String(),
		InterpretationType: "hypothesis",
		Rationale:          "valid otherwise",
		Transcript:         &TranscriptInput{TranscriptID: "not-a-uuid", Body: "hi"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", resp.StatusCode)
	}
}

// TestRecordInterpretation_BodyTooLarge: the route carries transcript bytes by
// design, so it is explicitly bounded — an over-limit body is a 400, not an
// unbounded read into memory and the side store.
func TestRecordInterpretation_BodyTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t)
	b := newTestBackend(t)

	resp, _ := postInterpretation(t, b, mintToken(t, nil), RecordInterpretationBody{
		InvestigationRef:   invID.String(),
		InterpretationType: "hypothesis",
		Rationale:          "huge transcript",
		Transcript:         &TranscriptInput{Body: strings.Repeat("x", maxInterpretationBodyBytes+1)},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", resp.StatusCode)
	}
}

// TestRecordInterpretation_AnalystOnly: a viewer token cannot write to the
// reasoning thread.
func TestRecordInterpretation_AnalystOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)

	token := mintToken(t, map[string]any{"realm_access": map[string]any{"roles": []string{"viewer"}}})
	resp, _ := postInterpretation(t, b, token, RecordInterpretationBody{
		InvestigationRef:   uuid.NewString(),
		InterpretationType: "hypothesis",
		Rationale:          "read-only should not write",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d; want 403", resp.StatusCode)
	}
}
