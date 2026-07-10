package aggregate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestRecordInterpretation_Validate covers the command-shape guards (pure — no
// DB): a reasoning-type tag is required, a lifecycle/action tag is rejected, the
// rationale is mandatory and bounded, and confidence is a closed vocabulary.
func TestRecordInterpretation_Validate(t *testing.T) {
	env := newTestEnvelope("analyst-1")
	base := RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationHypothesis,
		Rationale:          "the host beaconed to a known-bad domain",
	}
	if err := base.Validate(env); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}

	// A lifecycle/action tag must not slip through the free-form reasoning path.
	bad := base
	bad.InterpretationType = InterpretationLifecycle
	if err := bad.Validate(env); err == nil {
		t.Error("lifecycle tag accepted as a reasoning interpretation type")
	}
	bad.InterpretationType = InterpretationActionApproval
	if err := bad.Validate(env); err == nil {
		t.Error("action-approval tag accepted as a reasoning interpretation type")
	}

	// Rationale required + bounded.
	noRat := base
	noRat.Rationale = ""
	if err := noRat.Validate(env); err == nil {
		t.Error("empty rationale accepted")
	}
	longRat := base
	longRat.Rationale = strings.Repeat("x", rationaleMaxRunes+1)
	if err := longRat.Validate(env); err == nil {
		t.Error("over-long rationale accepted")
	}

	// Confidence vocabulary.
	badConf := base
	badConf.Confidence = "PROBABLY"
	if err := badConf.Validate(env); err == nil {
		t.Error("invalid confidence accepted")
	}
}

// activeInvestigation drives a fresh aggregate to ACTIVE via h and returns its
// id, so a reasoning act can be recorded against it.
func activeInvestigation(t *testing.T, h *Handler, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	env := func() Envelope {
		return Envelope{
			AggregateID: id, TenantID: tenantID, CorrelationID: uuid.New(),
			Actor: Actor{PrincipalID: "analyst-1"}, OccurredAt: newTestEnvelope("").OccurredAt,
		}
	}
	if _, err := h.Handle(context.Background(), env(), CreateInvestigation{Title: "INV"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := h.Handle(context.Background(), env(), ActivateInvestigation{}); err != nil {
		t.Fatalf("activate: %v", err)
	}
	return id
}

// TestRecordInterpretation_RecordsEventAndSideStore: an AI-delegated reasoning
// act (the agent is the legal author of x-interpretation) appends one
// InterpretationRecorded event carrying the content hash, and the transcript +
// tool-call bytes land in the side store within the same commit.
func TestRecordInterpretation_RecordsEventAndSideStore(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	tenantID := uuid.New()
	h := NewHandler(NewStore(testDB), InvestigationCurrentProjector{}, ActionCurrentProjector{}).
		WithSideStore(NewSideStore(testDB))
	invID := activeInvestigation(t, h, tenantID)

	transcript := []byte("system: you are a hunter\nassistant: proposing hypothesis H1")
	args := json.RawMessage(`{"entity":"WIN-A"}`)
	cmd := RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationHypothesis,
		InputRefs:          []string{"process--1"},
		OutputRefs:         []string{"x-hypothesis--1"},
		Rationale:          "beaconing pattern consistent with C2",
		Confidence:         ConfidenceMedium,
		Transcript:         &TranscriptContent{TranscriptID: uuid.New(), TurnID: "turn-1", Body: transcript},
		ToolCalls: []ToolCallContent{
			{CallID: "c1", ToolName: "list_processes", Args: args, ResultHash: "abc123"},
		},
	}
	// AI-delegated actor: the agent authors the interpretation (allowlisted).
	env := Envelope{
		AggregateID: invID, TenantID: tenantID, CorrelationID: uuid.New(),
		Actor:      Actor{PrincipalID: "analyst-1", Kind: ActorAIDelegated, Delegate: &AIDelegate{Vendor: "claude"}},
		OccurredAt: newTestEnvelope("").OccurredAt,
	}
	res, err := h.Handle(context.Background(), env, cmd)
	if err != nil {
		t.Fatalf("record interpretation: %v", err)
	}
	if len(res.AppliedEvents) != 1 || res.AppliedEvents[0].Type != EventTypeInterpretationRecorded {
		t.Fatalf("expected one interpretation.recorded event, got %+v", res.AppliedEvents)
	}

	// The event carries the content hash of the transcript we sent.
	var rec InterpretationRecorded
	if err := json.Unmarshal(res.AppliedEvents[0].Payload, &rec); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	wantHash := HashContent(transcript)
	if rec.TranscriptRef == nil || rec.TranscriptRef.ContentHash != wantHash {
		t.Fatalf("transcript_ref hash = %+v; want %s", rec.TranscriptRef, wantHash)
	}
	if rec.DerivationMode != DerivationInferred {
		t.Errorf("derivation_mode = %q; want INFERRED", rec.DerivationMode)
	}
	if len(rec.ToolCallRefs) != 1 || rec.ToolCallRefs[0].ContentHash != HashContent(args) {
		t.Errorf("tool_call_refs = %+v; want one with args hash", rec.ToolCallRefs)
	}

	// The transcript bytes are in the side store under that hash.
	var body []byte
	if err := testDB.QueryRow(`SELECT body FROM ai_transcripts WHERE tenant_id=$1 AND hash=$2`,
		tenantID, wantHash).Scan(&body); err != nil {
		t.Fatalf("transcript not in side store: %v", err)
	}
	if string(body) != string(transcript) {
		t.Errorf("stored transcript mismatch")
	}

	// The tool call is logged, linked to the interpretation event id.
	var toolName string
	var eventID uuid.UUID
	if err := testDB.QueryRow(`SELECT tool_name, event_id FROM ai_tool_calls WHERE investigation_id=$1`,
		invID).Scan(&toolName, &eventID); err != nil {
		t.Fatalf("tool call not logged: %v", err)
	}
	if toolName != "list_processes" || eventID != res.AppliedEvents[0].EventID {
		t.Errorf("tool call = (%s, %s); want (list_processes, %s)", toolName, eventID, res.AppliedEvents[0].EventID)
	}
}

// TestRecordInterpretation_RejectedWhenConcluded: reasoning requires a
// pre-conclusion state — a concluded investigation must be reopened first.
func TestRecordInterpretation_RejectedWhenConcluded(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	tenantID := uuid.New()
	h := NewHandler(NewStore(testDB), InvestigationCurrentProjector{}, ActionCurrentProjector{}).
		WithSideStore(NewSideStore(testDB))
	invID := activeInvestigation(t, h, tenantID)

	env := func() Envelope {
		return Envelope{
			AggregateID: invID, TenantID: tenantID, CorrelationID: uuid.New(),
			Actor: Actor{PrincipalID: "analyst-1"}, OccurredAt: newTestEnvelope("").OccurredAt,
		}
	}
	if _, err := h.Handle(context.Background(), env(), ConcludeInvestigation{ReportRef: "report--1"}); err != nil {
		t.Fatalf("conclude: %v", err)
	}
	_, err := h.Handle(context.Background(), env(), RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationHypothesis,
		Rationale:          "late thought",
	})
	if err == nil {
		t.Fatal("reasoning accepted on a concluded investigation")
	}
}
