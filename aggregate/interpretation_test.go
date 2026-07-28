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
	// A free-standing reasoning type (pivot) — this test covers the shared
	// D.1 guards (type allowlist, rationale, confidence, tool-call/ref bounds);
	// the node-bearing types have their own guards in hypothesis_test.go.
	base := RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationPivot,
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

	// Tool calls need a call_id (else the event's tool_call_ref dangles) and a
	// tool_name.
	noCallID := base
	noCallID.ToolCalls = []ToolCallContent{{ToolName: "list_processes"}}
	if err := noCallID.Validate(env); err == nil {
		t.Error("tool call without call_id accepted")
	}
	noToolName := base
	noToolName.ToolCalls = []ToolCallContent{{CallID: "c1"}}
	if err := noToolName.Validate(env); err == nil {
		t.Error("tool call without tool_name accepted")
	}

	// Ref lists are bounded — the event log is not the bulk store.
	manyRefs := base
	for i := 0; i <= maxRefsPerInterpretation; i++ {
		manyRefs.InputRefs = append(manyRefs.InputRefs, "process--x")
	}
	if err := manyRefs.Validate(env); err == nil {
		t.Error("over-cap input_refs accepted")
	}

	// Individual ref strings are bounded too — a 9MB "ref" is bulk masquerading
	// as an id.
	bulkRef := base
	bulkRef.InputRefs = []string{strings.Repeat("x", maxRefRunes+1)}
	if err := bulkRef.Validate(env); err == nil {
		t.Error("over-long ref string accepted")
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
		InterpretationType: InterpretationPivot,
		InputRefs:          []string{"process--1"},
		OutputRefs:         []string{"ipv4-addr--1"},
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

// TestRecordInterpretation_ArgsHashMatchesStore: the event's content_hash must
// equal the hash of exactly the bytes the side store holds — for EMPTY args
// (both sides normalize through normalizeArgs; without it the event addresses
// SHA256("") while the store holds "{}") and for NON-CANONICAL JSON args (the
// store must preserve bytes exactly — TEXT, not JSONB, which re-serializes with
// different whitespace/key order; migration 0010). Either mismatch is a false
// tamper alarm for a verifier recomputing hashes.
func TestRecordInterpretation_ArgsHashMatchesStore(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	tenantID := uuid.New()
	h := NewHandler(NewStore(testDB), InvestigationCurrentProjector{}, ActionCurrentProjector{}).
		WithSideStore(NewSideStore(testDB))
	invID := activeInvestigation(t, h, tenantID)

	env := Envelope{
		AggregateID: invID, TenantID: tenantID, CorrelationID: uuid.New(),
		Actor: Actor{PrincipalID: "analyst-1"}, OccurredAt: newTestEnvelope("").OccurredAt,
	}
	res, err := h.Handle(context.Background(), env, RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationPivot,
		Rationale:          "pivoting to the peer host",
		ToolCalls: []ToolCallContent{
			{CallID: "c1", ToolName: "list_hosts"}, // no args → normalized {}
			// Compact JSON with unsorted keys: JSONB storage would re-serialize
			// this ({"b": 1, "a": 2} with spaces, keys sorted) and break the hash.
			{CallID: "c2", ToolName: "query", Args: json.RawMessage(`{"b":1,"a":2}`)},
		},
	})
	if err != nil {
		t.Fatalf("record interpretation: %v", err)
	}

	var rec InterpretationRecorded
	if err := json.Unmarshal(res.AppliedEvents[0].Payload, &rec); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if len(rec.ToolCallRefs) != 2 {
		t.Fatalf("tool_call_refs = %+v; want 2", rec.ToolCallRefs)
	}
	refByCall := map[string]string{}
	for _, ref := range rec.ToolCallRefs {
		refByCall[ref.CallID] = ref.ContentHash
	}

	// Recompute each hash from the STORED bytes — they must match the event.
	rows, err := testDB.Query(`SELECT tool_args FROM ai_tool_calls WHERE investigation_id=$1 ORDER BY id`, invID)
	if err != nil {
		t.Fatalf("stored tool calls: %v", err)
	}
	defer rows.Close()
	var stored [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, b)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 {
		t.Fatalf("stored tool calls = %d; want 2", len(stored))
	}
	if got, want := HashContent(stored[0]), refByCall["c1"]; got != want {
		t.Errorf("empty args: hash of stored %q = %s; event ref %s", stored[0], got, want)
	}
	if got, want := HashContent(stored[1]), refByCall["c2"]; got != want {
		t.Errorf("non-canonical args: hash of stored %q = %s; event ref %s (storage must be byte-exact)", stored[1], got, want)
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
	// The conclude gate needs a verdict (which needs a pin).
	if _, err := h.Handle(context.Background(), env(), RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: InterpretationEvidencePin,
		InputRefs: []string{"observed-data--x"}, Rationale: "finding",
	}); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if _, err := h.Handle(context.Background(), env(), RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: InterpretationVerdict,
		Verdict:   &VerdictNode{Disposition: VerdictBenign},
		InputRefs: []string{"observed-data--x"}, Rationale: "nothing further",
	}); err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if _, err := h.Handle(context.Background(), env(), ConcludeInvestigation{ReportRef: "report--1"}); err != nil {
		t.Fatalf("conclude: %v", err)
	}
	_, err := h.Handle(context.Background(), env(), RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationPivot,
		Rationale:          "late thought",
	})
	if err == nil {
		t.Fatal("reasoning accepted on a concluded investigation")
	}
}
