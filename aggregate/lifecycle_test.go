package aggregate

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// cmdEnv builds an envelope for a command against an existing aggregate id,
// with a fresh correlation_id (one logical act per command).
func cmdEnv(aggID uuid.UUID) Envelope {
	return Envelope{
		AggregateID:   aggID,
		TenantID:      testTenantID,
		CorrelationID: uuid.New(),
		Actor:         Actor{PrincipalID: "alice"},
		OccurredAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
}

func mustHandle(t *testing.T, h *Handler, env Envelope, cmd Command) Result {
	t.Helper()
	res, err := h.Handle(context.Background(), env, cmd)
	if err != nil {
		t.Fatalf("Handle %s: %v", cmd.Kind(), err)
	}
	return res
}

// recordVerdictFixture satisfies the conclude gate: pin one evidence item,
// then record a verdict citing it (01 §Verdict — no conclude without a
// verdict, no verdict without a pin).
func recordVerdictFixture(t *testing.T, h *Handler, aggID uuid.UUID) {
	t.Helper()
	mustHandle(t, h, cmdEnv(aggID), RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationEvidencePin,
		InputRefs:          []string{"observed-data--fixture"},
		Rationale:          "load-bearing finding",
	})
	mustHandle(t, h, cmdEnv(aggID), RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationVerdict,
		Verdict:            &VerdictNode{Disposition: VerdictMalicious},
		InputRefs:          []string{"observed-data--fixture"},
		Rationale:          "confirmed by the pinned finding",
	})
}

func assertProjection(t *testing.T, aggID uuid.UUID, wantStatus, wantConclusion string) {
	t.Helper()
	ic, err := LoadInvestigationCurrent(context.Background(), testDB, aggID)
	if err != nil {
		t.Fatalf("LoadInvestigationCurrent: %v", err)
	}
	if ic.Status != wantStatus {
		t.Errorf("status = %q; want %q", ic.Status, wantStatus)
	}
	if ic.ConclusionRef != wantConclusion {
		t.Errorf("conclusion_ref = %q; want %q", ic.ConclusionRef, wantConclusion)
	}
}

// TestLifecycle_HappyPath walks the full state machine and checks the
// projection at every step, including conclusion_ref set on conclude, cleared
// on reopen, and preserved through archive.
func TestLifecycle_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	h := newTestHandler()
	aggID := uuid.New()

	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-1"})
	assertProjection(t, aggID, StatusDraft, "")

	mustHandle(t, h, cmdEnv(aggID), ActivateInvestigation{})
	assertProjection(t, aggID, StatusActive, "")

	mustHandle(t, h, cmdEnv(aggID), PauseInvestigation{Reason: "waiting on EDR"})
	assertProjection(t, aggID, StatusPaused, "")

	mustHandle(t, h, cmdEnv(aggID), ResumeInvestigation{})
	assertProjection(t, aggID, StatusActive, "")

	recordVerdictFixture(t, h, aggID)
	mustHandle(t, h, cmdEnv(aggID), ConcludeInvestigation{ReportRef: "report--a", Summary: "true positive"})
	assertProjection(t, aggID, StatusConcluded, "report--a")

	mustHandle(t, h, cmdEnv(aggID), ReopenInvestigation{Reason: "new evidence"})
	assertProjection(t, aggID, StatusActive, "") // conclusion cleared

	mustHandle(t, h, cmdEnv(aggID), ConcludeInvestigation{ReportRef: "report--b"})
	assertProjection(t, aggID, StatusConcluded, "report--b")

	mustHandle(t, h, cmdEnv(aggID), ArchiveInvestigation{})
	assertProjection(t, aggID, StatusArchived, "report--b") // preserved on archive
}

// TestLifecycle_PairedInterpretation asserts every transition emits its domain
// event plus an InterpretationRecorded sharing the command's correlation_id,
// with the domain event referencing the interpretation.
func TestLifecycle_PairedInterpretation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	h := newTestHandler()
	aggID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-2"})

	env := cmdEnv(aggID)
	res := mustHandle(t, h, env, ActivateInvestigation{})

	if len(res.AppliedEvents) != 2 {
		t.Fatalf("activate produced %d events; want 2 (domain + interpretation)", len(res.AppliedEvents))
	}
	domain, interp := res.AppliedEvents[0], res.AppliedEvents[1]
	if domain.Type != EventTypeStatusChanged {
		t.Errorf("domain event type = %q; want %q", domain.Type, EventTypeStatusChanged)
	}
	if interp.Type != EventTypeInterpretationRecorded {
		t.Errorf("paired event type = %q; want %q", interp.Type, EventTypeInterpretationRecorded)
	}
	if domain.CorrelationID != interp.CorrelationID {
		t.Errorf("correlation ids differ: %s vs %s", domain.CorrelationID, interp.CorrelationID)
	}
	if domain.CorrelationID != env.CorrelationID {
		t.Errorf("event correlation id %s != command's %s", domain.CorrelationID, env.CorrelationID)
	}

	var ir InterpretationRecorded
	if err := json.Unmarshal(interp.Payload, &ir); err != nil {
		t.Fatalf("unmarshal interpretation: %v", err)
	}
	if ir.InterpretationType != InterpretationLifecycle {
		t.Errorf("interpretation_type = %q; want %q", ir.InterpretationType, InterpretationLifecycle)
	}
	var sc InvestigationStatusChanged
	if err := json.Unmarshal(domain.Payload, &sc); err != nil {
		t.Fatalf("unmarshal status_changed: %v", err)
	}
	if sc.LifecycleInterpretationRef != ir.InterpretationID {
		t.Errorf("domain ref %s != interpretation id %s", sc.LifecycleInterpretationRef, ir.InterpretationID)
	}
}

// TestLifecycle_InvalidTransitions rejects moves that don't match the current
// state, and command-shape violations.
func TestLifecycle_InvalidTransitions(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	h := newTestHandler()
	ctx := context.Background()
	aggID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-3"})

	// From draft: pause/resume/conclude/reopen are all illegal.
	for _, cmd := range []Command{
		PauseInvestigation{}, ResumeInvestigation{},
		ConcludeInvestigation{ReportRef: "r"}, ReopenInvestigation{},
	} {
		if _, err := h.Handle(ctx, cmdEnv(aggID), cmd); err == nil {
			t.Errorf("%s from draft should fail", cmd.Kind())
		}
	}

	// Conclude requires a ReportRef even from the active state.
	mustHandle(t, h, cmdEnv(aggID), ActivateInvestigation{})
	if _, err := h.Handle(ctx, cmdEnv(aggID), ConcludeInvestigation{}); err == nil {
		t.Error("conclude without ReportRef should fail validation")
	}

	// Command against a non-existent aggregate.
	if _, err := h.Handle(ctx, cmdEnv(uuid.New()), ActivateInvestigation{}); err == nil {
		t.Error("activate on non-existent investigation should fail")
	}
}

// TestLifecycle_ArchivedIsTerminal confirms an archived aggregate rejects every
// further command.
func TestLifecycle_ArchivedIsTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	h := newTestHandler()
	ctx := context.Background()
	aggID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-4"})
	mustHandle(t, h, cmdEnv(aggID), ActivateInvestigation{})
	recordVerdictFixture(t, h, aggID)
	mustHandle(t, h, cmdEnv(aggID), ConcludeInvestigation{ReportRef: "report--x"})
	mustHandle(t, h, cmdEnv(aggID), ArchiveInvestigation{})

	for _, cmd := range []Command{
		ActivateInvestigation{}, PauseInvestigation{}, ReopenInvestigation{},
		ConcludeInvestigation{ReportRef: "r"}, ArchiveInvestigation{},
	} {
		if _, err := h.Handle(ctx, cmdEnv(aggID), cmd); err == nil {
			t.Errorf("%s after archive should fail (terminal)", cmd.Kind())
		}
	}
}

// TestLifecycle_ReplayIdentical rebuilds the projection from the event stream
// after a sequence of lifecycle transitions and confirms it matches.
func TestLifecycle_ReplayIdentical(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	h := newTestHandler()
	ctx := context.Background()
	aggID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-5"})
	mustHandle(t, h, cmdEnv(aggID), ActivateInvestigation{})
	recordVerdictFixture(t, h, aggID)
	mustHandle(t, h, cmdEnv(aggID), ConcludeInvestigation{ReportRef: "report--z", Summary: "s"})

	before, err := LoadInvestigationCurrent(ctx, testDB, aggID)
	if err != nil {
		t.Fatalf("load before: %v", err)
	}
	if err := h.Replay(ctx); err != nil {
		t.Fatalf("replay: %v", err)
	}
	after, err := LoadInvestigationCurrent(ctx, testDB, aggID)
	if err != nil {
		t.Fatalf("load after: %v", err)
	}
	if before != after {
		t.Errorf("projection changed across replay:\n before=%+v\n after =%+v", before, after)
	}
	if after.Status != StatusConcluded || after.ConclusionRef != "report--z" {
		t.Errorf("post-replay state = %+v; want concluded/report--z", after)
	}
}
