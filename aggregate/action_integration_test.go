package aggregate

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mustActivate drives a fresh investigation to ACTIVE, returning its id.
func mustActivate(t *testing.T, h *Handler) uuid.UUID {
	t.Helper()
	aggID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-ACT"})
	mustHandle(t, h, cmdEnv(aggID), ActivateInvestigation{})
	return aggID
}

// TestAction_RequestApproveProjection is the C.1 done-bar: request → approve
// through the real handler, with the action_current projection reflecting the
// APPROVED status, mode, and approver.
func TestAction_RequestApproveProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	ctx := context.Background()
	h := newTestHandler()
	aggID := mustActivate(t, h)

	actionID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), RequestAction{
		ActionID:   actionID,
		ActionType: "host.isolate",
		Tier:       TierT2,
		Targets:    []TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-DC01"}},
		ExpiresAt:  time.Now().Add(time.Hour),
		Rationale:  "contain",
	})

	// Projected as REQUESTED with no mode yet.
	ac, err := LoadActionCurrent(ctx, testDB, actionID)
	if err != nil {
		t.Fatalf("LoadActionCurrent: %v", err)
	}
	if ac.Status != ActionStatusRequested || ac.Mode != "" {
		t.Errorf("after request: status=%q mode=%q; want REQUESTED / empty", ac.Status, ac.Mode)
	}
	if len(ac.Targets) != 1 || ac.Targets[0].ResolvedIdentifier != "WIN-DC01" {
		t.Errorf("targets not projected: %+v", ac.Targets)
	}

	// Approve (principal "alice" == approver).
	mustHandle(t, h, cmdEnv(aggID), ApproveAction{
		ActionID: actionID,
		Authorization: Authorization{
			Mode: AuthModeManual, Stage: AuthStageSolo,
			PrimaryApproverRef: "alice", PrimaryApprovedAt: time.Now(),
		},
	})

	ac, err = LoadActionCurrent(ctx, testDB, actionID)
	if err != nil {
		t.Fatalf("LoadActionCurrent after approve: %v", err)
	}
	if ac.Status != ActionStatusApproved {
		t.Errorf("status = %q; want APPROVED", ac.Status)
	}
	if ac.Mode != AuthModeManual || ac.PrimaryApprover != "alice" {
		t.Errorf("authorization not projected: mode=%q approver=%q", ac.Mode, ac.PrimaryApprover)
	}
}

// TestAction_ReplayRebuildsProjection: replaying the event stream rebuilds
// action_current to the same state (the projection is derived, never primary).
func TestAction_ReplayRebuildsProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	ctx := context.Background()
	h := newTestHandler()
	aggID := mustActivate(t, h)

	actionID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), RequestAction{
		ActionID: actionID, ActionType: "account.disable", Tier: TierT2,
		Targets:   []TargetSpec{{EntityRef: "user-account--1", ResolvedIdentifier: "CONTOSO\\jdoe"}},
		ExpiresAt: time.Now().Add(time.Hour), Rationale: "compromised",
	})
	mustHandle(t, h, cmdEnv(aggID), RejectAction{ActionID: actionID, Reason: "false positive"})

	before, err := LoadActionCurrent(ctx, testDB, actionID)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.Replay(ctx); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	after, err := LoadActionCurrent(ctx, testDB, actionID)
	if err != nil {
		t.Fatalf("LoadActionCurrent after replay: %v", err)
	}
	if after.Status != ActionStatusRejected || after.Status != before.Status {
		t.Errorf("replay changed status: before=%q after=%q; want REJECTED both", before.Status, after.Status)
	}
	if after.ActionType != before.ActionType || after.Tier != before.Tier {
		t.Errorf("replay changed immutable fields: %+v vs %+v", before, after)
	}
}

// TestAction_ApproveNonexistentRejected: approving an unknown action id fails
// (the fold sees no such action).
func TestAction_ApproveNonexistentRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	h := newTestHandler()
	aggID := mustActivate(t, h)

	_, err := h.Handle(context.Background(), cmdEnv(aggID), ApproveAction{
		ActionID:      uuid.New(),
		Authorization: Authorization{Mode: AuthModeManual, Stage: AuthStageSolo, PrimaryApproverRef: "alice", PrimaryApprovedAt: time.Now()},
	})
	if err == nil {
		t.Error("approving a nonexistent action should fail")
	}
}
