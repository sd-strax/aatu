package aggregate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// activeStateWithAction returns a folded state for an ACTIVE investigation that
// optionally already carries one action in the given status.
func activeStateWithAction(env Envelope, actionID uuid.UUID, status string) aggregateState {
	s := aggregateState{
		Seq: 4, Exists: true, TenantID: env.TenantID, Status: StatusActive,
		Actions: map[uuid.UUID]actionState{},
	}
	if status != "" {
		s.Actions[actionID] = actionState{Status: status, Tier: TierT2}
	}
	return s
}

func sampleRequest(id uuid.UUID) RequestAction {
	return RequestAction{
		ActionID:   id,
		ActionType: "host.isolate",
		Tier:       TierT2,
		Targets:    []TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-DC01"}},
		ExpiresAt:  time.Now().Add(time.Hour),
		Rationale:  "contain lateral movement",
	}
}

// TestRequestAction_ProducesPairedEvents: a request emits (ActionRequested,
// action-request Interpretation) sharing a correlation_id, with the domain
// event pointing at the producing interpretation.
func TestRequestAction_ProducesPairedEvents(t *testing.T) {
	env := newTestEnvelope("alice")
	id := uuid.New()
	events, err := applyCommand(env, sampleRequest(id), activeStateWithAction(env, id, ""))
	if err != nil {
		t.Fatalf("applyCommand: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("produced %d events; want 2 (domain + interpretation)", len(events))
	}
	domain, interp := events[0], events[1]
	if domain.Type != EventTypeActionRequested {
		t.Errorf("domain type = %q; want %q", domain.Type, EventTypeActionRequested)
	}
	if interp.Type != EventTypeInterpretationRecorded {
		t.Errorf("paired type = %q; want %q", interp.Type, EventTypeInterpretationRecorded)
	}
	if domain.CorrelationID != env.CorrelationID || interp.CorrelationID != env.CorrelationID {
		t.Error("paired events do not share the command's correlation_id")
	}

	var req ActionRequested
	if err := json.Unmarshal(domain.Payload, &req); err != nil {
		t.Fatal(err)
	}
	var ir InterpretationRecorded
	if err := json.Unmarshal(interp.Payload, &ir); err != nil {
		t.Fatal(err)
	}
	if ir.InterpretationType != InterpretationActionRequest {
		t.Errorf("interpretation_type = %q; want %q", ir.InterpretationType, InterpretationActionRequest)
	}
	if req.RequestingInterpretationID != ir.InterpretationID {
		t.Errorf("action's requesting_interpretation_id %s != interpretation id %s",
			req.RequestingInterpretationID, ir.InterpretationID)
	}
	if req.ActionID != id {
		t.Errorf("action_id = %s; want %s", req.ActionID, id)
	}
}

// TestRequestAction_EmitsPolicyEvaluated: when Gate 2 ran (evaluations present),
// the PolicyEvaluated audit event is written in the SAME transaction as
// ActionRequested (02 §3), sharing the correlation_id, and is audit-only (does
// not move the action off REQUESTED).
func TestRequestAction_EmitsPolicyEvaluated(t *testing.T) {
	env := newTestEnvelope("alice")
	id := uuid.New()
	cmd := sampleRequest(id)
	cmd.PolicyEvaluations = []PolicyEvaluationRecord{
		{PolicyRef: "policy/ai-no-tier3/1.0.0", PolicyVersion: "abc", WouldHaveFired: false, Effect: "DENY"},
	}
	cmd.MatchedPolicyRef = ""

	events, err := applyCommand(env, cmd, activeStateWithAction(env, id, ""))
	if err != nil {
		t.Fatalf("applyCommand: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("produced %d events; want 3 (requested + interpretation + policy_evaluated)", len(events))
	}
	pe := events[2]
	if pe.Type != EventTypeActionPolicyEvaluated {
		t.Errorf("third event = %q; want %q", pe.Type, EventTypeActionPolicyEvaluated)
	}
	if pe.CorrelationID != env.CorrelationID {
		t.Error("policy_evaluated does not share the request's correlation_id")
	}

	// Audit-only: folding the whole batch leaves the action REQUESTED.
	folded := foldInto(map[uuid.UUID]actionState{}, events)
	if folded[id].Status != ActionStatusRequested {
		t.Errorf("after request+policy_evaluated, status = %q; want REQUESTED", folded[id].Status)
	}
}

// TestRequestAction_StatePreconditions: allowed only on ACTIVE, or CONCLUDED for
// a reversal.
func TestRequestAction_StatePreconditions(t *testing.T) {
	env := newTestEnvelope("alice")
	id := uuid.New()

	draft := aggregateState{Seq: 1, Exists: true, TenantID: env.TenantID, Status: StatusDraft, Actions: map[uuid.UUID]actionState{}}
	if _, err := applyCommand(env, sampleRequest(id), draft); err == nil {
		t.Error("RequestAction on DRAFT should be rejected")
	}

	concluded := aggregateState{Seq: 1, Exists: true, TenantID: env.TenantID, Status: StatusConcluded, Actions: map[uuid.UUID]actionState{}}
	if _, err := applyCommand(env, sampleRequest(id), concluded); err == nil {
		t.Error("non-reversal RequestAction on CONCLUDED should be rejected")
	}
	rev := sampleRequest(id)
	rev.IsReversal = true
	if _, err := applyCommand(env, rev, concluded); err != nil {
		t.Errorf("reversal RequestAction on CONCLUDED should be allowed: %v", err)
	}
}

// TestApproveAction_ActorApproverInvariant: the acting principal must be the
// approver (04 §3.3).
func TestApproveAction_ActorApproverInvariant(t *testing.T) {
	env := newTestEnvelope("alice")
	id := uuid.New()
	state := activeStateWithAction(env, id, ActionStatusRequested)

	// Approver != acting principal → rejected.
	mismatch := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeManual, Stage: AuthStageSolo, PrimaryApproverRef: "bob", PrimaryApprovedAt: time.Now(),
	}}
	if _, err := applyCommand(env, mismatch, state); err == nil {
		t.Error("approval by a non-approver principal should be rejected")
	}

	// Approver == acting principal → APPROVED.
	ok := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeManual, Stage: AuthStageSolo, PrimaryApproverRef: "alice", PrimaryApprovedAt: time.Now(),
	}}
	events, err := applyCommand(env, ok, state)
	if err != nil {
		t.Fatalf("valid approval rejected: %v", err)
	}
	if events[0].Type != EventTypeActionApproved {
		t.Errorf("domain type = %q; want %q", events[0].Type, EventTypeActionApproved)
	}
}

// TestApproveAction_TwoPartyStages: a TWO_PARTY primary approval pends secondary;
// the secondary (a different approver) finalizes.
func TestApproveAction_TwoPartyStages(t *testing.T) {
	env := newTestEnvelope("alice")
	id := uuid.New()

	// Primary approval on a REQUESTED action.
	reqState := activeStateWithAction(env, id, ActionStatusRequested)
	primary := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeTwoParty, Stage: AuthStagePrimary, PrimaryApproverRef: "alice", PrimaryApprovedAt: time.Now(),
	}}
	events, err := applyCommand(env, primary, reqState)
	if err != nil {
		t.Fatalf("primary approval: %v", err)
	}
	// Fold the emitted events: status should be PENDING_SECONDARY.
	folded := foldInto(reqState.Actions, events)
	if folded[id].Status != ActionStatusPendingSecondary {
		t.Fatalf("after primary, status = %q; want PENDING_SECONDARY", folded[id].Status)
	}

	// Secondary approval by a different principal on the pending action.
	env2 := newTestEnvelope("bob")
	env2.AggregateID = env.AggregateID
	pendState := aggregateState{Seq: 6, Exists: true, TenantID: env.TenantID, Status: StatusActive, Actions: folded}
	secTime := time.Now()
	secondary := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeTwoParty, Stage: AuthStageSecondary,
		PrimaryApproverRef: "alice", SecondaryApproverRef: "bob", SecondaryApprovedAt: &secTime,
	}}
	events2, err := applyCommand(env2, secondary, pendState)
	if err != nil {
		t.Fatalf("secondary approval: %v", err)
	}
	if foldInto(pendState.Actions, events2)[id].Status != ActionStatusApproved {
		t.Error("after secondary, status should be APPROVED")
	}
}

// TestAIWriteProtection: an AI_DELEGATED actor may request an action but can
// never approve, reject, or expire one (04 §5.6).
func TestAIWriteProtection(t *testing.T) {
	env := newTestEnvelope("alice")
	env.Actor.Kind = ActorAIDelegated
	id := uuid.New()

	// Request is permitted for the AI.
	if _, err := applyCommand(env, sampleRequest(id), activeStateWithAction(env, id, "")); err != nil {
		t.Errorf("AI RequestAction should be allowed: %v", err)
	}

	// Approve/Reject/Expire are all forbidden for the AI.
	state := activeStateWithAction(env, id, ActionStatusRequested)
	forbidden := []Command{
		ApproveAction{ActionID: id, Authorization: Authorization{Mode: AuthModeManual, Stage: AuthStageSolo, PrimaryApproverRef: "alice", PrimaryApprovedAt: time.Now()}},
		RejectAction{ActionID: id, Reason: "no"},
		ExpireAction{ActionID: id},
	}
	for _, cmd := range forbidden {
		if _, err := applyCommand(env, cmd, state); err == nil {
			t.Errorf("AI_DELEGATED %s should be rejected", cmd.Kind())
		}
	}
}

// TestDispatchResult_SystemOnlyAndTransitions: dispatch/result require a SYSTEM
// actor and the right source state (APPROVED → dispatch → EXECUTING → result).
func TestDispatchResult_SystemOnlyAndTransitions(t *testing.T) {
	id := uuid.New()

	// A human cannot dispatch — system-only guard.
	human := newTestEnvelope("alice")
	approved := activeStateWithAction(human, id, ActionStatusApproved)
	if _, err := applyCommand(human, DispatchAction{ActionID: id}, approved); err == nil {
		t.Error("human DispatchAction should be rejected (system-only)")
	}

	// SYSTEM dispatches an APPROVED action → EXECUTING.
	sys := newTestEnvelope("alice")
	sys.Actor.Kind = ActorSystem
	events, err := applyCommand(sys, DispatchAction{ActionID: id, Adapter: "fx", AdapterRequestID: "wf-1"}, approved)
	if err != nil {
		t.Fatalf("system dispatch: %v", err)
	}
	if events[0].Type != EventTypeActionDispatched {
		t.Errorf("domain type = %q; want dispatched", events[0].Type)
	}
	executing := foldInto(approved.Actions, events)
	if executing[id].Status != ActionStatusExecuting {
		t.Fatalf("after dispatch status = %q; want EXECUTING", executing[id].Status)
	}

	// Dispatch requires APPROVED — from REQUESTED it's rejected.
	req := activeStateWithAction(sys, id, ActionStatusRequested)
	if _, err := applyCommand(sys, DispatchAction{ActionID: id}, req); err == nil {
		t.Error("DispatchAction from REQUESTED should be rejected")
	}

	// SYSTEM records the result on the EXECUTING action → SUCCEEDED.
	execState := aggregateState{Seq: 8, Exists: true, TenantID: sys.TenantID, Status: StatusActive, Actions: executing}
	revents, err := applyCommand(sys, ResultAction{ActionID: id, FinalOutcome: "SUCCEEDED", PerTargetResults: map[string]string{"0": "OK"}, Attempts: 1}, execState)
	if err != nil {
		t.Fatalf("system result: %v", err)
	}
	if foldInto(executing, revents)[id].Status != ActionStatusSucceeded {
		t.Error("after SUCCEEDED result, status should be SUCCEEDED")
	}
}

// TestReverseAction: SYSTEM-only, legal only from SUCCEEDED, moves the original
// to REVERSED (04 §7).
func TestReverseAction(t *testing.T) {
	origID, revID := uuid.New(), uuid.New()

	sys := newTestEnvelope("alice")
	sys.Actor.Kind = ActorSystem
	succeeded := activeStateWithAction(sys, origID, ActionStatusSucceeded)

	events, err := applyCommand(sys, ReverseAction{OriginalActionID: origID, ReversingActionID: revID}, succeeded)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if events[0].Type != EventTypeActionReversed {
		t.Errorf("domain type = %q; want reversed", events[0].Type)
	}
	if foldInto(succeeded.Actions, events)[origID].Status != ActionStatusReversed {
		t.Error("original status should be REVERSED")
	}

	// Only a SUCCEEDED action can be reversed.
	req := activeStateWithAction(sys, origID, ActionStatusRequested)
	if _, err := applyCommand(sys, ReverseAction{OriginalActionID: origID, ReversingActionID: revID}, req); err == nil {
		t.Error("reversing a non-SUCCEEDED action should be rejected")
	}

	// System-only: a human cannot forge a reversal.
	human := newTestEnvelope("alice")
	if _, err := applyCommand(human, ReverseAction{OriginalActionID: origID, ReversingActionID: revID}, succeeded); err == nil {
		t.Error("human ReverseAction should be rejected (system-only)")
	}
}

// TestRecordReversalAttempt: SYSTEM-only, legal only from SUCCEEDED, and — the
// core of 04 §7.1 Position C — the original's status does NOT change: the
// unverified attempt is a back-reference on the projection, never a REVERSED
// claim.
func TestRecordReversalAttempt(t *testing.T) {
	origID, revID := uuid.New(), uuid.New()

	sys := newTestEnvelope("alice")
	sys.Actor.Kind = ActorSystem
	succeeded := activeStateWithAction(sys, origID, ActionStatusSucceeded)

	events, err := applyCommand(sys, RecordReversalAttempt{OriginalActionID: origID, ReversingActionID: revID}, succeeded)
	if err != nil {
		t.Fatalf("record attempt: %v", err)
	}
	if events[0].Type != EventTypeActionReversalAttempted {
		t.Errorf("domain type = %q; want reversal_attempted", events[0].Type)
	}
	// The honest-state assertion: folding the attempt leaves the original
	// SUCCEEDED (no case in foldActionEvent touches it, by design).
	if got := foldInto(succeeded.Actions, events)[origID].Status; got != ActionStatusSucceeded {
		t.Errorf("original status after attempt = %q; must stay SUCCEEDED", got)
	}

	// Only a SUCCEEDED action has an effect to attempt to reverse.
	req := activeStateWithAction(sys, origID, ActionStatusRequested)
	if _, err := applyCommand(sys, RecordReversalAttempt{OriginalActionID: origID, ReversingActionID: revID}, req); err == nil {
		t.Error("attempt on a non-SUCCEEDED action should be rejected")
	}

	// System-only: a human cannot forge an attempt record.
	human := newTestEnvelope("alice")
	if _, err := applyCommand(human, RecordReversalAttempt{OriginalActionID: origID, ReversingActionID: revID}, succeeded); err == nil {
		t.Error("human RecordReversalAttempt should be rejected (system-only)")
	}
}

// TestAIAllowlist: the AI guard is an ALLOWLIST (04 §5.6) — T1-annotate
// commands and RequestAction pass; conclude/archive and any unlisted command
// default to denied.
func TestAIAllowlist(t *testing.T) {
	env := newTestEnvelope("alice")
	env.Actor.Kind = ActorAIDelegated

	// T1: lifecycle draft→active is AI-permitted (04 §1).
	draft := aggregateState{Seq: 1, Exists: true, TenantID: env.TenantID, Status: StatusDraft, Actions: map[uuid.UUID]actionState{}}
	if _, err := applyCommand(env, ActivateInvestigation{}, draft); err != nil {
		t.Errorf("AI Activate (T1) should be allowed: %v", err)
	}

	// Concluding an investigation is a human act — denied by default.
	active := aggregateState{Seq: 1, Exists: true, TenantID: env.TenantID, Status: StatusActive, Actions: map[uuid.UUID]actionState{}}
	if _, err := applyCommand(env, ConcludeInvestigation{ReportRef: "r", Summary: "s"}, active); err == nil {
		t.Error("AI ConcludeInvestigation should be denied (not in allowlist)")
	}
}

// TestApproveAction_ModeStageConsistency: 04 §3.3 pairs are enforced at
// Validate — TWO_PARTY+SOLO (the one-step secondary bypass) and MANUAL+PRIMARY
// are both malformed.
func TestApproveAction_ModeStageConsistency(t *testing.T) {
	env := newTestEnvelope("alice")
	id := uuid.New()
	state := activeStateWithAction(env, id, ActionStatusRequested)

	bypass := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeTwoParty, Stage: AuthStageSolo, PrimaryApproverRef: "alice", PrimaryApprovedAt: time.Now(),
	}}
	if _, err := applyCommand(env, bypass, state); err == nil {
		t.Error("TWO_PARTY with stage SOLO must be rejected (one-step secondary bypass)")
	}

	malformed := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeManual, Stage: AuthStagePrimary, PrimaryApproverRef: "alice", PrimaryApprovedAt: time.Now(),
	}}
	if _, err := applyCommand(env, malformed, state); err == nil {
		t.Error("MANUAL with stage PRIMARY must be rejected")
	}
}

// TestApproveAction_TwoPartyIntegrity: the secondary approver must differ from
// the primary, and the secondary event's primary_approver_ref must match the
// recorded primary approval (folded state, not the caller's payload).
func TestApproveAction_TwoPartyIntegrity(t *testing.T) {
	env := newTestEnvelope("alice")
	id := uuid.New()
	pending := activeStateWithAction(env, id, ActionStatusPendingSecondary)
	act := pending.Actions[id]
	act.PrimaryApprover = "alice"
	pending.Actions[id] = act

	// Same human approving both stages → rejected.
	self := newTestEnvelope("alice")
	self.AggregateID = env.AggregateID
	sameHuman := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeTwoParty, Stage: AuthStageSecondary,
		PrimaryApproverRef: "alice", SecondaryApproverRef: "alice",
	}}
	if _, err := applyCommand(self, sameHuman, pending); err == nil {
		t.Error("secondary approver == primary approver must be rejected (TWO_PARTY requires two humans)")
	}

	// A secondary event rewriting who the primary was → rejected.
	bob := newTestEnvelope("bob")
	bob.AggregateID = env.AggregateID
	rewrite := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeTwoParty, Stage: AuthStageSecondary,
		PrimaryApproverRef: "mallory", SecondaryApproverRef: "bob",
	}}
	if _, err := applyCommand(bob, rewrite, pending); err == nil {
		t.Error("primary_approver_ref mismatching the recorded primary must be rejected")
	}
}

// TestFoldDispatchLifecycle: the system-emitted events (C.4's emitters) fold the
// rest of the machine — EXECUTING on dispatch, SUCCEEDED/FAILED per outcome
// (PARTIAL→SUCCEEDED, TIMEOUT→FAILED), and REVERSED on the original.
func TestFoldDispatchLifecycle(t *testing.T) {
	id := uuid.New()
	mk := func(eventType string, payload any) Event {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return Event{Type: eventType, Payload: b}
	}

	cases := []struct {
		name    string
		events  []Event
		want    string
		checkID uuid.UUID
	}{
		{"dispatched → EXECUTING",
			[]Event{mk(EventTypeActionDispatched, ActionDispatched{ActionID: id, Adapter: "fx"})},
			ActionStatusExecuting, id},
		{"resulted SUCCEEDED",
			[]Event{mk(EventTypeActionResulted, ActionResulted{ActionID: id, FinalOutcome: "SUCCEEDED"})},
			ActionStatusSucceeded, id},
		{"resulted PARTIAL → SUCCEEDED",
			[]Event{mk(EventTypeActionResulted, ActionResulted{ActionID: id, FinalOutcome: "PARTIAL"})},
			ActionStatusSucceeded, id},
		{"resulted TIMEOUT → FAILED",
			[]Event{mk(EventTypeActionResulted, ActionResulted{ActionID: id, FinalOutcome: "TIMEOUT"})},
			ActionStatusFailed, id},
		{"reversed → REVERSED on the original",
			[]Event{mk(EventTypeActionReversed, ActionReversed{OriginalActionID: id, ReversingActionID: uuid.New()})},
			ActionStatusReversed, id},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions := map[uuid.UUID]actionState{id: {Status: ActionStatusApproved, Tier: TierT2}}
			for _, e := range tc.events {
				if err := foldActionEvent(actions, e); err != nil {
					t.Fatal(err)
				}
			}
			if actions[tc.checkID].Status != tc.want {
				t.Errorf("status = %q; want %q", actions[tc.checkID].Status, tc.want)
			}
		})
	}
}

// foldInto applies events onto a copy of the given action state map, returning
// the result (test helper for pure fold assertions).
func foldInto(base map[uuid.UUID]actionState, events []Event) map[uuid.UUID]actionState {
	out := make(map[uuid.UUID]actionState, len(base))
	for k, v := range base {
		out[k] = v
	}
	for _, e := range events {
		_ = foldActionEvent(out, e)
	}
	return out
}
