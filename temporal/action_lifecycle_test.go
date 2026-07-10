package temporal

import (
	"testing"

	"github.com/stretchr/testify/mock"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	"github.com/sd-strax/reckon/aggregate"
)

func lifecycleInput() ActionLifecycleInput {
	return ActionLifecycleInput{
		ActionID:    "11111111-1111-4111-8111-111111111111",
		AggregateID: "22222222-2222-4222-8222-222222222222",
		TenantID:    "33333333-3333-4333-8333-333333333333",
		ApproverID:  "alice",
		ActionType:  "host.isolate",
		Targets:     []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
	}
}

// TestActionLifecycle_HappyPath: guard clear → dispatched → SUCCEEDED result.
func TestActionLifecycle_HappyPath(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	var a *Activities

	env.OnActivity(a.CheckDispatched, mock.Anything, mock.Anything).Return(false, nil)
	env.OnActivity(a.EmitDispatched, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity(a.DoDispatch, mock.Anything, mock.Anything).Return(
		DispatchOutput{FinalOutcome: "SUCCEEDED", PerTargetResults: map[string]string{"0": "OK"}}, nil)
	env.OnActivity(a.EmitResulted, mock.Anything, mock.MatchedBy(func(in EmitResultedInput) bool {
		return in.FinalOutcome == "SUCCEEDED"
	})).Return(nil)

	env.ExecuteWorkflow(ActionLifecycle, lifecycleInput())

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow errored: %v", err)
	}
	env.AssertExpectations(t)
}

// TestActionLifecycle_LedgerGuardShortCircuits is the R15 core: when an
// ActionDispatched already exists, the workflow must NOT dispatch again — no
// EmitDispatched, no DoDispatch.
func TestActionLifecycle_LedgerGuardShortCircuits(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	var a *Activities

	env.OnActivity(a.CheckDispatched, mock.Anything, mock.Anything).Return(true, nil)
	// EmitDispatched / DoDispatch / EmitResulted intentionally NOT mocked — if
	// the workflow calls them, the test fails with an unexpected-activity error.

	env.ExecuteWorkflow(ActionLifecycle, lifecycleInput())

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("short-circuit path errored: %v", err)
	}
	env.AssertNotCalled(t, "DoDispatch", mock.Anything, mock.Anything)
	env.AssertNotCalled(t, "EmitDispatched", mock.Anything, mock.Anything)
}

// TestActionLifecycle_FatalDispatch: a FATAL dispatch is not retried and closes
// the action FAILED with per-target UNKNOWN (08 §6c — no success inference).
func TestActionLifecycle_FatalDispatch(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	var a *Activities

	env.OnActivity(a.CheckDispatched, mock.Anything, mock.Anything).Return(false, nil)
	env.OnActivity(a.EmitDispatched, mock.Anything, mock.Anything).Return(nil)
	env.OnActivity(a.DoDispatch, mock.Anything, mock.Anything).Return(
		DispatchOutput{}, sdktemporal.NewApplicationError("no fixture matches", fatalErrorType))

	var gotFailed, gotUnknown bool
	env.OnActivity(a.EmitResulted, mock.Anything, mock.MatchedBy(func(in EmitResultedInput) bool {
		gotFailed = in.FinalOutcome == "FAILED"
		gotUnknown = in.PerTargetResults["0"] == "UNKNOWN"
		return true
	})).Return(nil)

	env.ExecuteWorkflow(ActionLifecycle, lifecycleInput())

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow not clean: completed=%v err=%v", env.IsWorkflowCompleted(), env.GetWorkflowError())
	}
	if !gotFailed || !gotUnknown {
		t.Errorf("FATAL dispatch → result failed=%v unknown=%v; want FAILED / UNKNOWN", gotFailed, gotUnknown)
	}
	// DoDispatch is FATAL → called exactly once (no retry).
	env.AssertNumberOfCalls(t, "DoDispatch", 1)
}

// TestActionLifecycle_RetryExhausted: a RETRYABLE dispatch is retried up to the
// budget, then closes FAILED/UNKNOWN.
func TestActionLifecycle_RetryExhausted(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	var a *Activities

	env.OnActivity(a.CheckDispatched, mock.Anything, mock.Anything).Return(false, nil)
	env.OnActivity(a.EmitDispatched, mock.Anything, mock.Anything).Return(nil)
	// Plain (retryable) error every attempt.
	env.OnActivity(a.DoDispatch, mock.Anything, mock.Anything).Return(
		DispatchOutput{}, sdktemporal.NewApplicationError("rate limited", "RETRYABLE_ERROR"))
	env.OnActivity(a.EmitResulted, mock.Anything, mock.MatchedBy(func(in EmitResultedInput) bool {
		return in.FinalOutcome == "FAILED"
	})).Return(nil)

	env.ExecuteWorkflow(ActionLifecycle, lifecycleInput())

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow not clean: err=%v", env.GetWorkflowError())
	}
	// Retried up to the budget (3 attempts).
	env.AssertNumberOfCalls(t, "DoDispatch", 3)
}
