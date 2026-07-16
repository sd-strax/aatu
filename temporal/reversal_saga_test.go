package temporal

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

// TestReversalSaga_SucceededReverses: when the reversing action's
// ActionLifecycle succeeds AND the original is reliably reversible, the saga
// marks the original REVERSED.
func TestReversalSaga_SucceededReverses(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	var a *Activities

	env.OnWorkflow(ActionLifecycle, mock.Anything, mock.Anything).Return("SUCCEEDED", nil)

	var reversedOriginal string
	env.OnActivity(a.EmitReversed, mock.Anything, mock.MatchedBy(func(in EmitReversedInput) bool {
		reversedOriginal = in.OriginalActionID
		return true
	})).Return(nil)

	env.ExecuteWorkflow(ReversalSaga, ReversalSagaInput{
		OriginalActionID: "orig-42",
		Reversing:        lifecycleInput(),
		OriginalReliable: true,
	})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("saga not clean: err=%v", env.GetWorkflowError())
	}
	if reversedOriginal != "orig-42" {
		t.Errorf("reversed original = %q; want orig-42", reversedOriginal)
	}
}

// TestReversalSaga_BestEffortRecordsAttempt: even when the reversing action
// fully succeeds, a best-effort original (OriginalReliable=false, e.g. ioc.block)
// is NOT marked REVERSED — the effect can't be verified undone. Instead the saga
// records action.reversal_attempted on the original (04 §7.1 Position C), so the
// attempt is queryable from the original's side while it honestly stays
// SUCCEEDED.
func TestReversalSaga_BestEffortRecordsAttempt(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	var a *Activities

	env.OnWorkflow(ActionLifecycle, mock.Anything, mock.Anything).Return("SUCCEEDED", nil)
	// EmitReversed intentionally NOT mocked — calling it fails the test.

	var attemptedOriginal string
	env.OnActivity(a.EmitReversalAttempted, mock.Anything, mock.MatchedBy(func(in EmitReversedInput) bool {
		attemptedOriginal = in.OriginalActionID
		return true
	})).Return(nil)

	env.ExecuteWorkflow(ReversalSaga, ReversalSagaInput{
		OriginalActionID: "orig-42",
		Reversing:        lifecycleInput(),
		OriginalReliable: false,
	})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("saga not clean: err=%v", env.GetWorkflowError())
	}
	env.AssertNotCalled(t, "EmitReversed", mock.Anything, mock.Anything)
	if attemptedOriginal != "orig-42" {
		t.Errorf("reversal attempt recorded on %q; want orig-42", attemptedOriginal)
	}
}

// TestReversalSaga_PartialDoesNotReverse: PARTIAL means some targets were NOT
// undone — marking the original REVERSED would overclaim (honest-state, 04 §7).
func TestReversalSaga_PartialDoesNotReverse(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()

	env.OnWorkflow(ActionLifecycle, mock.Anything, mock.Anything).Return("PARTIAL", nil)
	// EmitReversed intentionally NOT mocked — calling it fails the test.

	env.ExecuteWorkflow(ReversalSaga, ReversalSagaInput{
		OriginalActionID: "orig-42",
		Reversing:        lifecycleInput(),
	})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("saga not clean: err=%v", env.GetWorkflowError())
	}
	env.AssertNotCalled(t, "EmitReversed", mock.Anything, mock.Anything)
}

// TestReversalSaga_FailedDoesNotReverse: a FAILED reversing action leaves the
// original SUCCEEDED — EmitReversed is never called (we never claim to have
// undone something we didn't, 04 §7).
func TestReversalSaga_FailedDoesNotReverse(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()

	env.OnWorkflow(ActionLifecycle, mock.Anything, mock.Anything).Return("FAILED", nil)
	// EmitReversed intentionally NOT mocked — calling it fails the test.

	env.ExecuteWorkflow(ReversalSaga, ReversalSagaInput{
		OriginalActionID: "orig-42",
		Reversing:        lifecycleInput(),
	})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("saga not clean: err=%v", env.GetWorkflowError())
	}
	env.AssertNotCalled(t, "EmitReversed", mock.Anything, mock.Anything)
}
