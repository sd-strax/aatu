package temporal

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

// TestReversalSaga_SucceededReverses: when the reversing action's
// ActionLifecycle succeeds, the saga marks the original REVERSED.
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
	})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("saga not clean: err=%v", env.GetWorkflowError())
	}
	if reversedOriginal != "orig-42" {
		t.Errorf("reversed original = %q; want orig-42", reversedOriginal)
	}
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
