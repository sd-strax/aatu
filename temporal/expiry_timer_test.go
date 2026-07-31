package temporal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

// TestActionExpiryTimer_FiresAtDeadline: the timer sleeps to the frozen
// deadline (the test env fast-forwards) and then emits the expiry for the
// right action.
func TestActionExpiryTimer_FiresAtDeadline(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	var a *Activities

	env.OnActivity(a.EmitExpired, mock.Anything, mock.MatchedBy(func(in EmitExpiredInput) bool {
		return in.ActionID == "11111111-1111-4111-8111-111111111111"
	})).Return(nil)

	env.ExecuteWorkflow(ActionExpiryTimer, ActionExpiryTimerInput{
		ActionID:    "11111111-1111-4111-8111-111111111111",
		AggregateID: "22222222-2222-4222-8222-222222222222",
		TenantID:    "33333333-3333-4333-8333-333333333333",
		ExpiresAt:   env.Now().Add(30 * time.Minute),
	})

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow errored: %v", err)
	}
	env.AssertExpectations(t)
}

// TestActionExpiryTimer_ElapsedDeadlineFiresImmediately: a timer started for
// an already-elapsed window (the startup sweep over pre-timer actions) skips
// the sleep and emits at once — this is how lazily-expired stored statuses
// converge after an upgrade or an outage.
func TestActionExpiryTimer_ElapsedDeadlineFiresImmediately(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	var a *Activities

	env.OnActivity(a.EmitExpired, mock.Anything, mock.Anything).Return(nil)

	env.ExecuteWorkflow(ActionExpiryTimer, ActionExpiryTimerInput{
		ActionID:    "11111111-1111-4111-8111-111111111111",
		AggregateID: "22222222-2222-4222-8222-222222222222",
		TenantID:    "33333333-3333-4333-8333-333333333333",
		ExpiresAt:   env.Now().Add(-time.Hour),
	})

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow errored: %v", err)
	}
	env.AssertExpectations(t)
}
