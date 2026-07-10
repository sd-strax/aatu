package temporal

import (
	"time"

	"go.temporal.io/sdk/workflow"
)

// ReversalSagaInput carries the reversing action's dispatch input plus the id of
// the original action being reversed (04 §7).
type ReversalSagaInput struct {
	OriginalActionID string               `json:"original_action_id"`
	Reversing        ActionLifecycleInput `json:"reversing"`
}

// ReversalSaga compensates a succeeded action by dispatching its inverse and, on
// success, marking the original REVERSED (04 §7, 05 §6.2 step 5). The reversing
// action is a full x-action with its own lifecycle: the saga runs its
// ActionLifecycle as a child workflow (so it inherits the dispatch-ledger guard
// and retry budget), then — only if the reversing action actually took effect —
// records ActionReversed on the original. A failed reversal leaves the original
// SUCCEEDED: we never claim to have undone something we didn't (the honest-state
// principle behind action-based reversal, 04 §7).
func ReversalSaga(ctx workflow.Context, in ReversalSagaInput) error {
	log := workflow.GetLogger(ctx)

	// 1. Dispatch the reversing action via its own ActionLifecycle child
	// workflow (deterministic id = its action id, matching the direct-start path).
	childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
		WorkflowID: "action-lifecycle-" + in.Reversing.ActionID,
	})
	var outcome string
	if err := workflow.ExecuteChildWorkflow(childCtx, ActionLifecycle, in.Reversing).Get(ctx, &outcome); err != nil {
		return err
	}

	// 2. Only a real effect reverses the original (SUCCEEDED or PARTIAL). A
	// FAILED/TIMEOUT reversing action leaves the original SUCCEEDED.
	if outcome != "SUCCEEDED" && outcome != "PARTIAL" {
		log.Warn("reversing action did not take effect; original stays SUCCEEDED",
			"original", in.OriginalActionID, "reversing", in.Reversing.ActionID, "outcome", outcome)
		return nil
	}

	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{StartToCloseTimeout: 30 * time.Second})
	var a *Activities
	return workflow.ExecuteActivity(ctx, a.EmitReversed, EmitReversedInput{
		OriginalActionID:  in.OriginalActionID,
		ReversingActionID: in.Reversing.ActionID,
		AggregateID:       in.Reversing.AggregateID,
		TenantID:          in.Reversing.TenantID,
		ApproverID:        in.Reversing.ApproverID,
	}).Get(ctx, nil)
}
