package temporal

import (
	"time"

	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ReversalSagaInput carries the reversing action's dispatch input plus the id of
// the original action being reversed (04 §7).
type ReversalSagaInput struct {
	OriginalActionID string               `json:"original_action_id"`
	Reversing        ActionLifecycleInput `json:"reversing"`

	// OriginalReliable gates the REVERSED status claim on the original (04 §7,
	// Position C). True only when the original's effective reversibility is
	// REVERSIBLE — i.e. the tool is trusted to undo the effect cleanly. When the
	// original is BEST_EFFORT (e.g. ioc.block against a propagating denylist), a
	// successful reversing dispatch is NOT enough to claim REVERSED: the original
	// honestly stays SUCCEEDED and the reversing action's own forward
	// reversal_of_ref remains the queryable link. The caller resolves this from
	// the original action's descriptor (+ any per-binding override).
	OriginalReliable bool `json:"original_reliable,omitempty"`
}

// ReversalSaga compensates a succeeded action by dispatching its inverse and,
// when the original is reliably reversible, marking it REVERSED (04 §7 Position
// C, 05 §6.2 step 5). The reversing action is a full x-action with its own
// lifecycle: the saga runs its ActionLifecycle as a child workflow (so it
// inherits the dispatch-ledger guard and retry budget), then — only if the
// reversing action actually took effect AND the original is reliably reversible —
// records ActionReversed on the original. A failed reversal, or a best-effort
// original, leaves the original SUCCEEDED: we never claim to have undone
// something we can't verify we undid (the honest-state principle behind
// action-based reversal, 04 §7).
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

	// 2. Only a FULL effect reverses the original. PARTIAL means some targets
	// were NOT undone — marking the original REVERSED would overclaim the undo
	// (the honest-state principle, 04 §7). A PARTIAL/FAILED/TIMEOUT reversing
	// action leaves the original SUCCEEDED; the reversing action's own record
	// carries the per-target detail for the analyst to act on.
	if outcome != "SUCCEEDED" {
		log.Warn("reversing action did not fully take effect; original stays SUCCEEDED",
			"original", in.OriginalActionID, "reversing", in.Reversing.ActionID, "outcome", outcome)
		return nil
	}

	// 3. The reversing dispatch fully took effect — but that alone reverses the
	// original only when the original is RELIABLY reversible (04 §7 Position C).
	// For a BEST_EFFORT original, entry removal is not proof the effect is gone
	// (TTL lists, propagated RPZ, partner feeds), so we do NOT claim REVERSED: the
	// original stays SUCCEEDED, and the reversing action's own forward
	// reversal_of_ref is the honest, queryable record of the attempt. The analyst
	// judges residual effect per their tooling.
	if !in.OriginalReliable {
		log.Info("reversing action succeeded but original is best-effort reversible; original stays SUCCEEDED",
			"original", in.OriginalActionID, "reversing", in.Reversing.ActionID)
		return nil
	}

	// Bounded retries: a permanent domain rejection (e.g. the original vanished)
	// must fail the saga visibly, not spin forever.
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &sdktemporal.RetryPolicy{MaximumAttempts: 10},
	})
	var a *Activities
	return workflow.ExecuteActivity(ctx, a.EmitReversed, EmitReversedInput{
		OriginalActionID:  in.OriginalActionID,
		ReversingActionID: in.Reversing.ActionID,
		AggregateID:       in.Reversing.AggregateID,
		TenantID:          in.Reversing.TenantID,
		ApproverID:        in.Reversing.ApproverID,
	}).Get(ctx, nil)
}
