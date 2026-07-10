package temporal

import (
	"errors"
	"strconv"
	"time"

	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/sd-strax/reckon/aggregate"
)

// ActionLifecycleInput is the frozen action content the workflow dispatches
// (04 §8.1: resolution is frozen at request time). ApproverID is the human
// principal the workflow carries onto the system-emitted events (05 §6.2).
type ActionLifecycleInput struct {
	ActionID    string                 `json:"action_id"`
	AggregateID string                 `json:"aggregate_id"`
	TenantID    string                 `json:"tenant_id"`
	ApproverID  string                 `json:"approver_id"`
	ActionType  string                 `json:"action_type"`
	Targets     []aggregate.TargetSpec `json:"targets"`
	Parameters  map[string]any         `json:"parameters,omitempty"`
}

// ActionLifecycle is the durable dispatch of an APPROVED action (05 §6.2,
// 08 §7.1). This body owns the dispatch phase — the highest-correctness-stakes
// path in the system (R15): a workflow replay/crash/retrigger must never
// double-execute a real-world effect.
//
// Sequence:
//  1. Dispatch-ledger guard (08 §6b): if an ActionDispatched already exists,
//     short-circuit — never re-issue.
//  2. Record ActionDispatched BEFORE the outbound call (the ledger entry the
//     guard reads), with adapter_request_id = the workflow id (05 §6.2).
//  3. Dispatch through the action resolver under the retry budget (04 §6.1:
//     3 attempts, 2s/8s/30s; FATAL is non-retryable).
//  4. Record ActionResulted. On exhausted retries or FATAL, the honest residual
//     (08 §6c): FAILED with per-target UNKNOWN — never a success inference.
//
// v0 scope: the workflow is started for an already-APPROVED action. The
// approval-wait (signal-on-approve / expiry-timer, 05 §6.2 step 1) and the
// adapter name on the ledger entry (needs binding selection split from dispatch)
// are v1 refinements; the idempotency core is complete.
func ActionLifecycle(ctx workflow.Context, in ActionLifecycleInput) (string, error) {
	log := workflow.GetLogger(ctx)
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
	})
	var a *Activities // nil receiver — Temporal resolves activities by name

	// 1. Dispatch-ledger guard.
	var alreadyDispatched bool
	if err := workflow.ExecuteActivity(ctx, a.CheckDispatched, in.ActionID).Get(ctx, &alreadyDispatched); err != nil {
		return "", err
	}
	if alreadyDispatched {
		log.Info("action already dispatched; short-circuiting (idempotency guard)", "action_id", in.ActionID)
		return "", nil
	}

	requestID := workflow.GetInfo(ctx).WorkflowExecution.ID

	// 2. Record the ledger entry BEFORE the outbound call.
	if err := workflow.ExecuteActivity(ctx, a.EmitDispatched, EmitDispatchedInput{
		ActionID:         in.ActionID,
		AggregateID:      in.AggregateID,
		TenantID:         in.TenantID,
		ApproverID:       in.ApproverID,
		AdapterRequestID: requestID,
	}).Get(ctx, nil); err != nil {
		return "", err
	}

	// 3. Dispatch under the retry budget.
	dispatchCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:        2 * time.Second,
			BackoffCoefficient:     4, // 2s, 8s, 30s(capped)
			MaximumInterval:        30 * time.Second,
			MaximumAttempts:        3,
			NonRetryableErrorTypes: []string{fatalErrorType},
		},
	})
	var out DispatchOutput
	dispErr := workflow.ExecuteActivity(dispatchCtx, a.DoDispatch, DispatchInput{
		ActionID:   in.ActionID,
		ActionType: in.ActionType,
		Targets:    in.Targets,
		Parameters: in.Parameters,
	}).Get(dispatchCtx, &out)

	// 4. Record the outcome.
	result := EmitResultedInput{
		ActionID:    in.ActionID,
		AggregateID: in.AggregateID,
		TenantID:    in.TenantID,
		ApproverID:  in.ApproverID,
	}
	if dispErr != nil {
		// Exhausted retries or FATAL: the honest residual (08 §6c). No success
		// is ever inferred for an effect reckon cannot confirm. The audit's
		// attempt count is real (04 §6.1): a FATAL error is non-retryable, so
		// exactly one attempt ran; anything else exhausted the 3-attempt budget.
		log.Warn("dispatch failed; recording FAILED with UNKNOWN targets", "action_id", in.ActionID, "error", dispErr)
		result.FinalOutcome = "FAILED"
		result.PerTargetResults = unknownTargets(in.Targets)
		result.Attempts = 3
		var appErr *sdktemporal.ApplicationError
		if errors.As(dispErr, &appErr) && appErr.Type() == fatalErrorType {
			result.Attempts = 1
		}
	} else {
		result.FinalOutcome = out.FinalOutcome
		result.PerTargetResults = out.PerTargetResults
		// The real attempt number the dispatch succeeded on (from activity
		// info), never a fabricated 1.
		result.Attempts = out.Attempts
	}
	if err := workflow.ExecuteActivity(ctx, a.EmitResulted, result).Get(ctx, nil); err != nil {
		return "", err
	}
	return result.FinalOutcome, nil
}

// unknownTargets marks every target UNKNOWN — the residual outcome when a
// dispatch left reckon without a confirmable per-target result (08 §6c).
// (strconv is deterministic and fine in workflow code — the determinism
// constraint covers time/rand/goroutines/IO, not pure computation.)
func unknownTargets(targets []aggregate.TargetSpec) map[string]string {
	out := make(map[string]string, len(targets))
	for i := range targets {
		out[strconv.Itoa(i)] = "UNKNOWN"
	}
	return out
}
