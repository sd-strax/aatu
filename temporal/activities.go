package temporal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	sdktemporal "go.temporal.io/sdk/temporal"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/aggregate"
)

// fatalErrorType is the non-retryable ApplicationError type a FATAL dispatch
// maps to, so the workflow's retry budget skips it (08 §5, §6).
const fatalErrorType = "FATAL_ERROR"

// Activities are the side-effecting steps the ActionLifecycle workflow calls.
// They hold the aggregate handler (to emit lifecycle events) and the action
// resolver (to dispatch). Activities run outside the workflow's determinism
// constraint, so they may touch the DB, the clock, and the network.
type Activities struct {
	handler  *aggregate.Handler
	resolver *action.ActionResolver
}

// NewActivities constructs the activity set.
func NewActivities(handler *aggregate.Handler, resolver *action.ActionResolver) *Activities {
	return &Activities{handler: handler, resolver: resolver}
}

// CheckDispatched is the dispatch-ledger guard (08 §6b): it reports whether the
// action already has a dispatch recorded (status EXECUTING or terminal). A
// re-triggered workflow sees this and short-circuits re-issue — reckon owns the
// guarantee from its own event log, independent of the vendor honoring the key.
func (a *Activities) CheckDispatched(ctx context.Context, actionID string) (bool, error) {
	id, err := uuid.Parse(actionID)
	if err != nil {
		return false, fmt.Errorf("CheckDispatched: bad action id: %w", err)
	}
	ac, err := aggregate.LoadActionCurrent(ctx, a.handler.DB(), id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // no projection yet → not dispatched
	}
	if err != nil {
		return false, err
	}
	switch ac.Status {
	case aggregate.ActionStatusExecuting, aggregate.ActionStatusSucceeded,
		aggregate.ActionStatusFailed, aggregate.ActionStatusReversed:
		return true, nil
	default:
		return false, nil
	}
}

// EmitDispatchedInput carries what EmitDispatched needs to record the ledger
// entry. ApproverID is the human principal the workflow carries (05 §6.2).
type EmitDispatchedInput struct {
	ActionID         string
	AggregateID      string
	TenantID         string
	ApproverID       string
	Adapter          string
	AdapterRequestID string
}

// EmitDispatched records ActionDispatched (the ledger entry, 08 §6b) BEFORE the
// outbound call, so a crash-and-retrigger sees it via CheckDispatched.
func (a *Activities) EmitDispatched(ctx context.Context, in EmitDispatchedInput) error {
	env, err := systemEnvelope(in.AggregateID, in.TenantID, in.ApproverID)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(in.ActionID)
	if err != nil {
		return err
	}
	_, err = a.handler.Handle(ctx, env, aggregate.DispatchAction{
		ActionID:         id,
		Adapter:          in.Adapter,
		AdapterRequestID: in.AdapterRequestID,
	})
	return err
}

// DispatchInput is the frozen action content the resolver dispatches.
type DispatchInput struct {
	ActionID   string
	ActionType string
	Targets    []aggregate.TargetSpec
	Parameters map[string]any
}

// DispatchOutput is the classified outcome the workflow records.
type DispatchOutput struct {
	FinalOutcome     string
	PerTargetResults map[string]string
	Adapter          string
	AdapterRequestID string
}

// DoDispatch runs the actual outbound write via the action resolver. A FATAL
// WriteError maps to a non-retryable ApplicationError (the retry budget skips
// it); a RETRYABLE one is returned as a plain error so Temporal retries within
// the budget; a completed dispatch (any final_outcome) returns normally.
func (a *Activities) DoDispatch(ctx context.Context, in DispatchInput) (DispatchOutput, error) {
	id, err := uuid.Parse(in.ActionID)
	if err != nil {
		return DispatchOutput{}, sdktemporal.NewApplicationError(err.Error(), fatalErrorType)
	}
	res, binding, err := a.resolver.Resolve(ctx, action.DispatchRequest{
		ActionID:   id,
		ActionType: in.ActionType,
		Targets:    in.Targets,
		Parameters: in.Parameters,
	})
	if err != nil {
		var we *action.WriteError
		if errors.As(err, &we) && we.Class == action.WriteFatal {
			return DispatchOutput{}, sdktemporal.NewApplicationError(err.Error(), fatalErrorType)
		}
		return DispatchOutput{}, err // RETRYABLE (or unclassified) → Temporal retries
	}
	perTarget := make(map[string]string, len(res.PerTargetResults))
	for k, v := range res.PerTargetResults {
		perTarget[k] = string(v)
	}
	return DispatchOutput{
		FinalOutcome:     string(res.FinalOutcome),
		PerTargetResults: perTarget,
		Adapter:          binding.Adapter,
		AdapterRequestID: res.AdapterRequestID,
	}, nil
}

// EmitResultedInput carries the terminal outcome to record.
type EmitResultedInput struct {
	ActionID         string
	AggregateID      string
	TenantID         string
	ApproverID       string
	FinalOutcome     string
	PerTargetResults map[string]string
	Attempts         int
}

// EmitResulted records ActionResulted, closing the action.
func (a *Activities) EmitResulted(ctx context.Context, in EmitResultedInput) error {
	env, err := systemEnvelope(in.AggregateID, in.TenantID, in.ApproverID)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(in.ActionID)
	if err != nil {
		return err
	}
	_, err = a.handler.Handle(ctx, env, aggregate.ResultAction{
		ActionID:         id,
		FinalOutcome:     in.FinalOutcome,
		PerTargetResults: in.PerTargetResults,
		Attempts:         in.Attempts,
	})
	return err
}

// systemEnvelope builds the SYSTEM-actor envelope the workflow uses to emit
// lifecycle events. The principal is the action's approver (a named human, per
// the actor invariant); Kind is SYSTEM. uuid/time here are fine — activities are
// not under the workflow determinism constraint.
func systemEnvelope(aggregateID, tenantID, approverID string) (aggregate.Envelope, error) {
	aggID, err := uuid.Parse(aggregateID)
	if err != nil {
		return aggregate.Envelope{}, fmt.Errorf("bad aggregate id: %w", err)
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return aggregate.Envelope{}, fmt.Errorf("bad tenant id: %w", err)
	}
	return aggregate.Envelope{
		AggregateID:   aggID,
		TenantID:      tid,
		CorrelationID: uuid.New(),
		Actor:         aggregate.Actor{PrincipalID: approverID, Kind: aggregate.ActorSystem},
		OccurredAt:    time.Now().UTC(),
	}, nil
}
