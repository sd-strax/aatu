package temporal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/comms"
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
	comms    *comms.Store
}

// NewActivities constructs the activity set.
func NewActivities(handler *aggregate.Handler, resolver *action.ActionResolver) *Activities {
	return &Activities{handler: handler, resolver: resolver}
}

// WithComms attaches the comms-thread store (Phase F): a SUCCEEDED notify.*
// result opens (or, via thread_ref, extends) its comms thread. Nil-safe —
// without it, results record exactly as before.
func (a *Activities) WithComms(store *comms.Store) *Activities {
	a.comms = store
	return a
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

// DispatchOutput is the classified outcome the workflow records. Attempts is
// the REAL attempt number this dispatch succeeded on (from activity info), so
// the Execution audit record (04 §6.1) never carries a fabricated count.
type DispatchOutput struct {
	FinalOutcome     string
	PerTargetResults map[string]string
	Adapter          string
	AdapterRequestID string
	Attempts         int
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
		Attempts:         activityAttempt(ctx),
	}, nil
}

// activityAttempt reads the current attempt number from activity info,
// defaulting to 1 outside an activity context (unit tests), where
// activity.GetInfo panics.
func activityAttempt(ctx context.Context) (n int) {
	n = 1
	defer func() { _ = recover() }()
	if a := int(activity.GetInfo(ctx).Attempt); a > 0 {
		n = a
	}
	return n
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
	if err != nil {
		return err
	}
	// Phase F: a SUCCEEDED notify.* dispatch opens/extends its comms thread.
	// Best-effort by design: the result event is committed; failing (and
	// retrying) this activity for thread bookkeeping would attempt a second
	// result on the aggregate and be refused. A miss logs and the analyst
	// still has the action record.
	a.recordCommsThread(ctx, id, in)
	return nil
}

// recordCommsThread translates one successful notify.* result into comms
// thread state (binding §4: the outbound message is the action; the thread is
// the conversation that follows).
func (a *Activities) recordCommsThread(ctx context.Context, actionID uuid.UUID, in EmitResultedInput) {
	if a.comms == nil || in.FinalOutcome != aggregate.ActionStatusSucceeded {
		return
	}
	ac, err := aggregate.LoadActionCurrent(ctx, a.handler.DB(), actionID)
	if err != nil || !strings.HasPrefix(ac.ActionType, "notify.") {
		return
	}
	var params struct {
		Message       string  `json:"message"`
		Subject       string  `json:"subject"`
		Body          string  `json:"body"`
		FollowUpHours float64 `json:"follow_up_hours"`
		ThreadRef     string  `json:"thread_ref"`
	}
	_ = json.Unmarshal(ac.Parameters, &params)
	body := params.Message
	if body == "" {
		body = params.Body
	}
	subject := params.Subject
	if subject == "" {
		subject = clip(body, 80)
	}
	target := ""
	if len(ac.Targets) > 0 {
		target = ac.Targets[0].ResolvedIdentifier
		if target == "" {
			target = ac.Targets[0].EntityRef
		}
	}
	threadRef := uuid.Nil
	if params.ThreadRef != "" {
		threadRef, _ = uuid.Parse(params.ThreadRef)
	}
	tenantID, _ := uuid.Parse(in.TenantID)
	aggID, _ := uuid.Parse(in.AggregateID)
	if err := a.comms.Outbound(ctx, comms.OutboundMessage{
		AggregateID:   aggID,
		TenantID:      tenantID,
		ActionID:      actionID,
		ActionType:    ac.ActionType,
		Target:        target,
		Subject:       subject,
		Body:          body,
		Author:        in.ApproverID,
		FollowUpHours: int(params.FollowUpHours),
		At:            time.Now().UTC(),
		ThreadRef:     threadRef,
	}); err != nil {
		activity.GetLogger(ctx).Warn("comms thread not recorded", "action_id", actionID, "error", err)
	}
}

// clip shortens a string for use as a derived subject line.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// EmitReversedInput carries what EmitReversed needs to mark the original
// action REVERSED.
type EmitReversedInput struct {
	OriginalActionID  string
	ReversingActionID string
	AggregateID       string
	TenantID          string
	ApproverID        string
}

// EmitReversed records ActionReversed on the original action once its reversing
// action succeeded (04 §7). System-emitted by the ReversalSaga.
func (a *Activities) EmitReversed(ctx context.Context, in EmitReversedInput) error {
	env, err := systemEnvelope(in.AggregateID, in.TenantID, in.ApproverID)
	if err != nil {
		return err
	}
	origID, err := uuid.Parse(in.OriginalActionID)
	if err != nil {
		return err
	}
	revID, err := uuid.Parse(in.ReversingActionID)
	if err != nil {
		return err
	}
	_, err = a.handler.Handle(ctx, env, aggregate.ReverseAction{
		OriginalActionID:  origID,
		ReversingActionID: revID,
	})
	return err
}

// EmitReversalAttempted records ActionReversalAttempted on the original action:
// the reversing dispatch fully succeeded but the original is BEST_EFFORT, so
// the effect cannot be verified — the original stays SUCCEEDED and only the
// back-reference is recorded (04 §7.1 Position C). System-emitted by the
// ReversalSaga. Shares EmitReversedInput: same identifiers, different claim.
func (a *Activities) EmitReversalAttempted(ctx context.Context, in EmitReversedInput) error {
	env, err := systemEnvelope(in.AggregateID, in.TenantID, in.ApproverID)
	if err != nil {
		return err
	}
	origID, err := uuid.Parse(in.OriginalActionID)
	if err != nil {
		return err
	}
	revID, err := uuid.Parse(in.ReversingActionID)
	if err != nil {
		return err
	}
	_, err = a.handler.Handle(ctx, env, aggregate.RecordReversalAttempt{
		OriginalActionID:  origID,
		ReversingActionID: revID,
	})
	return err
}

// EmitExpiredInput identifies the action the expiry timer is closing out.
type EmitExpiredInput struct {
	ActionID    string
	AggregateID string
	TenantID    string
}

// EmitExpired records ActionExpired (the timer firing at the frozen deadline,
// 02 §3). The race with a human decision resolves in the human's favor: the
// aggregate rejects ExpireAction on anything no longer pending, and that
// rejection is a benign no-op here — never an error to retry. Only
// infrastructure failures (DB unreachable) propagate for retry.
func (a *Activities) EmitExpired(ctx context.Context, in EmitExpiredInput) error {
	env, err := systemEnvelope(in.AggregateID, in.TenantID, "system")
	if err != nil {
		return err
	}
	id, err := uuid.Parse(in.ActionID)
	if err != nil {
		return err
	}
	_, err = a.handler.Handle(ctx, env, aggregate.ExpireAction{ActionID: id})
	var rejected *aggregate.RejectedError
	if errors.As(err, &rejected) {
		// Approved, rejected, or already expired before the timer fired — the
		// deadline race resolved; nothing to record.
		return nil
	}
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
