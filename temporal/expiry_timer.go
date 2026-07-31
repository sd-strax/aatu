package temporal

// The ExpireAction emitter (04 §3.2; 02 §3 "system-emitted on expires_at") —
// the deferred v0 timer, now real. One durable Temporal timer per pending
// action: sleep until the frozen approval deadline, then emit ExpireAction so
// the stored status becomes EXPIRED on schedule instead of lazily.
//
// Division of labor (the recorded design rule): the TIMER is scheduling, the
// DEADLINE is the invariant. Surfaces derive `expired` from the frozen
// expires_at and the approve path refuses past-deadline approvals regardless —
// so a late or lost timer never makes the system dishonest, only its stored
// status tardy. The timer's job is convergence, not enforcement.

import (
	"time"

	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ActionExpiryTimerInput identifies the pending action and its frozen
// deadline. ExpiresAt is passed in (not re-read) because it is immutable by
// construction — frozen at request time (04 §8.1).
type ActionExpiryTimerInput struct {
	ActionID    string    `json:"action_id"`
	AggregateID string    `json:"aggregate_id"`
	TenantID    string    `json:"tenant_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ActionExpiryTimer sleeps until the action's approval deadline, then records
// the expiry. The race with a human decision is resolved by the aggregate:
// ExpireAction is only legal on a still-pending action, and the EmitExpired
// activity treats that rejection as a benign no-op — an approval or rejection
// that beat the timer is the correct outcome, not an error.
func ActionExpiryTimer(ctx workflow.Context, in ActionExpiryTimerInput) error {
	if d := in.ExpiresAt.Sub(workflow.Now(ctx)); d > 0 {
		if err := workflow.Sleep(ctx, d); err != nil {
			return err // canceled
		}
	}
	// Bounded retries: a DB blip survives; a persistent failure surfaces in the
	// Temporal UI instead of spinning forever. Domain rejections never reach
	// the retry policy — EmitExpired maps them to success.
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy:         &sdktemporal.RetryPolicy{MaximumAttempts: 10},
	})
	var a *Activities // nil receiver — Temporal resolves activities by name
	return workflow.ExecuteActivity(ctx, a.EmitExpired, EmitExpiredInput{
		ActionID:    in.ActionID,
		AggregateID: in.AggregateID,
		TenantID:    in.TenantID,
	}).Get(ctx, nil)
}
