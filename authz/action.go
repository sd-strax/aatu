package authz

import "context"

// Gate 2 — action authorization. Stub.
//
// The real engine lands in Phase C (CEL evaluator + policy registry + trust
// tiers per design/04-action-authorization.md). Today's stub auto-approves
// every action so the wireup compiles and Gate 2 can be inserted into
// handler chains without changing call sites later.
//
// When the real engine arrives, the only change at call sites should be
// constructor + decision shape.

// Decision is the outcome of evaluating an action against the configured
// policy and the principal's trust tier.
type Decision int

const (
	// DecisionAutoApprove means the action proceeds without an approval gate.
	DecisionAutoApprove Decision = iota
	// DecisionRequireTwoParty means the action must be approved by a second
	// principal before it dispatches.
	DecisionRequireTwoParty
	// DecisionDeny means policy refuses the action.
	DecisionDeny
)

// ActionRequest describes a proposed action for Gate 2 evaluation. Fields
// are intentionally permissive; the real engine will refine as policy
// requirements become concrete in Phase C.
type ActionRequest struct {
	// ActionType is the dot-separated identifier — e.g., "host.isolate",
	// "ioc.publish", "account.disable".
	ActionType string

	// Targets is the count of distinct targets the action affects. Used by
	// the T2→T3 blast-radius escalator (>10 targets escalates trust tier;
	// see CLAUDE.md "Blast radius, not action verb, drives the trust tier").
	Targets int

	// Reversibility names the architecturally-declared reversibility of
	// this action: "REVERSIBLE", "BEST_EFFORT", "IRREVERSIBLE".
	Reversibility string
}

// Gate2 is the action-authorization evaluator.
//
// Today: a stub that always returns DecisionAutoApprove. The Phase C
// implementation will replace this with the CEL policy engine; consumers
// hold a Gate2 reference so the swap is transparent.
type Gate2 interface {
	Evaluate(ctx context.Context, claims Claims, req ActionRequest) (Decision, error)
}

// PermissiveGate2 is the stub Gate2 used through Phase B. Returns
// DecisionAutoApprove for every action.
type PermissiveGate2 struct{}

// Evaluate returns DecisionAutoApprove unconditionally.
func (PermissiveGate2) Evaluate(_ context.Context, _ Claims, _ ActionRequest) (Decision, error) {
	return DecisionAutoApprove, nil
}
