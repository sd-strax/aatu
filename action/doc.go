// Package action is the write-side of the capability layer plus the action
// authorization machinery (design/08-write-side-actions.md, design/04-action-
// authorization.md).
//
// C.2 (the write surface, symmetric to capability's read surface) is built: the
// ActionDescriptor catalog + list_action_types, the ActionBinding model and the
// no-fall-through action resolver, the WriteAdapter contract (Dispatch +
// idempotency key → WriteResult), the fixture write adapter, and request_action
// construction with the blast-radius tier escalator. It reuses capability's
// templating engine (capability.RenderParams) and Adapter primitives.
//
// C.3 (Gate 2) is built: the CEL auto-approval policy engine (Gate2) evaluates
// versioned policies over a flattened context (EvalInput → ctx.*) and resolves
// an authorization Decision by priority (DENY > REQUIRE_TWO_PARTY > AUTO_APPROVE
// > manual), with the non-deletable baseline DENY (AI-no-T3) always prepended.
// It supersedes authz.PermissiveGate2. ApplyDecision threads the evaluation onto
// the RequestAction command so the PolicyEvaluated audit event (02 §3) is
// written in the same transaction as ActionRequested.
//
// The x-action lifecycle events themselves live in the aggregate (04 §3.1, C.1).
// C.4 wires Gate2 into the request_action HTTP endpoint (deriving Actor.Kind
// from the JWT delegate_kind claim) and fills the ActionLifecycle/ReversalSaga
// workflow bodies.
package action
