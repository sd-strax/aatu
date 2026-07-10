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
// C.3 (Gate 2: trust tiers, the CEL auto-approval policy engine, approval-mode
// resolution) still lands here, replacing authz's PermissiveGate2 stub. The
// x-action lifecycle events themselves live in the aggregate (04 §3.1, C.1),
// not here.
package action
