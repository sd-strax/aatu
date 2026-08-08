package action

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/capability"
)

// Reserved params keys the resolver injects so the (fixture) adapter can match
// and downstream ops can see the action context.
const (
	ParamActionType         = "action_type"
	ParamResolvedIdentifier = "resolved_identifier" // targets[0] convenience for single-target matching
)

// ActionBinding maps an action_type to a concrete write-adapter operation
// (08 §4). Symmetric to the read binding, with one write-specific field.
type ActionBinding struct {
	ActionType                        string         `yaml:"action_type" json:"action_type"`
	Adapter                           string         `yaml:"adapter" json:"adapter"`
	Operation                         string         `yaml:"operation" json:"operation"`
	Priority                          int            `yaml:"priority" json:"priority"`
	Params                            map[string]any `yaml:"params" json:"params"`
	ExternalApprovalSubstitutesReckon bool           `yaml:"external_approval_substitutes_reckon" json:"external_approval_substitutes_reckon"`
	// Scope is the source scope inherited from the adapter instance (03 §3.5),
	// set from the ActionAdapterSpec at build time — never read from binding YAML
	// (scope lives on the instance). A scope mismatch makes the binding
	// inapplicable, and because the write side never falls through, an action
	// whose every binding is scope-filtered reports no binding: unavailable for
	// that investigation, nothing dispatched (08 §4).
	Scope string `yaml:"-" json:"scope"`
}

// DispatchRequest is what the resolver dispatches: the frozen x-action content.
// Resolution of the targets happened at request time (04 §8.1); the adapter
// consumes resolved_identifier and never re-resolves.
type DispatchRequest struct {
	ActionID   uuid.UUID
	ActionType string
	Targets    []aggregate.TargetSpec
	Parameters map[string]any
	// SourceScope is the investigation's source scope (03 §3.5), carried from the
	// Seed so the resolver dispatches only to the matching organization's
	// instance. Empty for single-organization investigations.
	SourceScope string
}

// ActionResolver selects the write binding for an action and dispatches it
// (08 §4). Unlike the read resolver it does NOT fall through to a lower-priority
// binding on a failed call — a partially-executed state change must never be
// silently re-attempted against a different tool. Binding selection is resolved
// once; retries (08 §6) reuse the same binding.
type ActionResolver struct {
	bindings map[string][]ActionBinding
	adapters map[string]WriteAdapter
}

// NewActionResolver builds a resolver over a tenant's action bindings and its
// enabled write-adapter instances.
func NewActionResolver(bindings map[string][]ActionBinding, adapters map[string]WriteAdapter) *ActionResolver {
	return &ActionResolver{bindings: bindings, adapters: adapters}
}

// ValidateActionBindings compiles every binding template up front (08 §4,
// mirrors 03 §3.3.4).
func ValidateActionBindings(bindings map[string][]ActionBinding) error {
	for at, bs := range bindings {
		for _, b := range bs {
			if err := capability.ValidateParamTemplates(b.Params); err != nil {
				return fmt.Errorf("action_type %s, adapter %s: %w", at, b.Adapter, err)
			}
		}
	}
	return nil
}

// ErrNoBinding is returned when no applicable, enabled binding exists for an
// action type — dispatch cannot proceed.
var ErrNoBinding = errors.New("no applicable write binding")

// selection is one chosen binding with its configured adapter and rendered
// params — the SINGLE selection implementation behind both Resolve (dispatch)
// and PlannedBinding (the pre-approval preview), so what a surface promises is
// structurally what dispatch picks.
type selection struct {
	binding ActionBinding
	adapter WriteAdapter
	params  map[string]any
}

// selectBinding walks the action type's bindings by priority and returns the
// first applicable one (scope match, adapter configured, required params
// render). ok=false when nothing applies. A template-render error is returned
// with the offending binding — Resolve fails hard on it; a preview treats it
// as not-applicable.
func (r *ActionResolver) selectBinding(req DispatchRequest) (selection, bool, error) {
	tctx := dispatchContext(req)
	for _, b := range sortedActionBindings(r.bindings[req.ActionType]) {
		if !capability.ScopeApplicable(b.Scope, req.SourceScope) {
			continue // §3.5: wrong organization's instance — not applicable, no dispatch
		}
		adapter, ok := r.adapters[b.Adapter]
		if !ok {
			continue // adapter not configured/enabled — try a lower-priority binding
		}
		params, applicable, err := capability.RenderParams(b.Params, tctx)
		if err != nil {
			return selection{binding: b}, false, fmt.Errorf("action_type %s, adapter %s: template render: %w", req.ActionType, b.Adapter, err)
		}
		if !applicable {
			continue // required input missing — not this binding
		}
		return selection{binding: b, adapter: adapter, params: params}, true, nil
	}
	return selection{}, false, nil
}

// Resolve picks the highest-priority applicable binding for the request,
// renders its params against the frozen targets/parameters, injects the action
// context + idempotency key, and dispatches exactly once. It returns the binding
// used (so the caller records the adapter/idempotency context) alongside the
// result.
func (r *ActionResolver) Resolve(ctx context.Context, req DispatchRequest) (WriteResult, ActionBinding, error) {
	sel, ok, err := r.selectBinding(req)
	if err != nil {
		return WriteResult{}, sel.binding, err
	}
	if !ok {
		return WriteResult{}, ActionBinding{}, fmt.Errorf("%w for action_type %q", ErrNoBinding, req.ActionType)
	}

	// Binding chosen. From here there is NO fall-through: this is the single
	// outbound path for the action.
	sel.params[ParamActionType] = req.ActionType
	if len(req.Targets) > 0 {
		sel.params[ParamResolvedIdentifier] = req.Targets[0].ResolvedIdentifier
	}
	key := IdempotencyKey(req.ActionID, "")

	result, err := sel.adapter.Dispatch(ctx, sel.binding.Operation, sel.params, key)
	if err != nil {
		return WriteResult{}, sel.binding, err // classified WriteError; caller applies the retry budget
	}
	return result, sel.binding, nil
}

// PlannedBinding returns the binding Resolve WOULD select for req, without
// dispatching — the "which tool will act" preview an approval surface shows
// BEFORE a human approves (08 §4). It IS Resolve's selection (selectBinding),
// so what the card promises is structurally what dispatch will pick. ok is
// false when nothing applies (no binding, wrong scope, adapter disabled,
// required inputs missing, or a binding whose template fails to render).
func (r *ActionResolver) PlannedBinding(req DispatchRequest) (ActionBinding, bool) {
	sel, ok, err := r.selectBinding(req)
	if err != nil || !ok {
		return ActionBinding{}, false
	}
	return sel.binding, true
}

// dispatchContext assembles the template roots for action bindings: the target
// (targets[0]), the full target list, the request parameters, and the action
// type.
func dispatchContext(req DispatchRequest) map[string]any {
	targets := make([]any, 0, len(req.Targets))
	for _, t := range req.Targets {
		targets = append(targets, map[string]any{
			"entity_ref":          t.EntityRef,
			"resolved_identifier": t.ResolvedIdentifier,
			"asset_criticality":   t.AssetCriticality,
		})
	}
	ctx := map[string]any{
		"targets":    targets,
		"parameters": req.Parameters,
		"action":     req.ActionType,
	}
	if len(targets) > 0 {
		ctx["target"] = targets[0]
	}
	return ctx
}

func sortedActionBindings(bindings []ActionBinding) []ActionBinding {
	out := append([]ActionBinding(nil), bindings...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority > out[j].Priority })
	return out
}
