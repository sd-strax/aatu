package action

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/sd-strax/reckon/aggregate"
)

// Gate2 is the action-authorization engine (04 §4): it evaluates CEL policies
// over a flattened context and resolves an authorization Decision. It replaces
// the authz.PermissiveGate2 stub. The non-deletable baseline DENY (AI-no-T3) is
// always prepended, so an AI-delegated T3 can never auto-approve regardless of
// tenant policies.
type Gate2 struct {
	env      *cel.Env
	policies []compiledPolicy
}

type compiledPolicy struct {
	Policy
	program cel.Program
}

// NewGate2 compiles the given tenant policies (prepending the baseline DENY) and
// returns the engine. A predicate that fails to compile is a config error.
func NewGate2(policies []Policy) (*Gate2, error) {
	env, err := buildCELEnv()
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}
	all := append([]Policy{BaselineDenyPolicy()}, policies...)

	compiled := make([]compiledPolicy, 0, len(all))
	for _, p := range all {
		ast, iss := env.Compile(p.Predicate)
		if iss != nil && iss.Err() != nil {
			return nil, fmt.Errorf("policy %s: predicate compile: %w", p.ID, iss.Err())
		}
		if ast.OutputType() != cel.BoolType {
			return nil, fmt.Errorf("policy %s: predicate must return bool, got %s", p.ID, ast.OutputType())
		}
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("policy %s: program: %w", p.ID, err)
		}
		compiled = append(compiled, compiledPolicy{Policy: p, program: prg})
	}
	return &Gate2{env: env, policies: compiled}, nil
}

// Evaluate runs every matching, active policy over the input context and
// resolves the Decision by priority: any firing (non-shadow) DENY wins, else
// REQUIRE_TWO_PARTY, else AUTO_APPROVE, else fall through to manual. Shadow
// policies are evaluated and recorded (04 §4.4) but never drive the decision.
func (g *Gate2) Evaluate(input EvalInput) (Decision, error) {
	activation := map[string]any{"ctx": input.toContext()}

	var (
		evals           []PolicyEvaluation
		denyRef         string
		twoPartyRef     string
		twoPartyPool    []string
		autoRef         string
		autoAccountable string
	)
	for _, cp := range g.policies {
		if !cp.matchesType(input.ActionType) || !cp.active(input.Now) {
			continue
		}
		out, _, err := cp.program.Eval(activation)
		if err != nil {
			// FAIL-CLOSED by design: a predicate erroring at eval time (e.g. a
			// missing context field) fails the whole evaluation rather than
			// being skipped — silently skipping an erroring DENY would be
			// fail-open. The action request errors; the policy gets fixed.
			return Decision{}, fmt.Errorf("policy %s eval: %w", cp.ID, err)
		}
		fired, ok := out.Value().(bool)
		if !ok {
			return Decision{}, fmt.Errorf("policy %s: predicate did not return bool", cp.ID)
		}

		evals = append(evals, PolicyEvaluation{
			PolicyRef: cp.ID, PolicyVersion: cp.ContentHash(),
			WouldHaveFired: fired, Effect: cp.Effect, Shadow: cp.Shadow,
		})
		if !fired || cp.Shadow {
			continue // shadow (or non-firing) policies never drive authorization
		}
		switch cp.Effect {
		case EffectDeny:
			if denyRef == "" {
				denyRef = cp.ID
			}
		case EffectRequireTwoParty:
			if twoPartyRef == "" {
				twoPartyRef = cp.ID
				twoPartyPool = cp.SecondaryApproverPool
			}
		case EffectAutoApprove:
			if autoRef == "" {
				autoRef = cp.ID
				autoAccountable = accountableHuman(cp.Policy)
			}
		}
	}

	switch {
	case denyRef != "":
		// DENY drives the action to the manual flow (a human must approve); it
		// never auto-approves. (04 §4.3 Example 2.)
		return Decision{Effect: EffectDeny, Mode: ModeManual, MatchedPolicyRef: denyRef, Evaluations: evals}, nil
	case twoPartyRef != "":
		return Decision{Effect: EffectRequireTwoParty, Mode: ModeTwoParty, MatchedPolicyRef: twoPartyRef, SecondaryApproverPool: twoPartyPool, Evaluations: evals}, nil
	case autoRef != "":
		return Decision{Effect: EffectAutoApprove, Mode: ModeAutoPolicy, MatchedPolicyRef: autoRef, PolicyAccountable: autoAccountable, Evaluations: evals}, nil
	default:
		return Decision{Effect: "", Mode: ModeManual, Evaluations: evals}, nil
	}
}

// accountableHuman returns the analyst an AUTO_POLICY approval is attributed to:
// the last signed-off-by, else the authored-by (04 §3.3).
func accountableHuman(p Policy) string {
	if n := len(p.SignedOffBy); n > 0 {
		return p.SignedOffBy[n-1]
	}
	return p.AuthoredBy
}

// ApplyDecision attaches a Decision's audit trail to a RequestAction command,
// converting the evaluations to aggregate records so the PolicyEvaluated event
// is written in the same transaction as ActionRequested (02 §3). The endpoint
// then issues the (possibly auto-approving) follow-up per decision.Mode.
func ApplyDecision(cmd aggregate.RequestAction, d Decision) aggregate.RequestAction {
	records := make([]aggregate.PolicyEvaluationRecord, 0, len(d.Evaluations))
	for _, e := range d.Evaluations {
		records = append(records, aggregate.PolicyEvaluationRecord{
			PolicyRef:      e.PolicyRef,
			PolicyVersion:  e.PolicyVersion,
			WouldHaveFired: e.WouldHaveFired,
			Effect:         string(e.Effect),
			Shadow:         e.Shadow,
		})
	}
	cmd.PolicyEvaluations = records
	cmd.MatchedPolicyRef = d.MatchedPolicyRef
	return cmd
}

// EvalInputForCommand builds the action.* portion of the evaluation context from
// a built RequestAction command plus the requesting actor — including decoding
// the command's Parameters so ctx.action.parameters is populated (a policy
// conditioning on it must never silently see an empty object). The endpoint
// enriches the result with the investigation/evidence/similarity/SOP projections
// it assembles from the graph before calling Evaluate.
func EvalInputForCommand(cmd aggregate.RequestAction, actorKind, actorID string, now time.Time) EvalInput {
	var params map[string]any
	if len(cmd.Parameters) > 0 {
		// Best-effort: request_action parameters are JSON objects by contract
		// (08 §2); a non-object leaves ctx.action.parameters empty.
		_ = json.Unmarshal(cmd.Parameters, &params)
	}
	return EvalInput{
		ActionType:      cmd.ActionType,
		Tier:            cmd.Tier,
		Targets:         cmd.Targets,
		Parameters:      params,
		RequestedByKind: actorKind,
		RequestedByID:   actorID,
		Now:             now,
	}
}

// EvalInput is the flattened data the caller supplies to build the CEL context
// (04 §4.2). Fields are projections of the domain graph, not raw STIX — policy
// authors never navigate edges by hand.
type EvalInput struct {
	ActionType      string
	Tier            string // final tier after the §1 escalator
	Targets         []aggregate.TargetSpec
	Parameters      map[string]any
	RequestedByKind string // HUMAN | AI_DELEGATED
	RequestedByID   string
	DelegateAgentID string
	DelegateModel   string

	InvestigationID      string
	InvestigationContext string
	Lifecycle            string
	SeedKind             string

	Hypotheses          []map[string]any // hypothesis views
	AllDirect           bool
	HasStrongSupport    bool
	MaxSupportingWeight string

	CriticalityClasses []string

	SOPApplicable     bool
	SOPRecommendation string

	SimilarityHasMatch        bool
	SimilarityTopMatchOutcome string

	Now           time.Time
	BusinessHours bool
}

// toContext builds the nested ctx map the predicates evaluate against (04 §4.2).
func (in EvalInput) toContext() map[string]any {
	weight := in.MaxSupportingWeight
	if weight == "" {
		weight = "NONE"
	}
	return map[string]any{
		"action": map[string]any{
			"type":         in.ActionType,
			"tier":         in.Tier,
			"target_count": len(in.Targets),
			"parameters":   orEmptyMap(in.Parameters),
			"requested_by": map[string]any{"kind": in.RequestedByKind, "id": in.RequestedByID},
			"delegate":     map[string]any{"agent_id": in.DelegateAgentID, "model": in.DelegateModel},
			"targets":      targetMaps(in.Targets),
		},
		"investigation": map[string]any{
			"id":        in.InvestigationID,
			"context":   in.InvestigationContext,
			"lifecycle": in.Lifecycle,
			"seed_kind": in.SeedKind,
		},
		"evidence": map[string]any{
			"hypotheses":            orEmptyList(in.Hypotheses),
			"all_direct":            in.AllDirect,
			"has_strong_support":    in.HasStrongSupport,
			"max_supporting_weight": weight,
		},
		"targets": map[string]any{
			"criticality_classes": orEmptyStrings(in.CriticalityClasses),
		},
		"sop_guidance": map[string]any{
			"applicable":     in.SOPApplicable,
			"recommendation": in.SOPRecommendation,
		},
		"similarity": map[string]any{
			"has_match":         in.SimilarityHasMatch,
			"top_match_outcome": in.SimilarityTopMatchOutcome,
		},
		"time": map[string]any{
			"utc":            in.Now.UTC().Format(time.RFC3339),
			"business_hours": in.BusinessHours,
		},
	}
}

func targetMaps(targets []aggregate.TargetSpec) []any {
	out := make([]any, 0, len(targets))
	for _, t := range targets {
		out = append(out, map[string]any{
			"entity_ref":          t.EntityRef,
			"resolved_identifier": t.ResolvedIdentifier,
			"asset_criticality":   t.AssetCriticality,
		})
	}
	return out
}

func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
func orEmptyList(l []map[string]any) []any {
	out := make([]any, 0, len(l))
	for _, m := range l {
		out = append(out, m)
	}
	return out
}
func orEmptyStrings(s []string) []any {
	out := make([]any, 0, len(s))
	for _, v := range s {
		out = append(out, v)
	}
	return out
}

// buildCELEnv declares the ctx variable and the any_in/all_in membership
// helpers (04 §4.2). ctx is dyn-typed so predicates navigate the projection maps
// without a compiled schema; predicates still type-check to bool.
//
// any_in/all_in accept a dyn receiver so both the spec's declared surface —
// `ctx.targets.any_in("prod-critical")` (04 §4.2, and its §4.3 example
// policies) — and the explicit list form
// `ctx.targets.criticality_classes.any_in(...)` work: a map receiver resolves
// through its criticality_classes; a list receiver is used as-is.
func buildCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("ctx", cel.DynType),
		cel.Function("any_in",
			cel.MemberOverload("dyn_any_in_string",
				[]*cel.Type{cel.DynType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(anyIn)),
		),
		cel.Function("all_in",
			cel.MemberOverload("dyn_all_in_string",
				[]*cel.Type{cel.DynType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(allIn)),
		),
	)
}

// anyIn implements `<recv>.any_in(<class>)`: true when the class appears in the
// receiver's membership list.
func anyIn(recv, class ref.Val) ref.Val {
	items, err := membershipStrings(recv)
	if err != nil {
		return types.NewErr("any_in: %v", err)
	}
	want := fmt.Sprintf("%v", class.Value())
	for _, s := range items {
		if s == want {
			return types.Bool(true)
		}
	}
	return types.Bool(false)
}

// allIn implements `<recv>.all_in(<class>)`: true when the membership list is
// non-empty and every element equals the class (v0 approximation of "all
// targets in class"; sharper per-target modeling is a v1 enhancement).
func allIn(recv, class ref.Val) ref.Val {
	items, err := membershipStrings(recv)
	if err != nil {
		return types.NewErr("all_in: %v", err)
	}
	if len(items) == 0 {
		return types.Bool(false)
	}
	want := fmt.Sprintf("%v", class.Value())
	for _, s := range items {
		if s != want {
			return types.Bool(false)
		}
	}
	return types.Bool(true)
}

// membershipStrings resolves a receiver to its membership list: a map (the
// ctx.targets object) via its criticality_classes field, a list as-is.
func membershipStrings(recv ref.Val) ([]string, error) {
	if native, err := recv.ConvertToNative(reflect.TypeOf(map[string]any{})); err == nil {
		m := native.(map[string]any)
		cc, ok := m["criticality_classes"]
		if !ok {
			return nil, fmt.Errorf("receiver map has no criticality_classes")
		}
		return toStrings(cc)
	}
	native, err := recv.ConvertToNative(reflect.TypeOf([]any{}))
	if err != nil {
		return nil, fmt.Errorf("receiver is neither a targets object nor a list: %w", err)
	}
	return toStrings(native)
}

// toStrings coerces a []any (or []string) into strings.
func toStrings(v any) ([]string, error) {
	switch items := v.(type) {
	case []string:
		return items, nil
	case []any:
		out := make([]string, 0, len(items))
		for _, item := range items {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected a list, got %T", v)
	}
}
