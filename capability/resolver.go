package capability

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/sd-strax/reckon/identity"
)

// Coverage is the structured outcome of a capability call (§2, §6.1). The agent
// loop branches on it without parsing prose.
type Coverage string

const (
	CoverageComplete             Coverage = "COMPLETE"              // all eligible bindings invoked and succeeded
	CoveragePartial              Coverage = "PARTIAL"               // fan-out: some succeeded, some failed
	CoverageUnavailableTenant    Coverage = "UNAVAILABLE_TENANT"    // no configured/applicable binding
	CoverageUnavailableTransient Coverage = "UNAVAILABLE_TRANSIENT" // applicable bindings exist but all unhealthy
	CoverageFailed               Coverage = "FAILED"                // healthy bindings called, all errored
)

// TimeWindow is a verb's [from, to] time bound.
type TimeWindow struct {
	From time.Time
	To   time.Time
}

// Binding maps a verb to one adapter operation with a priority and a parameter
// template (§3.2). FanOut marks bindings that legitimately contribute together
// (§3.4).
type Binding struct {
	Adapter   string
	Operation string
	Priority  int
	Params    map[string]any
	FanOut    bool
	// Scope is the source scope inherited from the adapter instance this binding
	// runs on (03 §3.5). Empty means the instance is unscoped and applies to any
	// investigation; a non-empty scope makes the binding applicable only to an
	// investigation carrying the identical scope. Set from the AdapterSpec at
	// build time, never from binding YAML — scope lives on the instance.
	Scope string
}

// CallInput is a verb call's input: the entity (or composite) the template's
// entity.* root resolves against, the time window, and any extra roots.
type CallInput struct {
	Entity map[string]any
	Window TimeWindow
	Extra  map[string]any
	// SourceScope is the investigation's source scope (03 §3.5), carried from the
	// Seed. Empty for single-organization investigations. A scoped call reaches
	// only unscoped instances and scoped instances of the same scope, and mints
	// identity in that scope's namespace.
	SourceScope string
}

// ScopeApplicable is the fail-closed §3.5 matching rule, shared by the read and
// write resolvers so both sides route identically: an unscoped instance
// (instanceScope == "") is applicable to any investigation; a scoped instance is
// applicable only to an investigation carrying the identical scope, and an
// unscoped investigation never matches a scoped instance.
func ScopeApplicable(instanceScope, investigationScope string) bool {
	return instanceScope == "" || instanceScope == investigationScope
}

// TenantContext supplies the tenant.* template root and identifies the tenant.
type TenantContext struct {
	Name     string
	Policies map[string]any
}

// CapabilityResult is the verb-call envelope (§2). It carries the reference
// lists the agent loop attaches to an x-interpretation, the structured Coverage,
// and — for the caller that persists them — the concrete telemetry and
// interpretation objects produced.
type CapabilityResult struct {
	Coverage         Coverage
	OcsfEventRefs    []string
	ObservedDataRefs []identity.STIXID
	EntityRefs       []identity.STIXID
	DegradationNotes []string

	Events     []OcsfEvent
	Normalized []NormalizationResult
}

func (r *CapabilityResult) note(format string, args ...any) {
	r.DegradationNotes = append(r.DegradationNotes, fmt.Sprintf(format, args...))
}

// Resolver turns a verb call into telemetry + interpretation objects by
// selecting bindings, templating params, invoking adapters, and normalizing
// results (§3). It is the read surface's dispatch; it does not reason.
type Resolver struct {
	tenant     TenantContext
	bindings   map[string][]Binding
	adapters   map[string]Adapter
	normalizer *Registry
}

// NewResolver builds a resolver over a tenant's bindings and its enabled adapter
// instances (only enabled adapters belong in the map), normalizing through norm.
func NewResolver(tenant TenantContext, bindings map[string][]Binding, adapters map[string]Adapter, norm *Registry) *Resolver {
	return &Resolver{tenant: tenant, bindings: bindings, adapters: adapters, normalizer: norm}
}

// ValidateBindings compiles every binding template, surfacing config errors
// (unknown transforms, malformed expressions) at load time rather than at call
// time (§3.3.4).
func ValidateBindings(bindings map[string][]Binding) error {
	for verb, bs := range bindings {
		for _, b := range bs {
			if err := validateParams(b.Params); err != nil {
				return fmt.Errorf("verb %s, adapter %s: %w", verb, b.Adapter, err)
			}
		}
	}
	return nil
}

func validateParams(params map[string]any) error {
	for _, v := range params {
		switch val := v.(type) {
		case string:
			if _, err := parseTemplate(val); err != nil {
				return err
			}
		case map[string]any:
			if err := validateParams(val); err != nil {
				return err
			}
		case []any:
			for _, item := range val {
				if s, ok := item.(string); ok {
					if _, err := parseTemplate(s); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// Resolve executes verb against input: it walks the verb's bindings by priority,
// templates and invokes the applicable/healthy ones, normalizes their OCSF
// output, and classifies coverage. Non-fan-out verbs stop at the first success;
// fan-out verbs invoke all eligible bindings. A FATAL adapter error propagates.
func (r *Resolver) Resolve(ctx context.Context, verb string, input CallInput) (CapabilityResult, error) {
	bindings := sortedByPriority(r.bindings[verb])
	var res CapabilityResult
	if len(bindings) == 0 {
		res.Coverage = CoverageUnavailableTenant
		res.note("no binding configured for verb %q in tenant %q", verb, r.tenant.Name)
		return res, nil
	}

	tctx := r.templateContext(verb, input)
	// §3.4 specifies parallel fan-out invocation; v0 runs bindings
	// sequentially — a latency-only simplification against fixtures.
	// Parallelize when real adapters land (Phase E).
	fanout := anyFanOut(bindings)

	var applicable, succeeded, failed int
	unhealthy := map[string]bool{}

	// §3.5: scope filtering runs before the priority walk — a scope-mismatched
	// binding is *not applicable*, never merely lower-priority, so it is skipped
	// here and never counted toward `applicable`. A verb whose every binding is
	// scope-filtered degrades exactly like any other coverage gap (§6.1).
	norm := r.normalizer.Scoped(input.SourceScope)

	for _, b := range bindings {
		if !ScopeApplicable(b.Scope, input.SourceScope) {
			res.note("binding %s/%s: scope %q not applicable to investigation scope %q", verb, b.Adapter, b.Scope, input.SourceScope)
			continue
		}
		adapter, ok := r.adapters[b.Adapter]
		if !ok {
			res.note("binding %s/%s: adapter not configured or disabled", verb, b.Adapter)
			continue
		}
		if unhealthy[b.Adapter] {
			continue // already marked unhealthy earlier this call
		}

		params, appl, err := renderParams(b.Params, tctx)
		if err != nil {
			// A template error is a config bug, not an operational condition.
			return CapabilityResult{}, fmt.Errorf("verb %s, adapter %s: template render: %w", verb, b.Adapter, err)
		}
		if !appl {
			res.note("binding %s/%s: required input missing, not applicable", verb, b.Adapter)
			continue
		}
		applicable++

		if h := adapter.Health(); !h.Healthy {
			unhealthy[b.Adapter] = true
			res.note("binding %s/%s: adapter unhealthy: %s", verb, b.Adapter, h.Message)
			continue
		}

		params[ParamVerb] = verb // let the fixture adapter (and logging) see the verb
		resp, err := adapter.Invoke(ctx, b.Operation, params)
		if err != nil {
			var ae *AdapterError
			if errors.As(err, &ae) {
				switch ae.Class {
				case ErrFatal:
					return CapabilityResult{}, err
				case ErrUnhealthy:
					// The binding WAS applicable — the adapter turning out
					// unhealthy at invoke time is transient, not structural, so
					// applicable stays counted and the classifier yields
					// UNAVAILABLE_TRANSIENT, never UNAVAILABLE_TENANT (§6.1).
					unhealthy[b.Adapter] = true
					res.note("binding %s/%s: adapter became unhealthy: %v", verb, b.Adapter, ae.Err)
					continue
				}
			}
			failed++
			res.note("binding %s/%s: call failed: %v", verb, b.Adapter, err)
			continue
		}

		succeeded++
		r.ingest(&res, norm, resp)
		if !fanout {
			break // non-fan-out: highest-priority success wins
		}
	}

	res.Coverage = classifyCoverage(fanout, applicable, succeeded, failed)
	return res, nil
}

// ingest converts an adapter response to telemetry records, normalizes each
// through the scope-bound registry norm, and accumulates the refs and concrete
// objects into res.
func (r *Resolver) ingest(res *CapabilityResult, norm *Registry, resp AdapterResponse) {
	for _, evt := range resp.ToOcsfEvents(time.Now()) {
		res.Events = append(res.Events, evt)
		res.OcsfEventRefs = append(res.OcsfEventRefs, evt.ID.String())

		nr, err := norm.Normalize(evt)
		if err != nil {
			res.note("normalize class %d: %v", evt.ClassUID, err)
			continue
		}
		res.Normalized = append(res.Normalized, nr)
		for _, od := range nr.ObservedData {
			res.ObservedDataRefs = append(res.ObservedDataRefs, od.ID)
		}
		for _, sco := range nr.SCOs {
			res.EntityRefs = append(res.EntityRefs, sco.ID)
		}
	}
}

// classifyCoverage maps per-binding outcomes to the §6.1 enum.
func classifyCoverage(fanout bool, applicable, succeeded, failed int) Coverage {
	if succeeded > 0 {
		if fanout && failed > 0 {
			return CoveragePartial
		}
		return CoverageComplete
	}
	if applicable == 0 {
		return CoverageUnavailableTenant
	}
	if failed == 0 {
		return CoverageUnavailableTransient // applicable bindings existed but all unhealthy
	}
	return CoverageFailed
}

// templateContext assembles the roots the templating engine resolves against.
func (r *Resolver) templateContext(verb string, input CallInput) map[string]any {
	ctx := map[string]any{
		"entity": input.Entity,
		"window": map[string]any{"from": input.Window.From, "to": input.Window.To},
		"tenant": map[string]any{"name": r.tenant.Name, "policies": r.tenant.Policies},
		"verb":   verb,
	}
	for k, v := range input.Extra {
		ctx[k] = v
	}
	return ctx
}

// sortedByPriority returns a copy of bindings sorted by descending priority
// (stable), so the config slice is never mutated.
func sortedByPriority(bindings []Binding) []Binding {
	out := append([]Binding(nil), bindings...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority > out[j].Priority })
	return out
}

func anyFanOut(bindings []Binding) bool {
	for _, b := range bindings {
		if b.FanOut {
			return true
		}
	}
	return false
}
