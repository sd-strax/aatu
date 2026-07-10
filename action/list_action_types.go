package action

import "sort"

// ActionAvailability is an action type's current dispatchability in the tenant,
// analogous to capability.CapabilityStatus (08 §3, mirroring 03 §6.3).
type ActionAvailability string

const (
	ActionAvailable   ActionAvailability = "available"   // ≥1 healthy binding
	ActionDegraded    ActionAvailability = "degraded"    // bindings exist, all unhealthy
	ActionUnavailable ActionAvailability = "unavailable" // no binding configured
)

// ActionSummary pairs an action descriptor with its current availability.
type ActionSummary struct {
	Descriptor ActionDescriptor   `json:"descriptor"`
	Status     ActionAvailability `json:"status"`
	Bindings   int                `json:"bindings"`
}

// ListActionTypes implements the list_action_types verb (08 §3): for every
// cataloged action it reports whether the tenant can currently dispatch it, so
// the agent loop advertises only usable actions. An action appears once its
// descriptor is registered and at least one binding exists.
func (r *ActionResolver) ListActionTypes(catalog *ActionCatalog) []ActionSummary {
	types := catalog.ActionTypes()
	out := make([]ActionSummary, 0, len(types))
	for _, at := range types {
		d, _ := catalog.Descriptor(at)
		bindings := r.bindings[at]
		out = append(out, ActionSummary{
			Descriptor: d,
			Status:     r.actionStatus(bindings),
			Bindings:   len(bindings),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Descriptor.ActionType < out[j].Descriptor.ActionType })
	return out
}

// actionStatus classifies an action from its bindings and their adapters' health.
func (r *ActionResolver) actionStatus(bindings []ActionBinding) ActionAvailability {
	if len(bindings) == 0 {
		return ActionUnavailable
	}
	for _, b := range bindings {
		if a, ok := r.adapters[b.Adapter]; ok && a.Health().Healthy {
			return ActionAvailable
		}
	}
	return ActionDegraded
}
