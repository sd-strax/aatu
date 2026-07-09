package capability

import "sort"

// CapabilityStatus is a verb's current resolvability in the tenant (§6.3).
type CapabilityStatus string

const (
	// StatusAvailable: at least one configured binding's adapter is present and
	// healthy — the agent may advertise this verb to the LLM.
	StatusAvailable CapabilityStatus = "available"
	// StatusDegraded: bindings are configured but every adapter is absent or
	// unhealthy. Recoverable; the agent may re-list later in the session.
	StatusDegraded CapabilityStatus = "degraded"
	// StatusUnavailable: no binding is configured for this verb in the tenant.
	// Structural — will not change without a config edit.
	StatusUnavailable CapabilityStatus = "unavailable"
)

// CapabilitySummary pairs a verb descriptor with its current availability and
// the number of configured bindings.
type CapabilitySummary struct {
	Descriptor CapabilityDescriptor `json:"descriptor"`
	Status     CapabilityStatus     `json:"status"`
	Bindings   int                  `json:"bindings"`
}

// ListCapabilities implements the list_capabilities verb (§2.8): for every
// catalog descriptor it reports whether the tenant can currently resolve it,
// so the agent loop can trim the advertised tool set to healthy verbs (§6.3).
// Results are sorted by verb for stable output.
func (r *Resolver) ListCapabilities(catalog *Catalog) []CapabilitySummary {
	verbs := catalog.Verbs()
	out := make([]CapabilitySummary, 0, len(verbs))
	for _, verb := range verbs {
		d, _ := catalog.Descriptor(verb)
		bindings := r.bindings[verb]
		out = append(out, CapabilitySummary{
			Descriptor: d,
			Status:     r.verbStatus(bindings),
			Bindings:   len(bindings),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Descriptor.Verb < out[j].Descriptor.Verb })
	return out
}

// verbStatus classifies a verb from its bindings and their adapters' health.
func (r *Resolver) verbStatus(bindings []Binding) CapabilityStatus {
	if len(bindings) == 0 {
		return StatusUnavailable
	}
	for _, b := range bindings {
		if a, ok := r.adapters[b.Adapter]; ok && a.Health().Healthy {
			return StatusAvailable
		}
	}
	return StatusDegraded
}

// AvailableVerbs returns just the verbs the agent should advertise (§6.3): those
// whose status is available.
func (r *Resolver) AvailableVerbs(catalog *Catalog) []string {
	var out []string
	for _, s := range r.ListCapabilities(catalog) {
		if s.Status == StatusAvailable {
			out = append(out, s.Descriptor.Verb)
		}
	}
	return out
}
