package capability

import "sort"

// CapabilityDescriptor is the LLM-facing declaration of a verb (§5.3): its name,
// an intent description the agent renders into a tool definition, its typed
// inputs, and its output type. Descriptors are data, not code — a new verb is a
// catalog entry plus a binding, never a change to dispatch (§5.1).
type CapabilityDescriptor struct {
	Verb   string       `json:"verb"`
	Intent string       `json:"intent"` // one-line, LLM-facing
	Inputs []InputParam `json:"inputs"`
	Output string       `json:"output"` // output type description
}

// InputParam is one typed verb input.
type InputParam struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // "entity", "time_window", "string", "int", "enum", …
	Required bool   `json:"required"`
	Desc     string `json:"desc,omitempty"`
}

// Catalog holds the registered verb descriptors, keyed by verb name.
type Catalog struct {
	byVerb map[string]CapabilityDescriptor
}

// NewCatalog returns an empty catalog.
func NewCatalog() *Catalog { return &Catalog{byVerb: make(map[string]CapabilityDescriptor)} }

// Register adds or replaces a descriptor.
func (c *Catalog) Register(d CapabilityDescriptor) { c.byVerb[d.Verb] = d }

// Descriptor returns the descriptor for a verb, if registered.
func (c *Catalog) Descriptor(verb string) (CapabilityDescriptor, bool) {
	d, ok := c.byVerb[verb]
	return d, ok
}

// Verbs returns the registered verb names, sorted.
func (c *Catalog) Verbs() []string {
	out := make([]string, 0, len(c.byVerb))
	for v := range c.byVerb {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// entity is a shorthand for a required entity input.
func entityInput(name, desc string) InputParam {
	return InputParam{Name: name, Type: "entity", Required: true, Desc: desc}
}

// windowInput is the standard optional time-window input.
func windowInput() InputParam {
	return InputParam{Name: "window", Type: "time_window", Required: false, Desc: "time bound; defaults to the tenant investigation window"}
}

// DefaultCatalog registers the v0 verb descriptors the fixture path can service.
// It is a representative subset of §2, not the full 22 — the rest land as their
// normalizers and bindings do (§5.1).
func DefaultCatalog() *Catalog {
	c := NewCatalog()
	for _, d := range []CapabilityDescriptor{
		{
			Verb:   "resolve_entity",
			Intent: "Canonicalize a free-form identifier (IP, hostname, user) into a typed entity with a stable id.",
			Inputs: []InputParam{{Name: "identifier", Type: "string", Required: true}, {Name: "hint_type", Type: "string", Required: false}},
			Output: "entity",
		},
		{
			Verb:   "get_host_context",
			Intent: "Fetch asset/CMDB context for a host: owner, OS, last-seen, sensors.",
			Inputs: []InputParam{entityInput("host", "the host to look up")},
			Output: "host context",
		},
		{
			Verb:   "get_indicator_context",
			Intent: "Enrich an indicator (IP, domain, hash, URL) with threat-intel reputation and sightings.",
			Inputs: []InputParam{entityInput("indicator", "the indicator to enrich")},
			Output: "indicator context",
		},
		{
			Verb:   "get_process_ancestry",
			Intent: "Walk a process's parent chain to root, returning ordered parent-child observations.",
			Inputs: []InputParam{entityInput("process", "the process to walk from"), windowInput()},
			Output: "list<observed_data>",
		},
		{
			Verb:   "enumerate_logons",
			Intent: "List authentication events against a user or host in a window, optionally filtered by outcome.",
			Inputs: []InputParam{entityInput("target", "user-account or host"), windowInput(), {Name: "outcome", Type: "enum", Required: false, Desc: "SUCCESS|FAILURE|ALL"}},
			Output: "list<observed_data>",
		},
		{
			Verb:   "get_network_connections",
			Intent: "Return network connections for a host, IP, or process in a window.",
			Inputs: []InputParam{entityInput("endpoint", "host, IP, or process"), windowInput(), {Name: "direction", Type: "enum", Required: false, Desc: "INBOUND|OUTBOUND|ALL"}},
			Output: "list<observed_data>",
		},
		{
			Verb:   "search_alerts",
			Intent: "Search detection findings / alerts matching a filter in a window.",
			Inputs: []InputParam{{Name: "filter", Type: "alert_filter", Required: true}, windowInput()},
			Output: "list<observed_data>",
		},
		{
			Verb:   "list_capabilities",
			Intent: "List the verbs resolvable in this tenant and their current availability.",
			Inputs: nil,
			Output: "list<capability_summary>",
		},
	} {
		c.Register(d)
	}
	return c
}
