package capability

import "testing"

// TestListCapabilitiesStatus classifies verbs by binding presence and adapter
// health: available (healthy binding), degraded (binding but unhealthy),
// unavailable (no binding).
func TestListCapabilitiesStatus(t *testing.T) {
	catalog := DefaultCatalog()
	res := newResolver(
		map[string][]Binding{
			// enumerate_logons: healthy adapter → available.
			"enumerate_logons": {{Adapter: "fixture", Operation: "replay", Priority: 100}},
			// get_process_ancestry: adapter present but unhealthy → degraded.
			"get_process_ancestry": {{Adapter: "down", Operation: "op", Priority: 100}},
			// get_host_context: bound to an adapter not in the map → degraded.
			"get_host_context": {{Adapter: "missing", Operation: "op", Priority: 100}},
			// (get_indicator_context, search_alerts, resolve_entity have no
			// bindings → unavailable.)
		},
		map[string]Adapter{
			"fixture": healthyStub("fixture"),
			"down":    &stubAdapter{name: "down", healthy: false},
		},
	)

	byVerb := map[string]CapabilityStatus{}
	for _, s := range res.ListCapabilities(catalog) {
		byVerb[s.Descriptor.Verb] = s.Status
	}

	cases := map[string]CapabilityStatus{
		"enumerate_logons":      StatusAvailable,
		"get_process_ancestry":  StatusDegraded,
		"get_host_context":      StatusDegraded,
		"get_indicator_context": StatusUnavailable,
		"search_alerts":         StatusUnavailable,
	}
	for verb, want := range cases {
		if byVerb[verb] != want {
			t.Errorf("%s status = %q; want %q", verb, byVerb[verb], want)
		}
	}
}

// TestListCapabilitiesCoversCatalog: every catalog descriptor appears in the
// output exactly once, even with no bindings at all.
func TestListCapabilitiesCoversCatalog(t *testing.T) {
	catalog := DefaultCatalog()
	res := newResolver(map[string][]Binding{}, map[string]Adapter{})
	summaries := res.ListCapabilities(catalog)
	if len(summaries) != len(catalog.Verbs()) {
		t.Fatalf("got %d summaries; want %d (one per descriptor)", len(summaries), len(catalog.Verbs()))
	}
	for _, s := range summaries {
		if s.Status != StatusUnavailable {
			t.Errorf("%s: status %q with no bindings; want unavailable", s.Descriptor.Verb, s.Status)
		}
	}
}

// TestAvailableVerbs returns only the healthy-binding verbs.
func TestAvailableVerbs(t *testing.T) {
	catalog := DefaultCatalog()
	res := newResolver(
		map[string][]Binding{"enumerate_logons": {{Adapter: "fixture", Operation: "replay", Priority: 100}}},
		map[string]Adapter{"fixture": healthyStub("fixture")},
	)
	got := res.AvailableVerbs(catalog)
	if len(got) != 1 || got[0] != "enumerate_logons" {
		t.Errorf("available verbs = %v; want [enumerate_logons]", got)
	}
}
