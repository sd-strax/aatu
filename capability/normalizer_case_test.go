package capability

import (
	"testing"

	"github.com/sd-strax/reckon/identity"
)

func casePayload() map[string]any {
	return map[string]any{
		"class_uid":        2005,
		"time":             "2026-04-20T14:32:11Z",
		"status":           "In Progress",
		"priority":         "2 - High",
		"assignment_group": "SOC-Tier3",
		"finding_info": map[string]any{
			"uid":   "INC0010042",
			"title": "Suspicious RDP from WIN-FILE01",
			"desc":  "Analyst flagged lateral movement via RDP.",
		},
		"unmapped": map[string]any{
			"link": "https://acme.service-now.com/nav_to.do?uri=incident.do?sys_id=abc",
			"sor":  "servicenow",
		},
	}
}

// TestCaseNormalizer covers §2.9: an incident_finding (2005) normalizes to a
// single ObservedData carrying case metadata in Extensions, with no SCOs and a
// DIRECT derivation (a plain observation, not the INFERRED Indicator path).
func TestCaseNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(casePayload()))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	if len(res.SCOs) != 0 {
		t.Errorf("case normalizer produced %d SCOs; want 0 (no entity extraction in v0)", len(res.SCOs))
	}
	if len(res.ObservedData) != 1 {
		t.Fatalf("got %d ObservedData; want 1", len(res.ObservedData))
	}
	od := res.ObservedData[0]
	if len(od.ObjectRefs) != 0 {
		t.Errorf("ObservedData.object_refs = %d; want 0", len(od.ObjectRefs))
	}
	if od.Provenance.DerivationMode != DerivationDirect {
		t.Errorf("derivation_mode = %q; want DIRECT", od.Provenance.DerivationMode)
	}

	want := map[string]string{
		"case_number": "INC0010042",
		"title":       "Suspicious RDP from WIN-FILE01",
		"status":      "In Progress",
		"summary":     "Analyst flagged lateral movement via RDP.",
		"link":        "https://acme.service-now.com/nav_to.do?uri=incident.do?sys_id=abc",
	}
	for k, v := range want {
		if got := od.Extensions[k]; got != v {
			t.Errorf("Extensions[%q] = %v; want %q", k, od.Extensions[k], v)
		}
	}
}

// TestCaseNormalizerRegistered: class 2005 routes to the case normalizer, not
// the opaque default.
func TestCaseNormalizerRegistered(t *testing.T) {
	reg := NewRegistry(identity.NewResolver(testNS))
	var found bool
	for _, c := range reg.HandledClasses() {
		if c == 2005 {
			found = true
		}
	}
	if !found {
		t.Errorf("HandledClasses() = %v; want it to contain 2005", reg.HandledClasses())
	}
}
