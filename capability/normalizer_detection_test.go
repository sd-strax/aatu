package capability

import (
	"testing"

	"github.com/sd-strax/reckon/identity"
)

func detectionPayload() map[string]any {
	return map[string]any{
		"class_uid": 2004,
		"time":      "2026-04-20T14:32:11Z",
		"metadata":  map[string]any{"product": map[string]any{"vendor_name": "CrowdStrike"}},
		"finding": map[string]any{
			"uid":        "det-123",
			"title":      "Suspicious PowerShell",
			"confidence": "High",
			"types":      []any{"T1059.001", "T1086"},
		},
		// Nested evidence: a process_activity event the detection fired on.
		"evidence": map[string]any{
			"class_uid": 1007,
			"process": map[string]any{
				"pid":          4242,
				"name":         "powershell.exe",
				"created_time": "2026-04-20T14:32:11Z",
			},
			"device": map[string]any{"hostname": "WIN-DC01", "domain": "CONTOSO"},
			"actor":  map[string]any{"user": map[string]any{"name": "jdoe", "domain": "CONTOSO", "uid": "S-1"}},
		},
	}
}

// TestDetectionNormalizer covers §4.12: an Indicator + Sighting with INFERRED
// provenance attributed to a vendor Identity, on top of the DIRECT entities
// from recursively normalizing the nested evidence.
func TestDetectionNormalizer(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(detectionPayload()))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	// Indicator: INFERRED, vendor-attributed, carries technique IDs.
	if len(res.Indicators) != 1 {
		t.Fatalf("indicators = %d; want 1", len(res.Indicators))
	}
	ind := res.Indicators[0]
	if ind.Provenance.DerivationMode != DerivationInferred {
		t.Errorf("indicator derivation_mode = %q; want INFERRED", ind.Provenance.DerivationMode)
	}
	if ind.Provenance.Tool != "CrowdStrike" {
		t.Errorf("indicator tool = %q; want CrowdStrike", ind.Provenance.Tool)
	}
	if len(ind.IndicatorTypes) != 2 || ind.IndicatorTypes[0] != "T1059.001" {
		t.Errorf("indicator_types = %v; want [T1059.001 T1086]", ind.IndicatorTypes)
	}
	if ind.Confidence != 85 {
		t.Errorf("confidence = %d; want 85 (High)", ind.Confidence)
	}

	// Vendor Identity is the created_by_ref target and is emitted.
	if len(res.Identities) != 1 || res.Identities[0].ID != ind.CreatedByRef {
		t.Errorf("vendor identity missing or not the created_by_ref: %+v", res.Identities)
	}

	// Sighting references the indicator and the recursively-produced entities.
	if len(res.Sightings) != 1 {
		t.Fatalf("sightings = %d; want 1", len(res.Sightings))
	}
	s := res.Sightings[0]
	if s.SightingOfRef != ind.ID {
		t.Errorf("sighting_of_ref = %q; want indicator %q", s.SightingOfRef, ind.ID)
	}
	if len(s.WhereSighted) == 0 || len(s.ObservedDataRefs) == 0 {
		t.Error("sighting should reference evidence entities and observed-data")
	}

	// The recursive evidence normalization produced the process's DIRECT
	// entities (process, host, user) — those stay DIRECT.
	if countTypes(res.SCOs)[identity.TypeProcess] != 1 {
		t.Errorf("expected the evidence process SCO; got SCOs %v", countTypes(res.SCOs))
	}
	for _, sco := range res.SCOs {
		if sco.Provenance.DerivationMode != DerivationDirect {
			t.Errorf("evidence SCO %s is %q; want DIRECT", sco.Type, sco.Provenance.DerivationMode)
		}
	}
}

// TestDetectionNormalizerNoEvidence: a detection with no nested evidence still
// yields an Indicator + Sighting + vendor Identity (just no DIRECT entities).
func TestDetectionNormalizerNoEvidence(t *testing.T) {
	res, err := testRegistry().Normalize(makeEvent(map[string]any{
		"class_uid": 2004,
		"time":      "2026-04-20T14:32:11Z",
		"metadata":  map[string]any{"product": map[string]any{"vendor_name": "Defender"}},
		"finding":   map[string]any{"uid": "d-1", "title": "Malware", "confidence": 42},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Indicators) != 1 || len(res.Sightings) != 1 || len(res.Identities) != 1 {
		t.Fatalf("want 1 indicator/sighting/identity; got %d/%d/%d",
			len(res.Indicators), len(res.Sightings), len(res.Identities))
	}
	if res.Indicators[0].Confidence != 42 {
		t.Errorf("numeric confidence = %d; want 42", res.Indicators[0].Confidence)
	}
	if len(res.SCOs) != 0 {
		t.Errorf("no evidence should yield no SCOs; got %d", len(res.SCOs))
	}
	// §4.12: the raw "this was seen" signal must survive even without evidence —
	// one ObservedData, referenced by the Sighting.
	if len(res.ObservedData) != 1 {
		t.Fatalf("ObservedData = %d; want 1 (raw signal preserved)", len(res.ObservedData))
	}
	if len(res.Sightings[0].ObservedDataRefs) != 1 || res.Sightings[0].ObservedDataRefs[0] != res.ObservedData[0].ID {
		t.Error("Sighting does not reference the detection's raw ObservedData")
	}
}

// TestDetectionDeterministicIds: re-ingesting the same detection dedupes the
// Indicator to the same id.
func TestDetectionDeterministicIds(t *testing.T) {
	reg := testRegistry()
	a, _ := reg.Normalize(makeEvent(detectionPayload()))
	b, _ := reg.Normalize(makeEvent(detectionPayload()))
	if a.Indicators[0].ID != b.Indicators[0].ID {
		t.Errorf("indicator id not stable across ingests: %q vs %q", a.Indicators[0].ID, b.Indicators[0].ID)
	}
}
