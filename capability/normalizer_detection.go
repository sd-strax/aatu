package capability

import (
	"strings"

	"github.com/sd-strax/reckon/identity"
)

// detectionNormalizer handles OCSF detection_finding (class_uid 2004) → STIX
// (§4.12) — the single INFERRED path in the capability layer. A vendor detection
// is a claim, not a passive observation, so this normalizer:
//
//   - recursively normalizes the nested evidence event through the registry,
//     producing the DIRECT entities + ObservedData the underlying class would;
//   - emits an Indicator and a Sighting with derivation_mode = INFERRED,
//     attributed to a per-tenant vendor Identity via created_by_ref;
//   - does NOT wrap them in an x-interpretation (capability §1 / persistence
//     §2.1 forbid it — the agent loop does that on engagement).
type detectionNormalizer struct {
	r   *identity.Resolver
	reg *Registry // for recursive evidence normalization
}

func (*detectionNormalizer) ClassUID() int { return 2004 }
func (*detectionNormalizer) Version() int  { return 1 }

func (n *detectionNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	var result NormalizationResult

	// 1. Recursively normalize nested evidence (DIRECT entities + ObservedData).
	var entityRefs, odRefs []identity.STIXID
	if ev, ok := lookupPath(p, "evidence"); ok {
		if evMap, ok := ev.(map[string]any); ok && toInt(evMap["class_uid"]) != 0 {
			sub, err := n.reg.Normalize(OcsfEvent{
				ID:         evt.ID, // same telemetry record — edges point at the detection event
				ClassUID:   toInt(evMap["class_uid"]),
				ClassName:  toString(evMap["class_name"]),
				Time:       evt.Time,
				RecordedAt: evt.RecordedAt,
				SourceTool: evt.SourceTool,
				Payload:    evMap,
			})
			if err != nil {
				return NormalizationResult{}, err
			}
			result.SCOs = append(result.SCOs, sub.SCOs...)
			result.ObservedData = append(result.ObservedData, sub.ObservedData...)
			result.Relationships = append(result.Relationships, sub.Relationships...)
			result.Edges = append(result.Edges, sub.Edges...)
			for _, s := range sub.SCOs {
				entityRefs = append(entityRefs, s.ID)
			}
			for _, od := range sub.ObservedData {
				odRefs = append(odRefs, od.ID)
			}
		}
	}

	// 2. Vendor Identity (created_by_ref target), auto-created per tenant.
	vendor := detectionVendor(p, evt.SourceTool)
	vendorID := n.r.Identity(vendor)
	result.Identities = append(result.Identities, VendorIdentity{ID: vendorID, Name: vendor})

	prov := Provenance{
		DerivationMode:    DerivationInferred,
		Tool:              vendor,
		Normalizer:        "detection_finding",
		NormalizerVersion: n.Version(),
		ObservedAt:        evt.Time,
	}

	// 3. Indicator — the vendor's claim.
	uid := firstNonEmpty(pathStr(p, "finding.uid"), pathStr(p, "finding_info.uid"))
	title := firstNonEmpty(pathStr(p, "finding.title"), pathStr(p, "finding_info.title"))
	pattern := pathStr(p, "finding.pattern")
	conf := mapConfidence(firstPath(p, "finding.confidence", "confidence"))
	types := stringSlice(firstPath(p, "finding.types", "finding_info.types"))

	indID := n.r.Indicator(uid, pattern)
	patternType := "vendor"
	if pattern == "" {
		patternType = ""
	}
	result.Indicators = append(result.Indicators, Indicator{
		ID:             indID,
		Name:           title,
		Pattern:        pattern,
		PatternType:    patternType,
		IndicatorTypes: types,
		ValidFrom:      evt.Time,
		Confidence:     conf,
		CreatedByRef:   vendorID,
		Provenance:     prov,
	})

	// 4. Sighting — the indicator seen against the evidence entities.
	result.Sightings = append(result.Sightings, Sighting{
		ID:               n.r.Sighting(indID, evt.Time, vendor),
		SightingOfRef:    indID,
		ObservedDataRefs: odRefs,
		WhereSighted:     entityRefs,
		Confidence:       conf,
		Description:      title,
		CreatedByRef:     vendorID,
		Provenance:       prov,
	})

	return result, nil
}

// detectionVendor picks the vendor name for attribution, preferring OCSF
// metadata.product over the source tool.
func detectionVendor(p map[string]any, sourceTool string) string {
	return firstNonEmpty(
		pathStr(p, "metadata.product.vendor_name"),
		pathStr(p, "metadata.product.name"),
		sourceTool,
	)
}

// mapConfidence maps an OCSF confidence value to a 0–100 STIX confidence,
// accepting numeric values and the High/Medium/Low vocabulary.
func mapConfidence(v any) int {
	switch c := v.(type) {
	case float64:
		return int(c)
	case int:
		return c
	case string:
		switch strings.ToLower(strings.TrimSpace(c)) {
		case "high":
			return 85
		case "medium":
			return 50
		case "low":
			return 15
		}
	}
	return 0
}

// stringSlice coerces a value to a []string, tolerating an []any of strings.
func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s := toString(item); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// firstPath returns the value at the first present dotted path.
func firstPath(m map[string]any, paths ...string) any {
	for _, p := range paths {
		if v, ok := lookupPath(m, p); ok {
			return v
		}
	}
	return nil
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
