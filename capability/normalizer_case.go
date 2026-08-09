package capability

import "github.com/sd-strax/reckon/identity"

// caseNormalizer handles OCSF incident_finding (class_uid 2005) → an ObservedData
// wrapping an external case reference (§2.9). DIRECT derivation: unlike the
// detection normalizer (2004 → INFERRED Indicator), a case is a plain
// observation. It extracts no SCOs — SNOW incidents carry no structured entity
// fields in v0 — carrying the case metadata (number/title/status/summary/link)
// in the ObservedData Extensions instead.
type caseNormalizer struct{ r *identity.Resolver }

func (*caseNormalizer) ClassUID() int { return 2005 }
func (*caseNormalizer) Version() int  { return 1 }

func (n *caseNormalizer) Normalize(evt OcsfEvent) (NormalizationResult, error) {
	p := evt.Payload
	ext := map[string]any{}
	put := func(k, v string) {
		if v != "" {
			ext[k] = v
		}
	}
	put("case_number", pathStr(p, "finding_info.uid"))
	put("title", pathStr(p, "finding_info.title"))
	put("summary", pathStr(p, "finding_info.desc"))
	put("status", pathStr(p, "status"))
	put("priority", pathStr(p, "priority"))
	put("assignment_group", pathStr(p, "assignment_group"))
	put("link", pathStr(p, "unmapped.link"))
	put("sor", pathStr(p, "unmapped.sor"))
	if len(ext) == 0 {
		ext = nil
	}
	return newBuilder(n.r, evt, "case", n.Version()).finish(ext), nil
}
