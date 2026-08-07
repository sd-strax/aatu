package main

import (
	"encoding/json"
	"strings"
	"time"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// normalize shapes a greynoise-mcp tool's JSON output into OCSF events (11 §5.4).
// GreyNoise reports IP reputation, which is a threat-intel *claim* about an
// indicator, not passive telemetry — so a MALICIOUS classification becomes an
// OCSF detection_finding (class 2004) that the engine's §4.12 normalizer turns
// into an Indicator + Sighting (INFERRED). A benign/unknown result — and every
// RIOT (known-good business service) result — is emitted opaque (class 0) rather
// than minting a false malicious Indicator: the reputation is preserved, no
// indicator is asserted. get_indicator_context's contract (03 §3) is exactly
// this: `reputation` plus `ti_matches` only when there is a match.
//
// NOTE (validate live, 11 §3): the GreyNoise field paths below (ip,
// classification, last_seen, actor, tags) match the documented v2 IP-context
// response; confirm against real greynoise-mcp output and adjust if the server
// wraps or renames them.
func normalize(operation, text string) ([]ocsfEvent, error) {
	objs, err := extractObjects(text)
	if err != nil {
		return nil, err
	}
	switch operation {
	case "ip_context", "gnql_query":
		return normalizeContext(objs), nil
	case "riot":
		// RIOT is a known-good business service — always benign enrichment.
		return opaque("benign", objs), nil
	default:
		return opaque("", objs), nil
	}
}

// normalizeContext classifies each GreyNoise IP-context object.
func normalizeContext(items []map[string]any) []ocsfEvent {
	out := make([]ocsfEvent, 0, len(items))
	for _, e := range items {
		ip := str(e["ip"])
		if ip == "" {
			continue // not a context object (e.g. a stats wrapper) — skip
		}
		classification := strings.ToLower(str(e["classification"]))
		t := eventTime(e, "last_seen")
		if classification == "malicious" {
			out = append(out, findingEvent(ip, classification, t, e))
		} else {
			out = append(out, enrichmentEvent(ip, classification, t, e))
		}
	}
	return out
}

// findingEvent builds an OCSF detection_finding (2004) whose nested `evidence`
// carries the IP so the engine's recursion mints an ipv4-addr SCO, and whose
// finding fields drive the Indicator (03 §4.12).
func findingEvent(ip, classification string, t time.Time, raw map[string]any) ocsfEvent {
	title := "GreyNoise: " + classification
	if actor := str(raw["actor"]); actor != "" && actor != "unknown" {
		title += " (" + actor + ")"
	}
	finding := map[string]any{
		"uid":        "greynoise:" + ip,
		"title":      title,
		"pattern":    "[ipv4-addr:value = '" + ip + "']",
		"confidence": "High",
		"types":      stringSlice(raw["tags"]),
	}
	return ocsfEvent{
		ClassUID:  2004,
		ClassName: "Detection Finding",
		Time:      t,
		Raw: map[string]any{
			"finding": finding,
			"evidence": map[string]any{
				"class_uid":    4001,
				"class_name":   "Network Activity",
				"src_endpoint": map[string]any{"ip": ip},
			},
			"greynoise": raw,
		},
	}
}

// enrichmentEvent emits a benign/unknown reputation as an opaque event (class 0
// → the engine's default normalizer, 03 §4.13): the reputation is preserved as
// provenance without asserting an indicator.
func enrichmentEvent(ip, classification string, t time.Time, raw map[string]any) ocsfEvent {
	return ocsfEvent{
		ClassUID:  0,
		ClassName: "GreyNoise Context",
		Time:      t,
		Raw: map[string]any{
			"ip":         ip,
			"reputation": classification,
			"greynoise":  raw,
		},
	}
}

func opaque(reputation string, objs []map[string]any) []ocsfEvent {
	out := make([]ocsfEvent, 0, len(objs))
	for _, o := range objs {
		raw := map[string]any{"greynoise": o}
		if reputation != "" {
			raw["reputation"] = reputation
		}
		if ip := str(o["ip"]); ip != "" {
			raw["ip"] = ip
		}
		out = append(out, ocsfEvent{ClassUID: 0, ClassName: "GreyNoise Context", Raw: raw})
	}
	return out
}

// extractObjects pulls the list of GreyNoise objects out of a tool result: a
// bare object (ip_context / riot), or a wrapper with a well-known array field
// (gnql_query returns {"data": [...]}).
func extractObjects(text string) ([]map[string]any, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, err
	}
	for _, key := range []string{"data", "results", "items"} {
		if arr, ok := obj[key].([]any); ok {
			out := make([]map[string]any, 0, len(arr))
			for _, e := range arr {
				if m, ok := e.(map[string]any); ok {
					out = append(out, m)
				}
			}
			return out, nil
		}
	}
	return []map[string]any{obj}, nil
}

// eventTime parses an RFC3339 timestamp at key, or returns the zero time.
func eventTime(o map[string]any, key string) time.Time {
	if s, ok := o[key].(string); ok {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
