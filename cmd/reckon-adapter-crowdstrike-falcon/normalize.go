package main

import (
	"encoding/json"
	"strings"
	"time"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// normalize shapes a falcon-mcp tool's structured JSON output into OCSF events
// (11 §5.4):
//
//   - detections → OCSF detection_finding (class 2004): the engine's §4.12
//     normalizer turns each into an Indicator + Sighting (INFERRED). Field
//     paths are defensive first-guesses against the Falcon alerts shape
//     (composite_id, device.hostname, tactic/technique, severity_name) —
//     LIVE-TUNE against real output.
//   - hosts → opaque device-inventory events (class 0 → the engine's default
//     normalizer, 03 §4.13): the v0 engine has no device-inventory OCSF class,
//     so the shape is preserved whole with the hostname surfaced.
//   - intel indicators → opaque enrichment, same reasoning.
func normalize(operation, text string) ([]ocsfEvent, error) {
	objs, err := extractObjects(text)
	if err != nil {
		return nil, err
	}
	switch operation {
	case "search_detections", "get_detection_details":
		return normalizeDetections(objs), nil
	case "search_hosts", "get_host_details":
		return opaqueEvents("Falcon Host", "hostname", objs), nil
	case "search_indicators":
		return opaqueEvents("Falcon Intel Indicator", "indicator", objs), nil
	default:
		return opaqueEvents("Falcon Object", "", objs), nil
	}
}

// normalizeDetections maps Falcon detections onto the OCSF detection_finding
// shape the engine's §4.12 normalizer reads (finding.{uid,title,confidence,
// types}).
func normalizeDetections(items []map[string]any) []ocsfEvent {
	out := make([]ocsfEvent, 0, len(items))
	for _, d := range items {
		uid := firstNonEmpty(str(d["composite_id"]), str(d["detection_id"]), str(d["id"]))
		title := firstNonEmpty(str(d["description"]), str(d["display_name"]), str(d["name"]))
		if title == "" {
			title = "Falcon detection"
		}
		var types []string
		for _, k := range []string{"tactic", "technique"} {
			if v := str(d[k]); v != "" {
				types = append(types, v)
			}
		}
		finding := map[string]any{
			"uid":        "falcon:" + uid,
			"title":      title,
			"confidence": firstNonEmpty(str(d["severity_name"]), "Medium"),
			"types":      types,
		}
		raw := map[string]any{
			"finding": finding,
			"falcon":  d,
		}
		// Surface the device hostname for the reader; the engine's finding path
		// keeps the whole raw signal regardless (03 §4.12).
		if h := digStr(d, "device", "hostname"); h != "" {
			raw["hostname"] = h
		}
		out = append(out, ocsfEvent{
			ClassUID:  2004,
			ClassName: "Detection Finding",
			Time:      eventTime(d, "created_timestamp"),
			Raw:       raw,
		})
	}
	return out
}

// opaqueEvents preserves vendor objects whole under the default normalizer
// (03 §4.13), surfacing one well-known key when present.
func opaqueEvents(className, surfaceKey string, objs []map[string]any) []ocsfEvent {
	out := make([]ocsfEvent, 0, len(objs))
	for _, o := range objs {
		raw := map[string]any{"falcon": o}
		if surfaceKey != "" {
			if v := str(o[surfaceKey]); v != "" {
				raw[surfaceKey] = v
			}
		}
		out = append(out, ocsfEvent{ClassUID: 0, ClassName: className, Raw: raw})
	}
	return out
}

// extractObjects pulls the object list out of a tool result: a bare array, a
// bare object, or a wrapper with a well-known array field (the Falcon API
// convention is resources[]).
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
	for _, key := range []string{"resources", "detections", "hosts", "results", "data", "items"} {
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

// eventTime parses an RFC3339 timestamp at key, else returns the zero time.
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

func digStr(m map[string]any, path ...string) string {
	cur := any(m)
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	return str(cur)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
