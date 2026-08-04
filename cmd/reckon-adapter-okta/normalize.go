package main

import (
	"encoding/json"
	"strings"
	"time"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// normalize shapes an okta-mcp tool's JSON text output into OCSF events (11 §5.4
// — by the time data crosses the adapter boundary it is OCSF; the engine's
// normalizer then maps OCSF → STIX). It RESHAPES Okta's native fields into the
// exact OCSF paths the engine's normalizers read (capability/normalizer_auth.go
// class 3002, normalizer_account.go class 3005), and preserves the original Okta
// object under `okta` for provenance.
//
// Okta's System Log is heterogeneous (auth, account lifecycle, admin/config —
// all event types), so get_logs events are CLASSIFIED by eventType: only genuine
// authentications become 3002, lifecycle/privilege/group events become 3005, and
// everything else is emitted opaque (class 0 → the engine's default normalizer,
// 03 §4.13) rather than force-fit — an admin config change is not an
// authentication and must not be labeled one.
func normalize(operation, text string) ([]ocsfEvent, error) {
	objs, err := extractObjects(text)
	if err != nil {
		return nil, err
	}
	switch operation {
	case "get_logs":
		return normalizeLogs(objs), nil
	case "get_user", "list_users", "list_group_users":
		return normalizeUsers(objs), nil
	default: // groups etc. — preserved opaque until a dedicated shape is needed
		return opaque(objs), nil
	}
}

// normalizeLogs classifies each Okta System Log event and reshapes it.
func normalizeLogs(items []map[string]any) []ocsfEvent {
	out := make([]ocsfEvent, 0, len(items))
	for _, e := range items {
		t := eventTime(e, "published")
		switch classify(str(e["eventType"])) {
		case classAuth:
			out = append(out, ocsfEvent{ClassUID: 3002, ClassName: "Authentication", Time: t, Raw: authPayload(e)})
		case classAccount:
			out = append(out, ocsfEvent{ClassUID: 3005, ClassName: "Account Change", Time: t, Raw: accountPayload(e)})
		default:
			out = append(out, ocsfEvent{ClassUID: 0, ClassName: "Okta System Log", Time: t, Raw: e})
		}
	}
	return out
}

// normalizeUsers reshapes an Okta user object into an OCSF account event whose
// `user` the engine extracts into a user-account SCO — the entity-extraction
// path get_entity_context needs (the engine has no standalone user-inventory
// normalizer in v0; the account normalizer is the user-extraction route).
func normalizeUsers(users []map[string]any) []ocsfEvent {
	out := make([]ocsfEvent, 0, len(users))
	for _, u := range users {
		login := firstNonEmpty(digStr(u, "profile", "login"), digStr(u, "profile", "email"))
		p := map[string]any{
			"user": map[string]any{"name": login, "uid": str(u["id"])},
			"okta": u,
		}
		out = append(out, ocsfEvent{ClassUID: 3005, ClassName: "Account Change", Time: eventTime(u, "created"), Raw: p})
	}
	return out
}

func opaque(objs []map[string]any) []ocsfEvent {
	out := make([]ocsfEvent, 0, len(objs))
	for _, o := range objs {
		out = append(out, ocsfEvent{ClassUID: 0, ClassName: "Okta Object", Raw: o})
	}
	return out
}

// authPayload maps an Okta auth LogEvent onto the OCSF 3002 paths the engine's
// auth normalizer reads: actor.user.{name,uid}, src_endpoint.ip, status.
func authPayload(e map[string]any) map[string]any {
	return map[string]any{
		"actor": map[string]any{"user": map[string]any{
			"name": digStr(e, "actor", "alternateId"),
			"uid":  digStr(e, "actor", "id"),
		}},
		"src_endpoint": map[string]any{"ip": digStr(e, "client", "ipAddress")},
		"status":       digStr(e, "outcome", "result"),
		"logon_type":   str(e["eventType"]),
		"okta":         e,
	}
}

// accountPayload maps an Okta lifecycle/privilege/group LogEvent onto the OCSF
// 3005 paths the engine's account-change normalizer reads: user.{name,uid}
// (target), actor.user (initiator), group.name, privileges.
func accountPayload(e map[string]any) map[string]any {
	p := map[string]any{
		"actor": map[string]any{"user": map[string]any{
			"name": digStr(e, "actor", "alternateId"),
			"uid":  digStr(e, "actor", "id"),
		}},
		"status": digStr(e, "outcome", "result"),
		"okta":   e,
	}
	if tu := firstTarget(e, "User"); tu != nil {
		p["user"] = map[string]any{
			"name": firstNonEmpty(str(tu["alternateId"]), str(tu["displayName"])),
			"uid":  str(tu["id"]),
		}
	}
	if tg := firstTarget(e, "UserGroup"); tg != nil {
		p["group"] = map[string]any{"name": str(tg["displayName"])}
	}
	if strings.Contains(str(e["eventType"]), "privilege") {
		p["privileges"] = str(e["displayMessage"])
	}
	return p
}

// event classes for get_logs.
const (
	classAuth = iota
	classAccount
	classOther
)

// classify maps an Okta eventType to an OCSF class bucket. Prefixes follow
// Okta's System Log event-type taxonomy.
func classify(eventType string) int {
	switch {
	case hasAnyPrefix(eventType, "user.authentication", "user.session"),
		strings.Contains(eventType, ".signon"),
		strings.Contains(eventType, "mfa.factor.verify"):
		return classAuth
	case hasAnyPrefix(eventType, "user.lifecycle", "user.account", "group.user_membership"),
		strings.Contains(eventType, "user_membership"),
		strings.Contains(eventType, "mfa.factor.activate"),
		strings.Contains(eventType, "mfa.factor.reset"):
		return classAccount
	default:
		return classOther
	}
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// firstTarget returns the first target[] element of the given Okta type.
func firstTarget(e map[string]any, typ string) map[string]any {
	arr, ok := e["target"].([]any)
	if !ok {
		return nil
	}
	for _, el := range arr {
		if m, ok := el.(map[string]any); ok && str(m["type"]) == typ {
			return m
		}
	}
	return nil
}

// extractObjects pulls the list of Okta objects out of a tool result, whether a
// bare array, a single object, or a wrapper object with a well-known array field
// (get_logs returns {"items": [...]}).
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
	for _, key := range []string{"items", "logs", "events", "users", "groups", "data", "results"} {
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

// digStr reads a nested string at a path of map keys.
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
