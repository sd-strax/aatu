package main

import (
	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

// describe is the reckon surface this bridge serves (11 §4.2), per
// implementation/adapter-candidates.md §3 Adapter A. Tool names and argument
// shapes are validated against the shipped falcon-mcp 0.16.0 source
// (search_hosts/get_host_details, search_detections/get_detection_details,
// search_indicators, add_ioc/remove_iocs); the FQL field names inside the
// binding filters are doc-derived and are the LIVE-TUNE surface — correcting
// one is a params edit, not code.
//
// host.isolate is deliberately absent: falcon-mcp 0.16.0 exposes no per-host
// containment tool, so it lives on the sibling native adapter (Adapter B),
// exactly the two-adapters-one-vendor split 11 §8 sanctions.
func describe() adapterplugin.DescribeResult {
	return adapterplugin.DescribeResult{
		Verbs: []capability.CapabilityDescriptor{
			{
				Verb:   "get_host_context",
				Intent: "Fetch Falcon device inventory context for a host (platform, agent, network, policies).",
				Inputs: []capability.InputParam{{Name: "host", Type: "entity", Required: true, Desc: "the hostname"}},
				Output: "device inventory context",
			},
			{
				Verb:   "enumerate_detections",
				Intent: "Retrieve Falcon detections for a host.",
				Inputs: []capability.InputParam{{Name: "host", Type: "entity", Required: true, Desc: "the hostname"}},
				Output: "detection findings",
			},
			{
				Verb:   "get_intel_context",
				Intent: "Fetch Falcon threat-intel context for an indicator (hash/IP/domain).",
				Inputs: []capability.InputParam{{Name: "indicator", Type: "entity", Required: true, Desc: "the indicator value"}},
				Output: "intel indicator matches",
			},
		},
		ActionTypes: []action.ActionDescriptor{
			{
				ActionType:    "ioc.block",
				Intent:        "Create a Falcon custom IOC with action=prevent (block the indicator).",
				Inputs:        []capability.InputParam{{Name: "indicator", Type: "entity", Required: true}},
				DefaultTier:   "T2",
				Reversibility: action.ReversibilityBestEffort,
				ReversibleBy:  "ioc.unblock",
			},
			{
				ActionType:    "ioc.unblock",
				Intent:        "Remove the Falcon custom IOC for an indicator — the inverse of ioc.block.",
				Inputs:        []capability.InputParam{{Name: "indicator", Type: "entity", Required: true}},
				DefaultTier:   "T2",
				Reversibility: action.ReversibilityBestEffort,
			},
		},
		Operations: []adapterplugin.OperationSchema{
			{Name: "search_hosts", Params: objSchema()},
			{Name: "get_host_details", Params: objSchema()},
			{Name: "search_detections", Params: objSchema()},
			{Name: "get_detection_details", Params: objSchema()},
			{Name: "search_indicators", Params: objSchema()},
			{Name: "add_ioc", Params: objSchema()},
			{Name: "remove_iocs", Params: objSchema()},
		},
		DefaultReadBindings: []adapterplugin.ReadBinding{
			// The host SCO carries the hostname at host.hostname (03 §4); the
			// template engine interpolates inside the FQL literal. LIVE-TUNE:
			// the FQL field names (hostname / device.hostname / indicator).
			{Verb: "get_host_context", Adapter: "crowdstrike-falcon", Operation: "search_hosts", Priority: 100,
				Params: map[string]any{"filter": "hostname:'${entity.host.hostname}'"}},
			{Verb: "enumerate_detections", Adapter: "crowdstrike-falcon", Operation: "search_detections", Priority: 100,
				Params: map[string]any{"filter": "device.hostname:'${entity.host.hostname}'"}},
			{Verb: "get_intel_context", Adapter: "crowdstrike-falcon", Operation: "search_indicators", Priority: 100,
				Params: map[string]any{"filter": "indicator:'${entity.value}'"}},
		},
		DefaultWriteBindings: []action.ActionBinding{
			{ActionType: "ioc.block", Adapter: "crowdstrike-falcon", Operation: "add_ioc",
				Params: map[string]any{"value": "${target.resolved_identifier}"}},
			{ActionType: "ioc.unblock", Adapter: "crowdstrike-falcon", Operation: "remove_iocs",
				Params: map[string]any{"value": "${target.resolved_identifier}"}},
		},
		ConfigSchema: map[string]any{
			"type":     "object",
			"required": []any{"client_id", "client_secret"},
			"properties": map[string]any{
				"client_id": map[string]any{
					"type":        "string",
					"description": "Falcon API client ID (OAuth2 client credentials)",
				},
				"client_secret": map[string]any{
					"type":        "string",
					"x-secret":    true,
					"description": "Falcon API client secret, given as a secret reference (keychain:// / env:// / vault://)",
				},
				"base_url": map[string]any{
					"type":        "string",
					"format":      "uri",
					"description": "Falcon API cloud base URL; defaults to https://api.crowdstrike.com (US-1)",
				},
				"member_cid": map[string]any{
					"type":        "string",
					"description": "Optional child (multi-tenant) CID this instance acts for (pairs with a source-scoped instance, 03 §3.5)",
				},
				"server_command": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Override the falcon-mcp launch command (default: the provisioned ./.venv/bin/falcon-mcp)",
				},
			},
		},
	}
}

func objSchema() map[string]any { return map[string]any{"type": "object"} }

// readOp maps a reckon read operation onto a falcon-mcp tool + its arguments.
// The operation names ARE the tool names; this whitelists the read tools the
// bridge serves (write tools go through dispatch, never invoke).
func readOp(operation string, params map[string]any) (tool string, args map[string]any, ok bool) {
	switch operation {
	case "search_hosts", "get_host_details", "search_detections", "get_detection_details", "search_indicators":
		if params == nil {
			params = map[string]any{}
		}
		return operation, params, true
	default:
		return "", nil, false
	}
}

func stringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
