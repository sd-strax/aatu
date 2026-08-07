package main

import (
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

// describe is the reckon surface this bridge serves (11 §4.2). GreyNoise is
// read-only threat-intel enrichment: it contributes the get_indicator_context
// verb (03 §3) and no action types. The engine reconciles the verb into its
// catalog (it is already a DefaultCatalog verb) and owns tier/coverage.
//
// The operation names ARE the greynoise-mcp tool names (readOp whitelists them).
// NOTE (validate live, 11 §3): these tool names are the vendor server's; confirm
// with `reckon adapter mcp-probe greynoise` and correct here if they differ.
func describe() adapterplugin.DescribeResult {
	return adapterplugin.DescribeResult{
		Verbs: []capability.CapabilityDescriptor{
			{
				Verb:   "get_indicator_context",
				Intent: "Fetch GreyNoise reputation for an IP (classification, noise/RIOT, actor, tags).",
				Inputs: []capability.InputParam{{Name: "indicator", Type: "entity", Required: true, Desc: "the IP address to enrich"}},
				Output: "indicator reputation + threat-intel matches",
			},
		},
		Operations: []adapterplugin.OperationSchema{
			{Name: "ip_context", Params: objSchema()},
			{Name: "riot", Params: objSchema()},
			{Name: "gnql_query", Params: objSchema()},
		},
		DefaultReadBindings: []adapterplugin.ReadBinding{
			// The indicator SCO carries the IP in `value` (03 §4 ipv4-addr). Only
			// applicable to an IP indicator; a domain/hash indicator finds no
			// applicable binding and degrades honestly (§6.1).
			{Verb: "get_indicator_context", Adapter: "greynoise", Operation: "ip_context", Priority: 100, Params: map[string]any{"ip": "${entity.value}"}},
		},
		ConfigSchema: map[string]any{
			"type":     "object",
			"required": []any{"api_key"},
			"properties": map[string]any{
				"api_key": map[string]any{
					"type":        "string",
					"x-secret":    true,
					"description": "GreyNoise API key, delivered as an x-secret reference (keychain:// / env:// / vault://); the host resolves it before configure",
				},
				"server_command": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Override the greynoise-mcp-server launch command (default: the provisioned ./.venv/bin/greynoise-mcp-server)",
				},
			},
		},
	}
}

func objSchema() map[string]any { return map[string]any{"type": "object"} }

// readOp maps a reckon read operation onto a greynoise-mcp tool + its arguments.
// The operation names ARE the tool names (the binding chooses the operation and
// its templated params arrive as args); this whitelists the read tools the
// bridge serves.
func readOp(operation string, params map[string]any) (tool string, args map[string]any, ok bool) {
	switch operation {
	case "ip_context", "riot", "gnql_query":
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
