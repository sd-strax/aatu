package main

import (
	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

// describe is the reckon surface this bridge serves (11 §4.2). The verbs/actions
// are candidates the engine reconciles into its catalog; tier and reversibility
// are CLAIMS only — the engine catalog is authoritative (§4.2), which is exactly
// why we can claim account.disable reversible_by account.enable even though this
// bridge does NOT serve account.enable (okta-mcp-server has no reactivate tool):
// the honest degradation is that a reversal finds no binding, not a false claim.
func describe() adapterplugin.DescribeResult {
	return adapterplugin.DescribeResult{
		Verbs: []capability.CapabilityDescriptor{
			{
				Verb:   "get_entity_context",
				Intent: "Fetch Okta identity context for a user (profile, status, groups).",
				Inputs: []capability.InputParam{{Name: "user", Type: "entity", Required: true, Desc: "the user login or id"}},
				Output: "user context",
			},
			{
				Verb:   "enumerate_logons",
				Intent: "Retrieve Okta authentication/system-log events for a user or window.",
				Inputs: []capability.InputParam{
					{Name: "user", Type: "entity", Required: false, Desc: "filter to this user"},
					{Name: "window", Type: "time_window", Required: false},
				},
				Output: "authentication events",
			},
		},
		ActionTypes: []action.ActionDescriptor{
			{
				ActionType:    "account.disable",
				Intent:        "Deactivate an Okta user account.",
				Inputs:        []capability.InputParam{{Name: "user", Type: "entity", Required: true}},
				DefaultTier:   "T2",
				Reversibility: action.ReversibilityReversible,
				ReversibleBy:  "account.enable",
			},
		},
		Operations: []adapterplugin.OperationSchema{
			{Name: "get_user", Params: objSchema()},
			{Name: "list_users", Params: objSchema()},
			{Name: "get_logs", Params: objSchema()},
			{Name: "list_groups", Params: objSchema()},
			{Name: "list_group_users", Params: objSchema()},
			{Name: "deactivate_user", Params: objSchema()},
		},
		DefaultReadBindings: []adapterplugin.ReadBinding{
			{Verb: "get_entity_context", Adapter: "okta", Operation: "get_user", Priority: 100, Params: map[string]any{"login": "${entity.user}"}},
			{Verb: "enumerate_logons", Adapter: "okta", Operation: "get_logs", Priority: 100, Params: map[string]any{"since": "${window.start?}", "q": "${entity.user??}"}},
		},
		DefaultWriteBindings: []action.ActionBinding{
			{ActionType: "account.disable", Adapter: "okta", Operation: "deactivate_user"},
		},
		ConfigSchema: map[string]any{
			"type":     "object",
			"required": []any{"org_url", "client_id"},
			"properties": map[string]any{
				"org_url":   map[string]any{"type": "string", "format": "uri", "description": "Okta org base URL, e.g. https://acme.okta.com"},
				"client_id": map[string]any{"type": "string", "description": "Client ID of the Okta app okta-mcp-server authenticates as"},
				"scopes":    map[string]any{"type": "string", "description": "Space-separated OKTA_SCOPES; defaults to the v0 read+users.manage set"},
				"server_command": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Override the okta-mcp-server launch command (default: uvx okta-mcp-server)",
				},
			},
		},
	}
}

func objSchema() map[string]any { return map[string]any{"type": "object"} }

// readOp maps a reckon read operation onto an okta-mcp tool + its arguments. The
// operation names ARE the tool names (the binding chooses the operation, and its
// templated params arrive as args); this whitelists the read tools this bridge
// serves and never exposes create/update/delete on the read path.
func readOp(operation string, params map[string]any) (tool string, args map[string]any, ok bool) {
	switch operation {
	case "get_user", "list_users", "get_logs", "list_groups", "list_group_users":
		if params == nil {
			params = map[string]any{}
		}
		return operation, params, true
	default:
		return "", nil, false
	}
}

// resolvedTarget extracts the frozen target identifier the engine resolved at
// request time (08 §4 — the adapter never re-resolves). Falls back to an
// explicit user_id/login in the templated params.
func resolvedTarget(params map[string]any) string {
	for _, k := range []string{"resolved_identifier", "user_id", "login", "user"} {
		if v, ok := params[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
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
