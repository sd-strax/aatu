package main

import (
	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

// describe is the reckon surface this adapter serves (11 §4.2), per
// implementation/adapter-candidates.md §3 Adapter B: exactly the containment
// pair the vendor MCP does not expose. host.isolate is RELIABLY reversible by
// host.unisolate (lift_containment is a first-class platform operation), so a
// successful reversal marks the original REVERSED — unlike ioc.block's
// best-effort classification (04 §7.1).
func describe() adapterplugin.DescribeResult {
	return adapterplugin.DescribeResult{
		ActionTypes: []action.ActionDescriptor{
			{
				ActionType:    "host.isolate",
				Intent:        "Network-contain a host via Falcon (PerformActionV2 contain).",
				Inputs:        []capability.InputParam{{Name: "host", Type: "entity", Required: true, Desc: "the Falcon device id"}},
				DefaultTier:   "T2",
				Reversibility: action.ReversibilityReversible,
				ReversibleBy:  "host.unisolate",
			},
			{
				ActionType:    "host.unisolate",
				Intent:        "Lift Falcon network containment — the inverse of host.isolate.",
				Inputs:        []capability.InputParam{{Name: "host", Type: "entity", Required: true, Desc: "the Falcon device id"}},
				DefaultTier:   "T2",
				Reversibility: action.ReversibilityReversible,
				ReversibleBy:  "host.isolate",
			},
		},
		Operations: []adapterplugin.OperationSchema{
			{Name: "contain", Params: objSchema()},
			{Name: "lift_containment", Params: objSchema()},
		},
		DefaultWriteBindings: []action.ActionBinding{
			{ActionType: "host.isolate", Adapter: "crowdstrike-response", Operation: "contain",
				Params: map[string]any{"device_id": "${target.resolved_identifier}"}},
			{ActionType: "host.unisolate", Adapter: "crowdstrike-response", Operation: "lift_containment",
				Params: map[string]any{"device_id": "${target.resolved_identifier}"}},
		},
		ConfigSchema: map[string]any{
			"type":     "object",
			"required": []any{"client_id", "client_secret"},
			"properties": map[string]any{
				"client_id": map[string]any{
					"type":        "string",
					"description": "Falcon API client ID (OAuth2 client credentials; scope hosts:write)",
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
			},
		},
	}
}

func objSchema() map[string]any { return map[string]any{"type": "object"} }
