package main

import (
	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

// describe is the reckon surface this adapter serves (11 §4.2): the ticketing
// family bound onto the ServiceNow Table API. Every ticket action is
// IRREVERSIBLE (04 §2.2) — the incident record is permanent, and ticket.close
// is a forward transition, never a reversal of ticket.create. The engine, not
// the adapter, is the authority on tier/reversibility (11 §4.2); these
// descriptors state the FACTS (which ops exist, their inputs) and let the
// engine's own catalog (action/descriptor.go) classify.
//
// resolved_identifier means different things per action, per 04 §2 / 08 §4:
//   - ticket.create targets the DESTINATION queue (assignment_group)
//   - ticket.comment / .transition / .close target the incident itself
//     (sys_id or number — the adapter resolves a number to its sys_id).
func describe() adapterplugin.DescribeResult {
	return adapterplugin.DescribeResult{
		ActionTypes: []action.ActionDescriptor{
			{
				ActionType: "ticket.create",
				Intent:     "Open a ServiceNow incident — the operational-handoff vehicle. Target the destination assignment group (resolved_identifier); the entities the ticket concerns go in evidence_refs, not targets.",
				Inputs: []capability.InputParam{
					{Name: "assignment_group", Type: "entity", Required: true, Desc: "destination assignment group (sys_id or name) the incident is routed to — the action target"},
					{Name: "summary", Type: "string", Required: true, Desc: "one-line incident summary (→ ServiceNow short_description)"},
					{Name: "description", Type: "string", Required: false, Desc: "full incident body"},
					{Name: "assignee", Type: "string", Required: false, Desc: "user to assign (→ assigned_to)"},
					{Name: "urgency", Type: "string", Required: false, Desc: "ServiceNow urgency label, e.g. '1 - High' / '2 - Medium' / '3 - Low'; defaults to '3 - Low'"},
				},
				DefaultTier:   "T2",
				Reversibility: action.ReversibilityIrreversible,
			},
			{
				ActionType: "ticket.comment",
				Intent:     "Add a work note to an existing ServiceNow incident. Target the incident (resolved_identifier = sys_id or number).",
				Inputs: []capability.InputParam{
					{Name: "ticket", Type: "entity", Required: true, Desc: "the incident sys_id or number (e.g. INC0010042)"},
					{Name: "body", Type: "string", Required: true, Desc: "the work note text (→ work_notes)"},
				},
				DefaultTier:   "T2",
				Reversibility: action.ReversibilityIrreversible,
			},
			{
				ActionType: "ticket.transition",
				Intent:     "Move a ServiceNow incident to another workflow state. Target the incident (resolved_identifier = sys_id or number).",
				Inputs: []capability.InputParam{
					{Name: "ticket", Type: "entity", Required: true, Desc: "the incident sys_id or number"},
					{Name: "to_status", Type: "string", Required: true, Desc: "target ServiceNow state label, e.g. 'In Progress' / 'On Hold' (→ state)"},
				},
				DefaultTier:   "T2",
				Reversibility: action.ReversibilityIrreversible,
			},
			{
				ActionType: "ticket.close",
				Intent:     "Close a ServiceNow incident (state 7) — a forward transition, not a reversal of ticket.create. Target the incident (resolved_identifier = sys_id or number).",
				Inputs: []capability.InputParam{
					{Name: "ticket", Type: "entity", Required: true, Desc: "the incident sys_id or number"},
					{Name: "resolution", Type: "string", Required: false, Desc: "resolution notes (→ close_notes); defaults to a reckon marker"},
				},
				DefaultTier:   "T2",
				Reversibility: action.ReversibilityIrreversible,
			},
		},
		Operations: []adapterplugin.OperationSchema{
			{Name: "create_incident", Params: objSchema()},
			{Name: "add_comment", Params: objSchema()},
			{Name: "set_state", Params: objSchema()},
			{Name: "close_incident", Params: objSchema()},
		},
		DefaultWriteBindings: []action.ActionBinding{
			// Params map the ENGINE's canonical ticket vocabulary (04 §2 catalog:
			// summary/description/body/to_status/resolution — what the agent sends)
			// onto ServiceNow's incident fields. A required engine input maps with
			// no default (a missing one correctly makes servicenow inapplicable);
			// an optional input is marked `?` so a missing value OMITS the field
			// rather than rejecting the whole binding (§3.3.4).
			{ActionType: "ticket.create", Adapter: "servicenow", Operation: "create_incident", Priority: bindingPriority,
				Params: map[string]any{
					"assignment_group":  "${target.resolved_identifier}",
					"short_description": "${parameters.summary}",
					"description":       "${parameters.description?}",
					"assigned_to":       "${parameters.assignee?}",
					"urgency":           "${parameters.urgency ?? 3 - Low}",
				}},
			{ActionType: "ticket.comment", Adapter: "servicenow", Operation: "add_comment", Priority: bindingPriority,
				Params: map[string]any{
					"ticket":     "${target.resolved_identifier}",
					"work_notes": "${parameters.body}",
				}},
			{ActionType: "ticket.transition", Adapter: "servicenow", Operation: "set_state", Priority: bindingPriority,
				Params: map[string]any{
					"ticket": "${target.resolved_identifier}",
					"state":  "${parameters.to_status}",
				}},
			{ActionType: "ticket.close", Adapter: "servicenow", Operation: "close_incident", Priority: bindingPriority,
				Params: map[string]any{
					"ticket":      "${target.resolved_identifier}",
					"close_notes": "${parameters.resolution ?? Closed by reckon}",
				}},
		},
		ConfigSchema: map[string]any{
			"type":     "object",
			"required": []any{"instance_url", "username", "password"},
			"properties": map[string]any{
				"instance_url": map[string]any{
					"type":        "string",
					"format":      "uri",
					"description": "ServiceNow instance base URL, e.g. https://dev12345.service-now.com",
				},
				"username": map[string]any{
					"type":        "string",
					"description": "ServiceNow user for Basic auth (needs write on the incident table, e.g. the itil role). Use a dedicated integration user (Identity type Machine, no MFA) — an MFA-enabled user (the PDI admin default) cannot Basic-auth to the REST API",
				},
				"password": map[string]any{
					"type":        "string",
					"x-secret":    true,
					"description": "ServiceNow password, given as a secret reference (keychain:// / env:// / vault://)",
				},
				"table": map[string]any{
					"type":        "string",
					"description": "Table the ticketing family writes to; defaults to 'incident'",
				},
			},
		},
	}
}

// bindingPriority is the default priority of the ticketing bindings this adapter
// suggests. It sits deliberately above the bundled demo fixture_write bindings
// (priority 100) so that when servicenow is enabled into a config that already
// carries the fixture ticketing demo, the real system of record wins the
// highest-priority-binding selection (08 §4) — the fixture stays as the
// safety fallback only if servicenow is disabled/unconfigured (resolver.go).
const bindingPriority = 200

func objSchema() map[string]any { return map[string]any{"type": "object"} }
