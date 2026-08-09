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
		// Read surface (03 §2.9): the external-case verbs read the incident table
		// back as class-2005 Incident Findings. These literals mirror the engine's
		// DefaultCatalog entries (capability/descriptor.go) — the descriptors are
		// candidates the engine reconciles into its catalog (§4.2).
		Verbs: []capability.CapabilityDescriptor{
			{
				Verb:   "query_external_cases",
				Intent: "Search the case management system of record (ServiceNow, Jira SOC, TheHive) for cases matching a filter — the read side of 'have we seen this before?'.",
				Inputs: []capability.InputParam{
					{Name: "filter", Type: "string", Required: false, Desc: "free-text query over case title/summary"},
					{Name: "status", Type: "string", Required: false, Desc: "case status filter, e.g. 'In Progress'"},
					{Name: "window", Type: "time_window", Required: false, Desc: "time bound; defaults to the tenant investigation window"},
					{Name: "limit", Type: "int", Required: false, Desc: "max cases to return (default 50)"},
				},
				Output: "list<observed_data>",
			},
			{
				Verb:   "get_external_case_details",
				Intent: "Fetch full content for one case in the SoR (title, status, summary, link) — a follow-up after query_external_cases returns hits worth deep-diving.",
				Inputs: []capability.InputParam{{Name: "case_id", Type: "string", Required: true, Desc: "the case id/number, e.g. INC0010042 or a sys_id"}},
				Output: "observed_data",
			},
		},
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
			{Name: "get_incident", Params: objSchema()},
			{Name: "query_incidents", Params: objSchema()},
		},
		DefaultReadBindings: []adapterplugin.ReadBinding{
			// BINDING VOCABULARY (critical, 03 §3.3): the LEFT side is the ADAPTER's
			// operation param name (what caseToOcsf/invoke reads); the ${...} RIGHT
			// side is the ENGINE's read-call input root (CallInput.Extra keys /
			// entity / window), templated by the resolver. get_external_case_details's
			// declared input is `case_id`; query_external_cases's are
			// `filter`/`status`/`limit`. Optional inputs are marked `?` so a missing
			// one OMITS the param rather than rejecting the binding (§3.3.4).
			{Verb: "get_external_case_details", Adapter: "servicenow", Operation: "get_incident", Priority: bindingPriority,
				Params: map[string]any{"case_id": "${case_id}"}},
			{Verb: "query_external_cases", Adapter: "servicenow", Operation: "query_incidents", Priority: bindingPriority,
				Params: map[string]any{
					"filter": "${filter?}",
					"status": "${status?}",
					"limit":  "${limit?}",
				}},
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
