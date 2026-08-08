package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Intrinsic tool names — the reasoning/action surface that exists regardless of
// tenant capability config. Capability verbs are appended per session from the
// live catalog (05 §3.4 step 2).
const (
	ToolRecallSOPs              = "recall_sops"
	ToolProposeHypothesis       = "propose_hypothesis"
	ToolRecordPrediction        = "record_prediction"
	ToolEvaluateHypothesis      = "evaluate_hypothesis"
	ToolRecordPredictionOutcome = "record_prediction_outcome"
	ToolRequestAction           = "request_action"
	ToolListActions             = "list_actions"
)

// maxToolResultBytes bounds a tool result fed back to the model. Fixture
// envelopes are small; the cap guards a future real adapter returning bulk.
const maxToolResultBytes = 64 << 10

// buildTools assembles the session's tool definitions: one tool per AVAILABLE
// capability verb (unavailable/degraded verbs are trimmed, 03 §6.3 — the model
// only sees what can currently resolve), plus the intrinsic tools. actionTypes
// is the write-side catalog (may be nil when the action layer is off); it shapes
// the request_action tool so the model picks a real action_type.
func buildTools(caps []Capability, actionTypes []ActionType) []ToolDef {
	var defs []ToolDef
	for _, c := range caps {
		if c.Status != "available" {
			continue
		}
		if c.Descriptor.Verb == "list_capabilities" {
			continue // the loop already trims the tool set; re-listing is not a model concern in v0
		}
		defs = append(defs, verbToolDef(c))
	}
	return append(defs, intrinsicTools(actionTypes)...)
}

// verbToolDef renders a capability descriptor as an LLM tool. Every verb tool
// shares the CallInput shape: an `entity` object the tenant's binding templates
// resolve against, an optional `window`, and the descriptor's scalar inputs as
// extra template roots.
func verbToolDef(c Capability) ToolDef {
	props := map[string]any{}
	var required []string
	for _, in := range c.Descriptor.Inputs {
		switch in.Type {
		case "entity":
			props["entity"] = map[string]any{
				"type": "object",
				"description": in.Desc + " — a typed entity object keyed by kind, " +
					`e.g. {"host":{"hostname":"WIN-FILE01"}}, {"user":{"name":"jdoe"}}, {"process":{"pid":4312}}`,
			}
			if in.Required {
				required = append(required, "entity")
			}
		case "time_window":
			props["window"] = map[string]any{
				"type": "object",
				"properties": map[string]any{
					"from": map[string]any{"type": "string", "format": "date-time"},
					"to":   map[string]any{"type": "string", "format": "date-time"},
				},
				"description": in.Desc,
			}
		default:
			props[in.Name] = map[string]any{"type": "string", "description": in.Desc}
			if in.Required {
				required = append(required, in.Name)
			}
		}
	}
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return ToolDef{
		Name:        c.Descriptor.Verb,
		Description: c.Descriptor.Intent + " Returns: " + c.Descriptor.Output + ".",
		InputSchema: schema,
	}
}

// intrinsicTools declares the reasoning + knowledge + action tools. actionTypes
// (may be nil) shapes the request_action tool from the frozen write catalog.
func intrinsicTools(actionTypes []ActionType) []ToolDef {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	strList := func(desc string) map[string]any {
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
	}
	obj := func(props map[string]any, required ...string) map[string]any {
		s := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			s["required"] = required
		}
		return s
	}
	return []ToolDef{
		{
			Name:        ToolRecallSOPs,
			Description: "Recall the tenant's standard operating procedures relevant to a question. EMPTY coverage is evidence of absence, not an error.",
			InputSchema: obj(map[string]any{
				"query": str("what guidance you are looking for"),
				"tags":  strList("hard filter on SOP tags, optional"),
			}, "query"),
		},
		{
			Name:        ToolProposeHypothesis,
			Description: "Propose a falsifiable hypothesis about what is happening. It is recorded PROPOSED until the analyst acknowledges it. Returns the hypothesis id for later predictions and evaluation.",
			InputSchema: obj(map[string]any{
				"statement":     str("the claim, one or two sentences, falsifiable"),
				"rationale":     str("why you believe this, citing evidence refs"),
				"labels":        strList("MITRE ATT&CK technique ids where evident, e.g. T1021.001"),
				"rooted_at_ref": str("STIX id of the anchor entity, optional"),
				"parent_ref":    str("x-hypothesis id this refines, optional"),
				"confidence":    str("HIGH | MEDIUM | LOW"),
			}, "statement", "rationale"),
		},
		{
			Name:        ToolRecordPrediction,
			Description: "Record a testable prediction under a hypothesis: what you expect to observe if it is true, and what query would test it.",
			InputSchema: obj(map[string]any{
				"hypothesis_ref": str("the x-hypothesis id"),
				"statement":      str("what should be observable if the hypothesis holds"),
				"rationale":      str("why this test discriminates"),
				"test_tool":      str("the verb/tool that would test it, optional"),
				"test_query":     str("the query text, optional"),
			}, "hypothesis_ref", "statement", "rationale"),
		},
		{
			Name:        ToolEvaluateHypothesis,
			Description: "Record an evidential outcome for a hypothesis: support, refutation, or inconclusive. Decisive outcomes must cite the observed evidence refs.",
			InputSchema: obj(map[string]any{
				"hypothesis_ref":   str("the x-hypothesis id"),
				"disposition":      str("support | refutation | inconclusive"),
				"rationale":        str("the evidential reasoning"),
				"test_result_refs": strList("STIX/OCSF refs of the observed evidence; required for support and refutation"),
				"abandoned":        map[string]any{"type": "boolean", "description": "on inconclusive: mark ABANDONED instead"},
				"confidence":       str("HIGH | MEDIUM | LOW"),
			}, "hypothesis_ref", "disposition", "rationale"),
		},
		{
			Name:        ToolRecordPredictionOutcome,
			Description: "Record a prediction's test outcome. CONFIRMED and DISCONFIRMED must cite test_result_refs.",
			InputSchema: obj(map[string]any{
				"prediction_ref":   str("the x-prediction id"),
				"status":           str("CONFIRMED | DISCONFIRMED | INCONCLUSIVE"),
				"rationale":        str("what was observed"),
				"test_result_refs": strList("refs of the observed evidence"),
			}, "prediction_ref", "status", "rationale"),
		},
		{
			Name:        ToolRequestAction,
			Description: requestActionDescription(actionTypes),
			InputSchema: obj(map[string]any{
				"action_type": actionTypeSchema(actionTypes),
				"targets": map[string]any{
					"type": "array",
					"items": obj(map[string]any{
						"entity_ref":          str("STIX id of the target entity"),
						"resolved_identifier": str("the concrete identifier the tool acts on (hostname, account id)"),
					}, "entity_ref", "resolved_identifier"),
					"description": "the distinct targets; blast radius drives the trust tier",
				},
				"parameters":    parametersSchema(actionTypes),
				"evidence_refs": strList("refs grounding this action"),
				"rationale":     str("why this action, now"),
				"retry_of":      str("when re-requesting a FAILED or EXPIRED action: that action's id (records the retry lineage)"),
			}, "action_type", "targets", "rationale"),
		},
		{
			Name:        ToolListActions,
			Description: "List this investigation's requested actions with their CURRENT engine status (REQUESTED = awaiting the analyst's approval in this surface; APPROVED/EXECUTING/SUCCEEDED/FAILED/REJECTED/EXPIRED/REVERSED). Use this for ground truth about whether an action was approved or executed — never assume. Each row carries a computed `expired` flag (and the result carries `now`): expired=true means the approval window elapsed and the engine will refuse an approve even though status may still read REQUESTED — such an action is dead; a new request is the only way forward.",
			InputSchema: obj(map[string]any{}),
		},
	}
}

// requestActionDescription renders the request_action tool description from the
// frozen write catalog: the fixed guidance plus, when the catalog is known, an
// enumerated list of the real action types with tier, reversibility, and current
// dispatchability. This is what stops the model guessing action_type strings
// (ip.block, firewall.block_ip, …) — it can read the actual vocabulary.
func requestActionDescription(actionTypes []ActionType) string {
	base := "Propose a state-changing action (containment, remediation). It goes through authorization policy — you can propose, never approve; most proposals await the analyst's explicit approval. Cite evidence."
	if len(actionTypes) == 0 {
		return base
	}
	var b strings.Builder
	b.WriteString(base)
	b.WriteString("\n\nValid action_type values (use one EXACTLY as written; never invent a name):")
	for _, a := range actionTypes {
		d := a.Descriptor
		fmt.Fprintf(&b, "\n- %s [%s, %s, %s]: %s",
			d.ActionType, d.DefaultTier, d.Reversibility, a.Status, d.Intent)
		// The declared parameter schema (08 §3): entity inputs ride `targets`;
		// the rest are the ONLY keys `parameters` accepts — the backend rejects
		// unknown keys and missing required ones at request time.
		if params := paramList(a); params != "" {
			fmt.Fprintf(&b, "\n  parameters: %s", params)
		}
	}
	b.WriteString("\n\nEach action's `parameters` object accepts exactly its listed parameter keys (targets carry the entities). If the action you need is not in this list, or is marked 'unavailable' (no tool is wired for it), do NOT request it — tell the analyst it must be performed manually.")
	return b.String()
}

// paramList renders an action type's non-entity inputs — the declared
// request_action.parameters vocabulary — as "name (required), name, …".
func paramList(a ActionType) string {
	var parts []string
	for _, in := range a.Descriptor.Inputs {
		if in.Type == "entity" {
			continue // satisfied via targets
		}
		p := in.Name
		if in.Required {
			p += " (required)"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}

// actionTypeSchema builds the action_type property. When the catalog is known it
// is a hard enum of the real types, so an invented name cannot even be emitted;
// otherwise it falls back to a free-text string (action layer off).
func actionTypeSchema(actionTypes []ActionType) map[string]any {
	if len(actionTypes) == 0 {
		return map[string]any{"type": "string", "description": "the action type, e.g. host.isolate, account.disable"}
	}
	// Only requestable types belong in the hard enum: an 'unavailable' type has
	// no tool wired (08 §3), so the description flags it as unrequestable — the
	// enum must not then permit it. This mirrors the read side, where buildTools
	// trims non-available verbs from the tool set entirely.
	enum := make([]string, 0, len(actionTypes))
	for _, a := range actionTypes {
		if a.Status == "unavailable" {
			continue
		}
		enum = append(enum, a.Descriptor.ActionType)
	}
	// If nothing is currently requestable, fall back to the full list rather than
	// emit an empty enum (which no value could satisfy) — the backend still
	// rejects an unwired dispatch honestly, and the description says as much.
	if len(enum) == 0 {
		for _, a := range actionTypes {
			enum = append(enum, a.Descriptor.ActionType)
		}
	}
	return map[string]any{
		"type":        "string",
		"enum":        enum,
		"description": "the action type — exactly one of the enumerated catalog values",
	}
}

// UnwrapStringifiedObject corrects a common model quirk: emitting a nested
// object field — request_action.parameters — as a STRINGIFIED JSON string
// (`"{\"summary\":...}"`) instead of a JSON object. When raw is a JSON string
// whose contents parse as a JSON object, it returns the unwrapped object bytes;
// otherwise it returns raw unchanged so the backend still validates the shape.
// This is the loop being liberal in what it accepts from the model (05 §3.4):
// a benign double-encoding must not cost a rejected action — or, against a real
// write adapter templating ${parameters.x}, a silently empty field. The eval
// harness applies the same normalization so H5 grades the request's substance
// (keys), not its encoding.
func UnwrapStringifiedObject(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || raw[0] != '"' {
		return raw
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return raw
	}
	trimmed := strings.TrimSpace(s)
	if !strings.HasPrefix(trimmed, "{") {
		return raw // a plain string, not a stringified object — leave it
	}
	// Decode the FIRST complete JSON object and tolerate trailing garbage: the
	// model sometimes appends a stray ']' or other junk after the object (a
	// real, repeated malformation that blocked every ticket create), which
	// json.Unmarshal rejects but a streaming decoder does not. Re-marshal the
	// clean object so the backend receives well-formed bytes.
	dec := json.NewDecoder(strings.NewReader(trimmed))
	var probe map[string]json.RawMessage
	if dec.Decode(&probe) != nil {
		return raw // not even a leading JSON object — let the backend reject honestly
	}
	clean, err := json.Marshal(probe)
	if err != nil {
		return raw
	}
	return json.RawMessage(clean)
}

// parametersSchema builds the request_action `parameters` property as a concrete
// object schema: the union of every action type's non-entity declared inputs
// (08 §3), each annotated with which action_type(s) use it. A bare
// {"type":"object"} with NO properties is precisely what leads a model to emit
// the field as a STRINGIFIED JSON blob (the H6 finding); giving it real
// properties makes the model fill a structured object instead. The union is
// deliberately permissive (the model picks action_type at call time, so a single
// schema cannot be per-type): the description tells it to include only its
// action's keys, and the backend enforces per-type required-ness + rejects
// unknown keys.
func parametersSchema(actionTypes []ActionType) map[string]any {
	props := map[string]any{}
	owners := map[string][]string{}
	for _, a := range actionTypes {
		for _, in := range a.Descriptor.Inputs {
			if in.Type == "entity" {
				continue // entity inputs ride `targets`, not `parameters`
			}
			if _, seen := props[in.Name]; !seen {
				props[in.Name] = map[string]any{"type": jsonSchemaType(in.Type), "description": in.Desc}
			}
			owners[in.Name] = appendUnique(owners[in.Name], a.Descriptor.ActionType)
		}
	}
	if len(props) == 0 {
		return map[string]any{"type": "object",
			"description": "Action-type-specific parameters as a JSON object (this catalog declares none)."}
	}
	for name := range props {
		pm := props[name].(map[string]any)
		usedBy := "used by: " + strings.Join(owners[name], ", ")
		if d := strings.TrimSpace(pm["description"].(string)); d != "" {
			pm["description"] = d + " (" + usedBy + ")"
		} else {
			pm["description"] = usedBy
		}
	}
	return map[string]any{
		"type":       "object",
		"properties": props,
		"description": "The action-type-specific parameters, as a JSON OBJECT — never a JSON string. " +
			"Include only the keys listed for your chosen action_type (see the tool description above); omit the others.",
	}
}

// jsonSchemaType maps an InputParam type to a JSON Schema scalar type, defaulting
// to string for anything non-scalar (entity inputs never reach here).
func jsonSchemaType(t string) string {
	switch t {
	case "string", "number", "integer", "boolean":
		return t
	default:
		return "string"
	}
}

// appendUnique appends v to s if absent, preserving order.
func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// dispatchTool executes one model-issued tool call against the backend and
// returns the result content to feed back. A backend rejection (4xx/5xx)
// becomes an isError result — the engine's explanation goes to the model, which
// can adjust; only transport-level failures abort the turn.
func (s *Session) dispatchTool(ctx context.Context, name string, input json.RawMessage) (string, bool) {
	out, err := s.dispatch(ctx, name, input)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			return apiErr.Body, true
		}
		return "tool dispatch failed: " + err.Error(), true
	}
	if len(out) > maxToolResultBytes {
		out = append(out[:maxToolResultBytes], []byte(`… [truncated]`)...)
	}
	return string(out), false
}

func (s *Session) dispatch(ctx context.Context, name string, input json.RawMessage) ([]byte, error) {
	switch name {
	case ToolRecallSOPs:
		var in struct {
			Query string   `json:"query"`
			Tags  []string `json:"tags"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("bad recall_sops input: %w", err)
		}
		body := map[string]any{"query": in.Query}
		if len(in.Tags) > 0 {
			body["tags"] = in.Tags
		}
		return s.backend.RecallSOPs(ctx, body)

	case ToolProposeHypothesis:
		var in struct {
			Statement   string   `json:"statement"`
			Rationale   string   `json:"rationale"`
			Labels      []string `json:"labels"`
			RootedAtRef string   `json:"rooted_at_ref"`
			ParentRef   string   `json:"parent_ref"`
			Confidence  string   `json:"confidence"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("bad propose_hypothesis input: %w", err)
		}
		resp, err := s.backend.RecordInterpretation(ctx, InterpretationRequest{
			InvestigationRef:   s.investigationID,
			InterpretationType: "hypothesis",
			Rationale:          clipRunes(in.Rationale, maxRationaleRunes),
			Confidence:         in.Confidence,
			Hypothesis: &Hypothesis{
				Statement:   in.Statement,
				ParentRef:   in.ParentRef,
				RootedAtRef: in.RootedAtRef,
				Labels:      in.Labels,
			},
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"hypothesis_ref": resp.NodeID, "status": "PROPOSED"})

	case ToolRecordPrediction:
		var in struct {
			HypothesisRef string `json:"hypothesis_ref"`
			Statement     string `json:"statement"`
			Rationale     string `json:"rationale"`
			TestTool      string `json:"test_tool"`
			TestQuery     string `json:"test_query"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("bad record_prediction input: %w", err)
		}
		pred := &Prediction{HypothesisRef: in.HypothesisRef, Statement: in.Statement}
		if in.TestTool != "" || in.TestQuery != "" {
			pred.TestQuery = &QuerySpec{Tool: in.TestTool, QueryText: in.TestQuery}
		}
		resp, err := s.backend.RecordInterpretation(ctx, InterpretationRequest{
			InvestigationRef:   s.investigationID,
			InterpretationType: "prediction",
			Rationale:          clipRunes(in.Rationale, maxRationaleRunes),
			Prediction:         pred,
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"prediction_ref": resp.NodeID, "status": "UNTESTED"})

	case ToolEvaluateHypothesis:
		var in struct {
			HypothesisRef  string   `json:"hypothesis_ref"`
			Disposition    string   `json:"disposition"`
			Rationale      string   `json:"rationale"`
			TestResultRefs []string `json:"test_result_refs"`
			Abandoned      bool     `json:"abandoned"`
			Confidence     string   `json:"confidence"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("bad evaluate_hypothesis input: %w", err)
		}
		resp, err := s.backend.RecordInterpretation(ctx, InterpretationRequest{
			InvestigationRef:   s.investigationID,
			InterpretationType: in.Disposition, // support | refutation | inconclusive — the aggregate validates
			Rationale:          clipRunes(in.Rationale, maxRationaleRunes),
			Confidence:         in.Confidence,
			HypothesisRef:      in.HypothesisRef,
			Abandoned:          in.Abandoned,
			TestResultRefs:     in.TestResultRefs,
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"interpretation_id": resp.InterpretationID})

	case ToolRecordPredictionOutcome:
		var in struct {
			PredictionRef  string   `json:"prediction_ref"`
			Status         string   `json:"status"`
			Rationale      string   `json:"rationale"`
			TestResultRefs []string `json:"test_result_refs"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("bad record_prediction_outcome input: %w", err)
		}
		resp, err := s.backend.RecordInterpretation(ctx, InterpretationRequest{
			InvestigationRef:   s.investigationID,
			InterpretationType: "prediction",
			Rationale:          clipRunes(in.Rationale, maxRationaleRunes),
			PredictionRef:      in.PredictionRef,
			PredictionStatus:   in.Status,
			TestResultRefs:     in.TestResultRefs,
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"interpretation_id": resp.InterpretationID})

	case ToolRequestAction:
		var in struct {
			ActionType   string          `json:"action_type"`
			Targets      []ActionTarget  `json:"targets"`
			Parameters   json.RawMessage `json:"parameters"`
			EvidenceRefs []string        `json:"evidence_refs"`
			Rationale    string          `json:"rationale"`
			RetryOf      string          `json:"retry_of"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("bad request_action input: %w", err)
		}
		resp, err := s.backend.RequestAction(ctx, ActionRequest{
			ActionType:       in.ActionType,
			Targets:          in.Targets,
			Parameters:       UnwrapStringifiedObject(in.Parameters),
			EvidenceRefs:     in.EvidenceRefs,
			Rationale:        in.Rationale,
			InvestigationRef: s.investigationID,
			RetryOf:          in.RetryOf,
		})
		if err != nil {
			return nil, err
		}
		s.pendingActions = append(s.pendingActions, resp)
		return json.Marshal(resp)

	case ToolListActions:
		acts, err := s.backend.ListActions(ctx, s.investigationID)
		if err != nil {
			return nil, err
		}
		// The model has no clock: it cannot compare expires_at to "now", so a
		// lazily-expired action (status still REQUESTED, 04) would read as
		// live. The engine answers the question instead — a computed expired
		// flag per action, plus now for grounding.
		now := time.Now().UTC()
		type actionView struct {
			ActionStatus
			Expired bool `json:"expired"`
		}
		views := make([]actionView, 0, len(acts))
		for _, a := range acts {
			views = append(views, actionView{ActionStatus: a, Expired: a.Expired(now)})
		}
		return json.Marshal(map[string]any{
			"now":     now.Format(time.RFC3339),
			"actions": views,
		})

	default:
		// A capability verb.
		var in struct {
			Entity map[string]any `json:"entity"`
			Window *struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"window"`
		}
		// Decode twice: once for the typed roots, once for the extras.
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("bad %s input: %w", name, err)
		}
		var all map[string]json.RawMessage
		_ = json.Unmarshal(input, &all)
		extra := map[string]any{}
		for k, v := range all {
			if k == "entity" || k == "window" {
				continue
			}
			var val any
			if err := json.Unmarshal(v, &val); err == nil {
				extra[k] = val
			}
		}
		call := InvokeInput{Entity: in.Entity}
		if len(extra) > 0 {
			call.Extra = extra
		}
		if in.Window != nil {
			w := &Window{}
			if t, err := time.Parse(time.RFC3339, in.Window.From); err == nil {
				w.From = t
			}
			if t, err := time.Parse(time.RFC3339, in.Window.To); err == nil {
				w.To = t
			}
			call.Window = w
		}
		return s.backend.InvokeCapability(ctx, name, call)
	}
}
