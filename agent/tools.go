package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
)

// maxToolResultBytes bounds a tool result fed back to the model. Fixture
// envelopes are small; the cap guards a future real adapter returning bulk.
const maxToolResultBytes = 64 << 10

// buildTools assembles the session's tool definitions: one tool per AVAILABLE
// capability verb (unavailable/degraded verbs are trimmed, 03 §6.3 — the model
// only sees what can currently resolve), plus the intrinsic tools.
func buildTools(caps []Capability) []ToolDef {
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
	return append(defs, intrinsicTools()...)
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

// intrinsicTools declares the reasoning + knowledge + action tools.
func intrinsicTools() []ToolDef {
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
			Description: "Propose a state-changing action (containment, remediation). It goes through authorization policy — you can propose, never approve; most proposals await the analyst's explicit approval. Cite evidence.",
			InputSchema: obj(map[string]any{
				"action_type": str("the action type, e.g. host.isolate, account.disable"),
				"targets": map[string]any{
					"type": "array",
					"items": obj(map[string]any{
						"entity_ref":          str("STIX id of the target entity"),
						"resolved_identifier": str("the concrete identifier the tool acts on (hostname, account id)"),
					}, "entity_ref", "resolved_identifier"),
					"description": "the distinct targets; blast radius drives the trust tier",
				},
				"parameters":    map[string]any{"type": "object", "description": "action-type-specific parameters, optional"},
				"evidence_refs": strList("refs grounding this action"),
				"rationale":     str("why this action, now"),
			}, "action_type", "targets", "rationale"),
		},
	}
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
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, fmt.Errorf("bad request_action input: %w", err)
		}
		resp, err := s.backend.RequestAction(ctx, ActionRequest{
			ActionType:       in.ActionType,
			Targets:          in.Targets,
			Parameters:       in.Parameters,
			EvidenceRefs:     in.EvidenceRefs,
			Rationale:        in.Rationale,
			InvestigationRef: s.investigationID,
		})
		if err != nil {
			return nil, err
		}
		s.pendingActions = append(s.pendingActions, resp)
		return json.Marshal(resp)

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
