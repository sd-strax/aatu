// Package eval is the agent behavioral evaluation harness (design/10). It
// drives the shipped agent.Session through deterministic scenario scripts
// against a running local stack, then grades the COMMITTED turn records — the
// transcript bytes the product content-hashed into the side store and the
// event-log views read back through the API — against the assertion catalogue.
//
// The harness is engineering infrastructure, not a product surface (10 §0). It
// adds no capture path: graders read what an auditor would pull (10 §1.1).
// Runs cost real tokens and are explicitly invoked (`make eval`), never part
// of -short or `make ci` (10 §1.5).
package eval

import "strings"

// TurnRecord is one analyst turn of one trial: the driver's input and the
// committed record it produced. Transcript is byte-identical to the side-store
// bytes (agent.TurnResult contract): Session.Turn fails when the commit fails,
// so a record with a non-empty InterpretationID is the persisted truth.
type TurnRecord struct {
	Index            int        `json:"index"`
	UserMsg          string     `json:"user_msg"`
	Text             string     `json:"text"` // final assistant text
	Transcript       string     `json:"transcript"`
	ToolCalls        []ToolCall `json:"tool_calls,omitempty"`
	InterpretationID string     `json:"interpretation_id,omitempty"`
	ToolRounds       int        `json:"tool_rounds"`
	Err              string     `json:"err,omitempty"` // turn-level failure (model call, commit)
}

// ToolCall mirrors the committed tool-call log entry (agent.ToolCall) without
// importing the agent package into grader unit tests' synthetic records.
type ToolCall struct {
	ToolName string `json:"tool_name"`
	Args     string `json:"args,omitempty"`
}

// ParamSpec is one declared parameter of an action type (the non-entity slice
// of the descriptor's Inputs, 08 §3).
type ParamSpec struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

// TrialRecord is one full scripted conversation (10 §2): the per-turn records
// plus the context graders need (the action vocabulary the session saw).
type TrialRecord struct {
	Trial           int          `json:"trial"`
	InvestigationID string       `json:"investigation_id"`
	Turns           []TurnRecord `json:"turns"`
	// ActionCatalog is the action_type vocabulary the backend served at session
	// build — H3's ground truth.
	ActionCatalog []string `json:"action_catalog,omitempty"`
	// ActionInputs is each action type's declared non-entity parameter schema
	// (08 §3) as served by the backend — H5's ground truth.
	ActionInputs map[string][]ParamSpec `json:"action_inputs,omitempty"`
	// Aborted is set when the trial stopped before completing its script (a
	// turn-level error); unreached turn-scoped assertions grade NOT_EXERCISED.
	Aborted bool `json:"aborted,omitempty"`
}

// transcriptEvent is one parsed line of the committed transcript. The framing
// is the line format Session.Turn writes ([user] / [assistant] /
// [tool_use NAME id=ID] / [tool_result NAME id=ID error=BOOL] / [loop]);
// sanitizeTranscript guarantees embedded content cannot forge a frame line, so
// line-oriented parsing is sound.
type transcriptEvent struct {
	Kind    string // "user" | "assistant" | "tool_use" | "tool_result" | "loop"
	Tool    string // tool name, for tool_use / tool_result
	IsError bool   // tool_result only
	Content string // the payload after the frame
}

// parseTranscript splits a committed transcript body into ordered events.
// Unrecognized lines are ignored (forward compatibility with new frames).
func parseTranscript(body string) []transcriptEvent {
	var events []transcriptEvent
	for _, line := range strings.Split(body, "\n") {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "[user] "):
			events = append(events, transcriptEvent{Kind: "user", Content: line[len("[user] "):]})
		case strings.HasPrefix(line, "[assistant] "):
			events = append(events, transcriptEvent{Kind: "assistant", Content: line[len("[assistant] "):]})
		case strings.HasPrefix(line, "[tool_use "):
			ev, ok := parseToolFrame(line, "[tool_use ")
			if ok {
				events = append(events, ev)
			}
		case strings.HasPrefix(line, "[tool_result "):
			ev, ok := parseToolFrame(line, "[tool_result ")
			if ok {
				events = append(events, ev)
			}
		case strings.HasPrefix(line, "[loop] "):
			events = append(events, transcriptEvent{Kind: "loop", Content: line[len("[loop] "):]})
		}
	}
	return events
}

// parseToolFrame decodes "[tool_use NAME id=ID] args" and
// "[tool_result NAME id=ID error=BOOL] content" lines.
func parseToolFrame(line, prefix string) (transcriptEvent, bool) {
	rest := line[len(prefix):]
	end := strings.Index(rest, "] ")
	if end < 0 {
		return transcriptEvent{}, false
	}
	header, content := rest[:end], rest[end+2:]
	fields := strings.Fields(header)
	if len(fields) == 0 {
		return transcriptEvent{}, false
	}
	ev := transcriptEvent{
		Kind:    strings.TrimSuffix(strings.TrimPrefix(prefix, "["), " "),
		Tool:    fields[0],
		Content: content,
	}
	for _, f := range fields[1:] {
		if f == "error=true" {
			ev.IsError = true
		}
	}
	return ev, true
}
