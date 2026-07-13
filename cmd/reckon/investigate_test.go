package main

import (
	"strings"
	"testing"

	"github.com/sd-strax/reckon/agent"
)

// TestPrettyJSON: valid JSON is indented; non-JSON (e.g. a plain error result)
// is returned unchanged rather than mangled — /raw must show error strings too.
func TestPrettyJSON(t *testing.T) {
	in := `{"verb":"enumerate_logons","coverage":"COMPLETE","events":[{"id":"e1"}]}`
	out := prettyJSON(in)
	if !strings.Contains(out, "\n") || !strings.Contains(out, `"coverage": "COMPLETE"`) {
		t.Errorf("expected indented JSON, got:\n%s", out)
	}

	notJSON := "tool dispatch failed: connection refused"
	if got := prettyJSON(notJSON); got != notJSON {
		t.Errorf("non-JSON content mangled: %q", got)
	}
}

// TestToolNames: distinct tool names from the last turn, in first-seen order,
// for /raw's "have: …" hint.
func TestToolNames(t *testing.T) {
	r := &repl{lastTools: []toolExchange{
		{name: "enumerate_logons"},
		{name: "get_network_connections"},
		{name: "enumerate_logons"}, // duplicate — collapsed
	}}
	got := strings.Join(r.toolNames(), ",")
	if got != "enumerate_logons,get_network_connections" {
		t.Errorf("toolNames = %q; want the two distinct verbs in order", got)
	}
}

// TestTargetList: the approval prompt prefers the resolved identifier and falls
// back to the entity ref; no targets renders a clear placeholder.
func TestTargetList(t *testing.T) {
	cases := []struct {
		name string
		in   []agent.ActionTarget
		want string
	}{
		{"resolved", []agent.ActionTarget{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-FILE01"}}, "WIN-FILE01"},
		{"fallback", []agent.ActionTarget{{EntityRef: "x-host--1"}}, "x-host--1"},
		{"multi", []agent.ActionTarget{{ResolvedIdentifier: "A"}, {ResolvedIdentifier: "B"}}, "A, B"},
		{"empty", nil, "(no targets)"},
	}
	for _, c := range cases {
		if got := targetList(c.in); got != c.want {
			t.Errorf("%s: targetList = %q; want %q", c.name, got, c.want)
		}
	}
}
