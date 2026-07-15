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

// TestTargetList_NeutralizesControlBytes: a model-supplied resolved_identifier
// carrying ANSI/CR cannot reach the terminal verbatim at the approval gate — the
// deception vector (render a benign host while dispatching against another).
func TestTargetList_NeutralizesControlBytes(t *testing.T) {
	// "dc-01.corp.local" + CR + ANSI erase-line + "test-sandbox-vm": on a raw
	// terminal the CR/erase would overwrite the real target with the fake one.
	evil := "dc-01.corp.local\r\x1b[Ktest-sandbox-vm"
	got := targetList([]agent.ActionTarget{{ResolvedIdentifier: evil}})
	if strings.ContainsAny(got, "\r\x1b") {
		t.Fatalf("control bytes survived to the terminal: %q", got)
	}
	// The real identifier is still visible (just escaped), so nothing is hidden.
	if !strings.Contains(got, "dc-01.corp.local") || !strings.Contains(got, "test-sandbox-vm") {
		t.Errorf("sanitized identifier lost content: %q", got)
	}
}

// TestSanitizeTerminal: control bytes become visible escapes on a single line;
// the block variant keeps newlines/tabs (JSON layout) but still kills cursor
// control; clean text is untouched (and not reallocated needlessly).
func TestSanitizeTerminal(t *testing.T) {
	if got := sanitizeTerminal("clean host-01"); got != "clean host-01" {
		t.Errorf("clean text changed: %q", got)
	}
	if got := sanitizeTerminal("a\x1b[2Kb\nc"); strings.ContainsAny(got, "\x1b\n") {
		t.Errorf("single-line sanitize left control bytes: %q", got)
	}
	// Block variant: newline/tab preserved, ESC neutralized.
	block := sanitizeTerminalBlock("{\n\t\"k\": \"v\x1b[31m\"\n}")
	if !strings.Contains(block, "\n") || !strings.Contains(block, "\t") {
		t.Errorf("block sanitize dropped layout: %q", block)
	}
	if strings.ContainsRune(block, '\x1b') {
		t.Errorf("block sanitize left an ESC: %q", block)
	}
}
