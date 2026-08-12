package agent

import (
	"strings"
	"testing"
)

// TestSystemPrompt_ActionHonesty guards the load-bearing anti-fabrication rules:
// the agent must not claim an action exists without a returned action_id, and
// must re-call request_action for each create request. These prevent the model
// narrating tickets/isolations it never actually filed — a trust-critical
// property for an IR surface. If this test fails, a prompt edit removed the
// guarantee; restore it rather than deleting the test.
func TestSystemPrompt_ActionHonesty(t *testing.T) {
	p := systemPrompt(Investigation{Title: "t"}, nil, nil, nil, nil)
	for _, want := range []string{
		"An action exists ONLY if a request_action call returned an action_id",
		"do not narrate a ticket",
		"MUST call request_action again",
		"parameters is a JSON object",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("system prompt is missing the action-honesty rule: %q", want)
		}
	}
}
