package action

import (
	"strings"
	"testing"
)

// TestValidateBindingParams: a binding referencing a param the descriptor does
// not declare is flagged (the servicenow short_description vs summary bug);
// a binding speaking the canonical vocabulary passes.
func TestValidateBindingParams(t *testing.T) {
	cat := DefaultActionCatalog()

	// The exact authoring bug: short_description is not a ticket.create input.
	bad := map[string][]ActionBinding{
		"ticket.create": {{
			ActionType: "ticket.create", Adapter: "servicenow", Operation: "create_incident",
			Params: map[string]any{
				"assignment_group":  "${target.resolved_identifier}",
				"short_description": "${parameters.short_description}",
			},
		}},
	}
	probs := ValidateBindingParams(bad, cat)
	if len(probs) != 1 || !strings.Contains(probs[0], "parameters.short_description") {
		t.Fatalf("want 1 problem naming short_description, got %v", probs)
	}

	// The fix: map the canonical inputs (summary/description) onto tool fields.
	good := map[string][]ActionBinding{
		"ticket.create": {{
			ActionType: "ticket.create", Adapter: "servicenow", Operation: "create_incident",
			Params: map[string]any{
				"assignment_group":  "${target.resolved_identifier}",
				"short_description": "${parameters.summary}",
				"description":       "${parameters.description?}",
				"urgency":           "${parameters.urgency ?? 3 - Low}",
			},
		}},
	}
	if probs := ValidateBindingParams(good, cat); len(probs) != 0 {
		t.Errorf("canonical binding should pass, got %v", probs)
	}

	// target.* refs are always available and never flagged.
	tgtOnly := map[string][]ActionBinding{
		"host.isolate": {{ActionType: "host.isolate", Adapter: "edr", Operation: "op",
			Params: map[string]any{"device_id": "${target.resolved_identifier}"}}},
	}
	if probs := ValidateBindingParams(tgtOnly, cat); len(probs) != 0 {
		t.Errorf("target-only binding should pass, got %v", probs)
	}
}
