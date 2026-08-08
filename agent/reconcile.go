package agent

import (
	"context"
	"regexp"
	"strings"
)

// actionIDRe matches a full UUID as the model prints it when "confirming" an
// action_id — the exact shape it has fabricated (1f7c8fce-…, 7c3e0f9b-…) and
// misreported (a FAILED action narrated as REQUESTED).
var actionIDRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// reconcileActionClaims returns an engine-authored ground-truth line stating
// the REAL status of every action_id the model's final text cites (or "not on
// record" when the id does not exist). It is a DETERMINISTIC backstop to the
// system-prompt honesty rules, which have proven insufficient: the model
// fabricates action_ids and misreports statuses even when explicitly asked to
// reconcile against ground truth. Stating the truth beside the model's prose —
// and carrying it into the model's own history next turn — corrects the record
// the analyst reads and counters the narrative-consistency drift that makes the
// model compound its own earlier claims.
//
// Empty when the text cites no action_ids, or the engine can't be read (never
// assert what we can't verify). Deterministic — no NLP on the model's prose;
// it simply reports the authoritative status for each id mentioned.
func (s *Session) reconcileActionClaims(ctx context.Context, finalText string) string {
	cited := dedupeLower(actionIDRe.FindAllString(finalText, -1))
	if len(cited) == 0 {
		return ""
	}
	acts, err := s.backend.ListActions(ctx, s.investigationID)
	if err != nil {
		return "" // cannot verify — say nothing rather than assert
	}
	status := make(map[string]string, len(acts))
	for _, a := range acts {
		status[strings.ToLower(a.ActionID)] = a.Status
	}
	parts := make([]string, 0, len(cited))
	for _, id := range cited {
		if st, ok := status[id]; ok {
			parts = append(parts, id[:8]+"="+st)
		} else {
			parts = append(parts, id[:8]+"=NOT ON RECORD")
		}
	}
	return "[engine record — authoritative, verified against the action log: " +
		strings.Join(parts, ", ") + "]"
}

func dedupeLower(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		l := strings.ToLower(s)
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}
