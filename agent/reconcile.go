package agent

import (
	"context"
	"fmt"
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

// anchorEveryTurns is how often the engine-state anchor rides a user message
// (and a ResetContext forces it on the very next turn). Frequent enough to
// counter narrative drift in a long conversation, rare enough not to bloat
// every turn.
const anchorEveryTurns = 5

// creationClaimRe spots prose claiming an action/ticket was created or queued.
// Deliberately generous: it only gates whether the (always-true) attestation is
// APPENDED, so a false positive costs a redundant true sentence, never a wrong
// one.
var creationClaimRe = regexp.MustCompile(`(?is)\b(creat\w*|queu\w*|fil\w*|request\w*|open\w*)\b[^.!?]{0,80}\b(ticket|action|incident|isolat\w*|notification)\b|\b(ticket|action|incident)\b[^.!?]{0,80}\b(creat\w*|queu\w*|fil\w*|request\w*|open\w*)\b`)

// noActionAttestation returns the engine's attestation when the model's final
// text claims a creation but NO request_action succeeded this turn — the
// confabulation observed in practice (the model narrating "created and
// verified" on a turn with zero tool calls). Deterministic: it states a fact
// the loop's own bookkeeping guarantees. Empty when an action really was
// requested or no creation claim appears.
func noActionAttestation(finalText string, actionsRequestedThisTurn int) string {
	if actionsRequestedThisTurn > 0 {
		return ""
	}
	if !creationClaimRe.MatchString(finalText) {
		return ""
	}
	return "[engine record: NO action was requested this turn — any claim above of a new ticket/action is unconfirmed]"
}

// turnFooter combines the deterministic ground-truth corrections for one turn:
// the real status of every cited action_id, and the no-action attestation when
// a creation claim has no matching request_action. Empty when nothing needs
// saying.
func (s *Session) turnFooter(ctx context.Context, finalText string, actionsRequestedThisTurn int) string {
	parts := make([]string, 0, 2)
	if gt := s.reconcileActionClaims(ctx, finalText); gt != "" {
		parts = append(parts, gt)
	}
	if at := noActionAttestation(finalText, actionsRequestedThisTurn); at != "" {
		parts = append(parts, at)
	}
	return strings.Join(parts, "\n")
}

// engineStateAnchor renders the compact authoritative action record for the
// periodic re-grounding anchor. Empty when the investigation has no actions or
// the engine can't be read.
func (s *Session) engineStateAnchor(ctx context.Context) string {
	acts, err := s.backend.ListActions(ctx, s.investigationID)
	if err != nil || len(acts) == 0 {
		return ""
	}
	rows := make([]string, 0, len(acts))
	pending := 0
	for _, a := range acts {
		if a.Pending() {
			pending++
		}
		id := a.ActionID
		if len(id) > 8 {
			id = id[:8]
		}
		rows = append(rows, id+" "+a.ActionType+"="+a.Status)
	}
	return fmt.Sprintf("[engine state — the authoritative action record for this investigation (trust THIS over any earlier narration): %s; %d awaiting approval]",
		strings.Join(rows, ", "), pending)
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
