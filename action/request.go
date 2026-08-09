package action

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
)

// DefaultBlastRadiusThreshold is the default T2→T3 escalator threshold (04 §1):
// a T2 action targeting more than this many distinct entities is promoted to
// T3. Non-negotiable in code — adjustable per action class, never disableable.
const DefaultBlastRadiusThreshold = 10

// ActionRequest is a request_action tool call (08 §2), the agent-facing shape.
type ActionRequest struct {
	ActionType       string                 `json:"action_type"`
	Targets          []aggregate.TargetSpec `json:"targets"`
	Parameters       json.RawMessage        `json:"parameters,omitempty"`
	EvidenceRefs     []string               `json:"evidence_refs,omitempty"`
	Rationale        string                 `json:"rationale"`
	InvestigationRef uuid.UUID              `json:"investigation_ref"`
	// ReversalOfRef, when set, makes this a reversal of that original x-action
	// (04 §7): IsReversal is implied, and the endpoint triggers the ReversalSaga
	// instead of a plain ActionLifecycle on auto-approval.
	ReversalOfRef uuid.UUID `json:"reversal_of_ref,omitempty"`
	// RetryOf, when set, records lineage to the prior FAILED/EXPIRED x-action
	// this request replaces (a retry IS a new action — the dispatch ledger
	// forbids re-dispatching one id).
	RetryOf uuid.UUID `json:"retry_of,omitempty"`
	// TTL bounds how long the request stays pending before ActionExpired; 0
	// applies DefaultRequestTTL.
	TTL time.Duration `json:"-"`
}

// DefaultRequestTTL is how long a pending action stays open before expiring.
const DefaultRequestTTL = 30 * time.Minute

// BuildRequestCommand validates a request_action against the catalog and builds
// the aggregate.RequestAction command that creates the x-action in REQUESTED
// (08 §2). The AI may call this — it sets no Authorization and cannot advance
// status; that write-protection lives in the aggregate command handler
// (04 §5.6). The tier is the descriptor's default with the blast-radius
// escalator applied (04 §1); `now` is passed in so the function stays pure.
func BuildRequestCommand(catalog *ActionCatalog, req ActionRequest, now time.Time) (aggregate.RequestAction, error) {
	d, ok := catalog.Descriptor(req.ActionType)
	if !ok {
		return aggregate.RequestAction{}, fmt.Errorf("unknown action_type %q (not in catalog)", req.ActionType)
	}
	if len(req.Targets) == 0 {
		return aggregate.RequestAction{}, fmt.Errorf("action_type %q: at least one target required", req.ActionType)
	}
	if req.Rationale == "" {
		return aggregate.RequestAction{}, fmt.Errorf("action_type %q: rationale required", req.ActionType)
	}
	for i, t := range req.Targets {
		if t.ResolvedIdentifier == "" {
			return aggregate.RequestAction{}, fmt.Errorf("action_type %q: target %d has no resolved_identifier", req.ActionType, i)
		}
	}
	if err := validateParameters(d, req.Parameters); err != nil {
		return aggregate.RequestAction{}, err
	}
	// Grounding is a mechanism, not a prompt convention (09 §3): a forward action
	// must cite the evidence that justifies it, or the engine rejects it — an
	// ungrounded containment must never reach the approval queue (a live opus run
	// requested account.disable with no evidence_refs 1-in-3, the archetype 09 §2
	// anticipated). Reversals are exempt: their grounding is the original action
	// (reversal_of_ref), the same carve-out G1 makes (design/10). Retries are NOT
	// exempt — a re-request is a fresh proposal and restates its grounding.
	if req.ReversalOfRef == uuid.Nil && len(req.EvidenceRefs) == 0 {
		return aggregate.RequestAction{}, fmt.Errorf("action_type %q: at least one evidence_ref required — a containment must cite the evidence that grounds it (reversals excepted)", req.ActionType)
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultRequestTTL
	}

	return aggregate.RequestAction{
		ActionID:      uuid.New(),
		ActionType:    req.ActionType,
		Tier:          EscalateTier(d.DefaultTier, distinctTargets(req.Targets), DefaultBlastRadiusThreshold),
		Reversibility: d.Reversibility, // frozen at request time (04 §7.1)
		Targets:       req.Targets,
		Parameters:    req.Parameters,
		EvidenceRefs:  req.EvidenceRefs,
		ExpiresAt:     now.Add(ttl),
		Rationale:     req.Rationale,
		IsReversal:    req.ReversalOfRef != uuid.Nil,
		ReversalOfRef: req.ReversalOfRef,
		RetryOf:       req.RetryOf,
	}, nil
}

// validateParameters checks a request's parameters against the descriptor's
// declared Inputs (08 §3: Inputs is THE schema for request_action.parameters).
// Entity-typed inputs ride the targets list (validated above), so only
// non-entity inputs are checked here: required ones must be present and
// non-empty, and unknown keys are rejected — a key the descriptor never
// declared is a typo or hallucination ("title" for ticket.create's "summary")
// that would otherwise sail through approval and only fail — or silently
// render empty — when a real binding templates ${parameters.<name>} at
// dispatch, AFTER the human approved. The error names the declared keys so a
// model caller can self-correct in one round.
func validateParameters(d ActionDescriptor, raw json.RawMessage) error {
	declared := map[string]bool{}
	var names, missing []string
	for _, in := range d.Inputs {
		if in.Type == "entity" {
			continue // satisfied via targets
		}
		declared[in.Name] = true
		names = append(names, in.Name)
	}

	params := map[string]json.RawMessage{}
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &params); err != nil {
			return fmt.Errorf("action_type %q: parameters is not a JSON object: %w", d.ActionType, err)
		}
	}

	for k := range params {
		if !declared[k] {
			return fmt.Errorf("action_type %q: unknown parameter %q (declared inputs: %s)",
				d.ActionType, k, strings.Join(names, ", "))
		}
	}
	for _, in := range d.Inputs {
		if in.Type == "entity" || !in.Required {
			continue
		}
		v, ok := params[in.Name]
		if !ok || string(v) == `""` || string(v) == "null" {
			missing = append(missing, in.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("action_type %q: missing required parameter(s): %s",
			d.ActionType, strings.Join(missing, ", "))
	}
	return nil
}

// EscalateTier applies the non-negotiable blast-radius escalator (04 §1): a T2
// action over the threshold distinct targets is promoted to T3. It never
// demotes, and T3 stays T3. The escalator promotes the tier, not the
// authorization mode (an auto-approval policy may still fire on the escalated
// T3 — 04 §1); the mode decision is the policy engine's (C.3).
func EscalateTier(tier string, targetCount, threshold int) string {
	if tier == aggregate.TierT2 && targetCount > threshold {
		return aggregate.TierT3
	}
	return tier
}

// MaxTier returns the higher of two tiers (T3 > T2 > T1). Used to enforce
// 04 §7: "reversing an action is the same tier as the original, not lower" —
// the reversal's tier is max(inverse descriptor's tier, original action's tier).
func MaxTier(a, b string) string {
	if tierRank(a) >= tierRank(b) {
		return a
	}
	return b
}

func tierRank(t string) int {
	switch t {
	case aggregate.TierT3:
		return 3
	case aggregate.TierT2:
		return 2
	case aggregate.TierT1:
		return 1
	default:
		return 0
	}
}

// distinctTargets counts DISTINCT entities (04 §1's escalator unit — not raw
// target-list length, so duplicated entries neither over- nor under-count).
// Keyed by entity_ref, falling back to resolved_identifier when unset.
func distinctTargets(targets []aggregate.TargetSpec) int {
	seen := make(map[string]bool, len(targets))
	for _, t := range targets {
		key := t.EntityRef
		if key == "" {
			key = t.ResolvedIdentifier
		}
		seen[key] = true
	}
	return len(seen)
}
