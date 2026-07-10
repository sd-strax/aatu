package action

import (
	"encoding/json"
	"fmt"
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
	IsReversal       bool                   `json:"is_reversal,omitempty"`
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

	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultRequestTTL
	}

	return aggregate.RequestAction{
		ActionID:     uuid.New(),
		ActionType:   req.ActionType,
		Tier:         EscalateTier(d.DefaultTier, distinctTargets(req.Targets), DefaultBlastRadiusThreshold),
		Targets:      req.Targets,
		Parameters:   req.Parameters,
		EvidenceRefs: req.EvidenceRefs,
		ExpiresAt:    now.Add(ttl),
		Rationale:    req.Rationale,
		IsReversal:   req.IsReversal,
	}, nil
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
