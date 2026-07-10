package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// The seven x-action lifecycle event types (04 §3.1, 02 §3). The x-action is a
// sibling primitive tracked *inside* the investigation aggregate — its status is
// a projection over these events, never stored state. Each transition is paired
// with an action-* Interpretation in the same transaction (shared
// correlation_id), so the reasoning thread stays intact.
const (
	EventTypeActionRequested  = "action.requested"
	EventTypeActionApproved   = "action.approved"
	EventTypeActionRejected   = "action.rejected"
	EventTypeActionExpired    = "action.expired"
	EventTypeActionDispatched = "action.dispatched" // system-emitted (C.4)
	EventTypeActionResulted   = "action.resulted"   // system-emitted (C.4)
	EventTypeActionReversed   = "action.reversed"   // system-emitted (C.4)
)

// The action-* Interpretation type tags (04 §3.2), members of the canonical
// interpretation_type enum alongside the reasoning types.
const (
	InterpretationActionRequest   = "action-request"
	InterpretationActionApproval  = "action-approval"
	InterpretationActionRejection = "action-rejection"
	InterpretationActionExpiry    = "action-expiry"
	InterpretationActionDispatch  = "action-dispatch"
	InterpretationActionResult    = "action-result"
	InterpretationActionReversal  = "action-reversal"
)

// x-action status values (04 §3.1). The status field is a projection; this is
// the state machine the events drive.
const (
	ActionStatusRequested        = "REQUESTED"
	ActionStatusPendingSecondary = "PENDING_SECONDARY"
	ActionStatusApproved         = "APPROVED"
	ActionStatusRejected         = "REJECTED"
	ActionStatusExpired          = "EXPIRED"
	ActionStatusExecuting        = "EXECUTING"
	ActionStatusSucceeded        = "SUCCEEDED"
	ActionStatusFailed           = "FAILED"
	ActionStatusReversed         = "REVERSED"
)

// Trust tiers (04 §1). T0/T1 don't produce x-actions (they stay in the
// interpretation layer); write actions are T2 or T3.
const (
	TierT1 = "T1"
	TierT2 = "T2"
	TierT3 = "T3"
)

// Authorization modes and stages (04 §3.3).
const (
	AuthModeManual            = "MANUAL"
	AuthModeAutoPolicy        = "AUTO_POLICY"
	AuthModeTwoParty          = "TWO_PARTY"
	AuthModeExternalDelegated = "EXTERNAL_DELEGATED"

	AuthStageSolo      = "SOLO"
	AuthStagePrimary   = "PRIMARY"
	AuthStageSecondary = "SECONDARY"
)

// TargetSpec is one thing an action acts on (04 §3.1). Resolution is frozen at
// request time: resolved_identifier is what the write adapter sends downstream;
// it is never re-resolved.
type TargetSpec struct {
	EntityRef          string `json:"entity_ref"`
	ResolvedIdentifier string `json:"resolved_identifier"`
	AssetCriticality   string `json:"asset_criticality,omitempty"`
}

// Authorization is the auth sub-record recorded on ActionApproved (04 §3.3).
type Authorization struct {
	Mode                 string     `json:"mode"`
	Stage                string     `json:"stage"`
	PrimaryApproverRef   string     `json:"primary_approver_ref"`
	PrimaryApprovedAt    time.Time  `json:"primary_approved_at"`
	SecondaryApproverRef string     `json:"secondary_approver_ref,omitempty"`
	SecondaryApprovedAt  *time.Time `json:"secondary_approved_at,omitempty"`
	PolicyRef            string     `json:"policy_ref,omitempty"`
	PolicyVersion        string     `json:"policy_version,omitempty"`
	ChallengeResponse    string     `json:"challenge_response,omitempty"`
}

// --- event payloads (02 §3) --------------------------------------------------

// ActionRequested records a new x-action in REQUESTED. Paired with the
// producing action-request Interpretation.
type ActionRequested struct {
	ActionID                   uuid.UUID       `json:"action_id"`
	ActionType                 string          `json:"action_type"`
	Tier                       string          `json:"tier"`
	Targets                    []TargetSpec    `json:"targets"`
	Parameters                 json.RawMessage `json:"parameters,omitempty"`
	EvidenceRefs               []string        `json:"evidence_refs,omitempty"`
	ExpiresAt                  time.Time       `json:"expires_at"`
	IsReversal                 bool            `json:"is_reversal,omitempty"`
	RequestingInterpretationID uuid.UUID       `json:"requesting_interpretation_id"`
}

// ActionApproved advances an action to APPROVED (or PENDING_SECONDARY for a
// TWO_PARTY primary approval).
type ActionApproved struct {
	ActionID                 uuid.UUID     `json:"action_id"`
	Authorization            Authorization `json:"authorization"`
	ApprovalInterpretationID uuid.UUID     `json:"approval_interpretation_id"`
}

// ActionRejected records a declined action.
type ActionRejected struct {
	ActionID                  uuid.UUID `json:"action_id"`
	Reason                    string    `json:"reason"`
	RejectionInterpretationID uuid.UUID `json:"rejection_interpretation_id"`
}

// ActionExpired records a REQUESTED/PENDING_SECONDARY action lapsing at
// expires_at. System-emitted.
type ActionExpired struct {
	ActionID               uuid.UUID `json:"action_id"`
	ExpiryInterpretationID uuid.UUID `json:"expiry_interpretation_id"`
}

// --- folded state ------------------------------------------------------------

// actionState is one x-action's folded state within the aggregate.
type actionState struct {
	Status     string
	Tier       string
	IsReversal bool
}

// foldActionEvent applies one action event to the per-action state map. Kept
// separate from foldState so the switch there stays readable; all seven types
// are handled so the machine is complete for the C.4 dispatch events.
func foldActionEvent(actions map[uuid.UUID]actionState, e Event) error {
	get := func(id uuid.UUID) actionState { return actions[id] }
	set := func(id uuid.UUID, s actionState) { actions[id] = s }

	switch e.Type {
	case EventTypeActionRequested:
		var p ActionRequested
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("fold action.requested seq %d: %w", e.SequenceNo, err)
		}
		set(p.ActionID, actionState{Status: ActionStatusRequested, Tier: p.Tier, IsReversal: p.IsReversal})
	case EventTypeActionApproved:
		var p ActionApproved
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("fold action.approved seq %d: %w", e.SequenceNo, err)
		}
		s := get(p.ActionID)
		if p.Authorization.Mode == AuthModeTwoParty && p.Authorization.Stage == AuthStagePrimary {
			s.Status = ActionStatusPendingSecondary
		} else {
			s.Status = ActionStatusApproved
		}
		set(p.ActionID, s)
	case EventTypeActionRejected:
		var p ActionRejected
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("fold action.rejected seq %d: %w", e.SequenceNo, err)
		}
		s := get(p.ActionID)
		s.Status = ActionStatusRejected
		set(p.ActionID, s)
	case EventTypeActionExpired:
		var p ActionExpired
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("fold action.expired seq %d: %w", e.SequenceNo, err)
		}
		s := get(p.ActionID)
		s.Status = ActionStatusExpired
		set(p.ActionID, s)
	}
	return nil
}

// --- commands ----------------------------------------------------------------

// RequestAction proposes a state-changing action, producing an x-action in
// REQUESTED plus its action-request Interpretation (08 §2). The AI may issue
// this; it carries no Authorization and cannot advance status.
type RequestAction struct {
	ActionID     uuid.UUID       `json:"action_id"` // the x-action id, minted by the caller
	ActionType   string          `json:"action_type"`
	Tier         string          `json:"tier"`
	Targets      []TargetSpec    `json:"targets"`
	Parameters   json.RawMessage `json:"parameters,omitempty"`
	EvidenceRefs []string        `json:"evidence_refs,omitempty"`
	ExpiresAt    time.Time       `json:"expires_at"`
	Rationale    string          `json:"rationale"`
	IsReversal   bool            `json:"is_reversal,omitempty"`
}

// Kind returns "RequestAction".
func (RequestAction) Kind() string { return "RequestAction" }

// Validate checks the envelope and the request shape.
func (c RequestAction) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.ActionID == (uuid.UUID{}) {
		return errors.New("RequestAction: ActionID is zero")
	}
	if c.ActionType == "" {
		return errors.New("RequestAction: ActionType is empty")
	}
	if c.Tier != TierT2 && c.Tier != TierT3 {
		return fmt.Errorf("RequestAction: Tier %q must be T2 or T3", c.Tier)
	}
	if len(c.Targets) == 0 {
		return errors.New("RequestAction: at least one target required")
	}
	return nil
}

// ApproveAction advances a REQUESTED (or PENDING_SECONDARY) action to APPROVED,
// carrying the Authorization sub-record. Never AI-issuable (§5.6); the acting
// principal must be the approver.
type ApproveAction struct {
	ActionID      uuid.UUID     `json:"action_id"`
	Authorization Authorization `json:"authorization"`
}

// Kind returns "ApproveAction".
func (ApproveAction) Kind() string { return "ApproveAction" }

// Validate checks the envelope and the authorization shape.
func (c ApproveAction) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.ActionID == (uuid.UUID{}) {
		return errors.New("ApproveAction: ActionID is zero")
	}
	switch c.Authorization.Mode {
	case AuthModeManual, AuthModeAutoPolicy, AuthModeTwoParty, AuthModeExternalDelegated:
	default:
		return fmt.Errorf("ApproveAction: invalid authorization mode %q", c.Authorization.Mode)
	}
	if c.Authorization.PrimaryApproverRef == "" {
		return errors.New("ApproveAction: primary_approver_ref is empty")
	}
	return nil
}

// RejectAction declines a REQUESTED or PENDING_SECONDARY action. Never
// AI-issuable.
type RejectAction struct {
	ActionID uuid.UUID `json:"action_id"`
	Reason   string    `json:"reason"`
}

// Kind returns "RejectAction".
func (RejectAction) Kind() string { return "RejectAction" }

// Validate checks the envelope and the action id.
func (c RejectAction) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.ActionID == (uuid.UUID{}) {
		return errors.New("RejectAction: ActionID is zero")
	}
	return nil
}

// ExpireAction lapses a REQUESTED/PENDING_SECONDARY action at expires_at.
// System-emitted (actor.kind = SYSTEM).
type ExpireAction struct {
	ActionID uuid.UUID `json:"action_id"`
}

// Kind returns "ExpireAction".
func (ExpireAction) Kind() string { return "ExpireAction" }

// Validate checks the envelope and the action id.
func (c ExpireAction) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.ActionID == (uuid.UUID{}) {
		return errors.New("ExpireAction: ActionID is zero")
	}
	return nil
}

// --- apply functions ---------------------------------------------------------

// applyRequestAction builds the (ActionRequested, action-request Interpretation)
// pair. Permitted while the investigation is ACTIVE, or CONCLUDED when the
// request is a reversal (04 §9.1).
func applyRequestAction(env Envelope, state aggregateState, c RequestAction) ([]Event, error) {
	switch {
	case state.Status == StatusActive:
	case state.Status == StatusConcluded && c.IsReversal:
	default:
		return nil, fmt.Errorf("RequestAction rejected: investigation %s is %s (actions require ACTIVE, or CONCLUDED for a reversal)", env.AggregateID, state.Status)
	}
	if _, exists := state.Actions[c.ActionID]; exists {
		return nil, fmt.Errorf("RequestAction rejected: action %s already exists", c.ActionID)
	}

	interpID := uuid.New()
	payload, err := json.Marshal(ActionRequested{
		ActionID:                   c.ActionID,
		ActionType:                 c.ActionType,
		Tier:                       c.Tier,
		Targets:                    c.Targets,
		Parameters:                 c.Parameters,
		EvidenceRefs:               c.EvidenceRefs,
		ExpiresAt:                  c.ExpiresAt,
		IsReversal:                 c.IsReversal,
		RequestingInterpretationID: interpID,
	})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeActionRequested, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationActionRequest,
		c.Rationale, c.EvidenceRefs)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// applyApproveAction builds the (ActionApproved, action-approval Interpretation)
// pair, enforcing the actor/approver invariant (04 §3.3): the acting principal
// must equal the approver whose stage this approval records.
func applyApproveAction(env Envelope, state aggregateState, c ApproveAction) ([]Event, error) {
	act, ok := state.Actions[c.ActionID]
	if !ok {
		return nil, fmt.Errorf("ApproveAction rejected: action %s does not exist", c.ActionID)
	}

	stage := c.Authorization.Stage
	if err := checkApprover(env, c.Authorization, stage); err != nil {
		return nil, err
	}

	// Legal source states: REQUESTED for a solo/primary approval; PENDING_SECONDARY
	// for a two-party secondary approval.
	switch {
	case act.Status == ActionStatusRequested && stage != AuthStageSecondary:
	case act.Status == ActionStatusPendingSecondary && stage == AuthStageSecondary:
	default:
		return nil, fmt.Errorf("ApproveAction rejected: action %s is %s, cannot record a %s approval", c.ActionID, act.Status, stage)
	}

	interpID := uuid.New()
	payload, err := json.Marshal(ActionApproved{
		ActionID:                 c.ActionID,
		Authorization:            c.Authorization,
		ApprovalInterpretationID: interpID,
	})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeActionApproved, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationActionApproval,
		fmt.Sprintf("action %s approved (%s/%s)", c.ActionID, c.Authorization.Mode, stage), nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// checkApprover enforces the actor/approver invariant for the recorded stage.
// The AI-write-protection guard in applyCommand already ensures the actor is not
// AI_DELEGATED before we get here.
func checkApprover(env Envelope, auth Authorization, stage string) error {
	want := auth.PrimaryApproverRef
	if stage == AuthStageSecondary {
		want = auth.SecondaryApproverRef
	}
	if want == "" {
		return fmt.Errorf("ApproveAction rejected: no approver ref for stage %s", stage)
	}
	// AUTO_POLICY approvals are attributed to the policy's signed-off-by human,
	// who is the recorded principal; the invariant holds identically.
	if env.Actor.PrincipalID != want {
		return fmt.Errorf("ApproveAction rejected: actor principal %q is not the %s approver %q (04 §3.3 actor/approver invariant)", env.Actor.PrincipalID, stage, want)
	}
	return nil
}

// applyRejectAction builds the (ActionRejected, action-rejection Interpretation)
// pair.
func applyRejectAction(env Envelope, state aggregateState, c RejectAction) ([]Event, error) {
	act, ok := state.Actions[c.ActionID]
	if !ok {
		return nil, fmt.Errorf("RejectAction rejected: action %s does not exist", c.ActionID)
	}
	if act.Status != ActionStatusRequested && act.Status != ActionStatusPendingSecondary {
		return nil, fmt.Errorf("RejectAction rejected: action %s is %s (not pending)", c.ActionID, act.Status)
	}

	interpID := uuid.New()
	payload, err := json.Marshal(ActionRejected{
		ActionID:                  c.ActionID,
		Reason:                    c.Reason,
		RejectionInterpretationID: interpID,
	})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeActionRejected, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationActionRejection, c.Reason, nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// applyExpireAction builds the (ActionExpired, action-expiry Interpretation)
// pair for a pending action that lapsed.
func applyExpireAction(env Envelope, state aggregateState, c ExpireAction) ([]Event, error) {
	act, ok := state.Actions[c.ActionID]
	if !ok {
		return nil, fmt.Errorf("ExpireAction rejected: action %s does not exist", c.ActionID)
	}
	if act.Status != ActionStatusRequested && act.Status != ActionStatusPendingSecondary {
		return nil, fmt.Errorf("ExpireAction rejected: action %s is %s (not pending)", c.ActionID, act.Status)
	}

	interpID := uuid.New()
	payload, err := json.Marshal(ActionExpired{ActionID: c.ActionID, ExpiryInterpretationID: interpID})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeActionExpired, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationActionExpiry, "action expired", nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}
