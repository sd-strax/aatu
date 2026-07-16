package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// The eight x-action lifecycle event types (04 §3.1, 02 §3). The x-action is a
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

	// EventTypeActionReversalAttempted records a reversing dispatch that fully
	// succeeded but whose effect could not be verified (04 §7.1 Position C —
	// BEST_EFFORT originals). The original's status does NOT change; only
	// reversal_attempted_by_ref is recorded, so the attempt is queryable from
	// the original's side without over-claiming the undo. System-emitted by the
	// ReversalSaga.
	EventTypeActionReversalAttempted = "action.reversal_attempted"

	// EventTypeActionPolicyEvaluated records the Gate 2 policy evaluation
	// (04 §4, 02 §3). Recorded once per action-request in the SAME transaction
	// as ActionRequested — the shared-tx requirement is why the evaluation
	// result travels on the RequestAction command rather than being a separate
	// command. Audit-only: it does not move the action's status.
	EventTypeActionPolicyEvaluated = "action.policy_evaluated"
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

// PolicyEvaluationRecord is one policy's outcome in the PolicyEvaluated audit
// (02 §3). Mirrors action.PolicyEvaluation; kept as a plain aggregate type so
// the aggregate never imports the action package (which imports it).
type PolicyEvaluationRecord struct {
	PolicyRef      string `json:"policy_ref"`
	PolicyVersion  string `json:"policy_version"`
	WouldHaveFired bool   `json:"would_have_fired"`
	Effect         string `json:"effect"`
	Shadow         bool   `json:"shadow"`
}

// ActionPolicyEvaluated is the payload of the policy-evaluation audit event.
// matched_policy_ref is the policy whose effect drove authorization, or empty
// when all matching policies were shadow and the action fell through to manual.
type ActionPolicyEvaluated struct {
	ActionID         uuid.UUID                `json:"action_id"`
	Evaluations      []PolicyEvaluationRecord `json:"evaluations"`
	MatchedPolicyRef string                   `json:"matched_policy_ref,omitempty"`
}

// --- event payloads (02 §3) --------------------------------------------------

// ActionRequested records a new x-action in REQUESTED. Paired with the
// producing action-request Interpretation.
type ActionRequested struct {
	ActionID   uuid.UUID `json:"action_id"`
	ActionType string    `json:"action_type"`
	Tier       string    `json:"tier"`
	// Reversibility freezes the action type's reversibility classification
	// (04 §7: reversible | best_effort | irreversible) at request time, so the
	// REVERSED-claim gate (04 §7.1) reads the value the analyst approved under —
	// a later catalog edit cannot re-classify an in-flight action.
	Reversibility              string          `json:"reversibility,omitempty"`
	Targets                    []TargetSpec    `json:"targets"`
	Parameters                 json.RawMessage `json:"parameters,omitempty"`
	EvidenceRefs               []string        `json:"evidence_refs,omitempty"`
	ExpiresAt                  time.Time       `json:"expires_at"`
	IsReversal                 bool            `json:"is_reversal,omitempty"`
	ReversalOfRef              uuid.UUID       `json:"reversal_of_ref,omitempty"`
	RequestingInterpretationID uuid.UUID       `json:"requesting_interpretation_id"`

	// RequiredMode + SecondaryApproverPool freeze the Gate 2 authorization
	// requirement at request time (08 §8.1 — resolution is frozen), so the
	// approval surface enforces it later without re-evaluating (which could
	// drift). RequiredMode == TWO_PARTY makes a solo approval illegal at the
	// aggregate boundary; the pool bounds who may be the secondary approver.
	RequiredMode          string   `json:"required_mode,omitempty"`
	SecondaryApproverPool []string `json:"secondary_approver_pool,omitempty"`
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

// ActionDispatched records the dispatcher picking up an APPROVED action
// (02 §3). System-emitted by the ActionLifecycle workflow (C.4); its presence
// in the stream is the dispatch-ledger guard (08 §6b) — a replayed workflow
// sees it and short-circuits re-issue.
type ActionDispatched struct {
	ActionID                 uuid.UUID `json:"action_id"`
	Adapter                  string    `json:"adapter"`
	AdapterRequestID         string    `json:"adapter_request_id"`
	DispatchedAt             time.Time `json:"dispatched_at"`
	DispatchInterpretationID uuid.UUID `json:"dispatch_interpretation_id"`
}

// ActionResulted records the terminal outcome of a dispatched action (02 §3).
// System-emitted. per_target_results is what makes PARTIAL outcomes auditable.
type ActionResulted struct {
	ActionID               uuid.UUID         `json:"action_id"`
	FinalOutcome           string            `json:"final_outcome"` // SUCCEEDED | FAILED | PARTIAL | TIMEOUT
	PerTargetResults       map[string]string `json:"per_target_results,omitempty"`
	Attempts               int               `json:"attempts"`
	RawResponseRef         string            `json:"raw_response_ref,omitempty"`
	ResultInterpretationID uuid.UUID         `json:"result_interpretation_id"`
}

// ActionReversed records the original action's status moving to REVERSED on the
// reversing action's success (02 §3). The reversing action is its own x-action
// with its own lifecycle events.
type ActionReversed struct {
	OriginalActionID         uuid.UUID `json:"original_action_id"`
	ReversingActionID        uuid.UUID `json:"reversing_action_id"`
	ReversalInterpretationID uuid.UUID `json:"reversal_interpretation_id"`
}

// ActionReversalAttempted records a fully-successful reversing dispatch whose
// effect could not be verified (04 §7.1 Position C): the original honestly
// stays SUCCEEDED — only the back-reference is recorded, so "was a reversal
// ever attempted?" is answerable from the original's side without claiming an
// undo we cannot verify.
type ActionReversalAttempted struct {
	OriginalActionID         uuid.UUID `json:"original_action_id"`
	ReversingActionID        uuid.UUID `json:"reversing_action_id"`
	ReversalInterpretationID uuid.UUID `json:"reversal_interpretation_id"`
}

// --- folded state ------------------------------------------------------------

// actionState is one x-action's folded state within the aggregate.
// PrimaryApprover is retained from the primary approval so the secondary stage
// can enforce two-party integrity (distinct approvers, consistent audit record)
// against authoritative state rather than trusting the caller's payload.
type actionState struct {
	Status                string
	Tier                  string
	IsReversal            bool
	PrimaryApprover       string
	RequiredMode          string   // Gate 2 requirement, frozen at request time
	SecondaryApproverPool []string // who may be the secondary approver (TWO_PARTY)
}

// foldActionEvent applies one action event to the per-action state map. Kept
// separate from foldState so the switch there stays readable; all eight types
// are handled so the machine is complete for the C.4 dispatch events.
// action.reversal_attempted deliberately has no case: it never changes folded
// state (the original stays SUCCEEDED, 04 §7.1) — it only feeds the projection.
func foldActionEvent(actions map[uuid.UUID]actionState, e Event) error {
	get := func(id uuid.UUID) actionState { return actions[id] }
	set := func(id uuid.UUID, s actionState) { actions[id] = s }

	switch e.Type {
	case EventTypeActionRequested:
		var p ActionRequested
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("fold action.requested seq %d: %w", e.SequenceNo, err)
		}
		set(p.ActionID, actionState{
			Status: ActionStatusRequested, Tier: p.Tier, IsReversal: p.IsReversal,
			RequiredMode: p.RequiredMode, SecondaryApproverPool: p.SecondaryApproverPool,
		})
	case EventTypeActionApproved:
		var p ActionApproved
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("fold action.approved seq %d: %w", e.SequenceNo, err)
		}
		s := get(p.ActionID)
		s.PrimaryApprover = p.Authorization.PrimaryApproverRef
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
	case EventTypeActionDispatched:
		var p ActionDispatched
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("fold action.dispatched seq %d: %w", e.SequenceNo, err)
		}
		s := get(p.ActionID)
		s.Status = ActionStatusExecuting
		set(p.ActionID, s)
	case EventTypeActionResulted:
		var p ActionResulted
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("fold action.resulted seq %d: %w", e.SequenceNo, err)
		}
		s := get(p.ActionID)
		// Status mapping per 08 §7.1: PARTIAL terminates SUCCEEDED (with the
		// partial detail on the event); TIMEOUT terminates FAILED with no
		// success inference (04 §6.2).
		switch p.FinalOutcome {
		case "SUCCEEDED", "PARTIAL":
			s.Status = ActionStatusSucceeded
		default: // FAILED, TIMEOUT
			s.Status = ActionStatusFailed
		}
		set(p.ActionID, s)
	case EventTypeActionReversed:
		var p ActionReversed
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("fold action.reversed seq %d: %w", e.SequenceNo, err)
		}
		s := get(p.OriginalActionID)
		s.Status = ActionStatusReversed
		set(p.OriginalActionID, s)
	}
	return nil
}

// --- commands ----------------------------------------------------------------

// RequestAction proposes a state-changing action, producing an x-action in
// REQUESTED plus its action-request Interpretation (08 §2). The AI may issue
// this; it carries no Authorization and cannot advance status.
type RequestAction struct {
	ActionID   uuid.UUID `json:"action_id"` // the x-action id, minted by the caller
	ActionType string    `json:"action_type"`
	Tier       string    `json:"tier"`
	// Reversibility is the action type's classification from the catalog
	// (04 §7), frozen onto the ActionRequested event — see that event's field.
	Reversibility string          `json:"reversibility,omitempty"`
	Targets       []TargetSpec    `json:"targets"`
	Parameters    json.RawMessage `json:"parameters,omitempty"`
	EvidenceRefs  []string        `json:"evidence_refs,omitempty"`
	ExpiresAt     time.Time       `json:"expires_at"`
	Rationale     string          `json:"rationale"`
	IsReversal    bool            `json:"is_reversal,omitempty"`
	// ReversalOfRef points at the original x-action this action reverses
	// (04 §7). Set only when IsReversal; drives the ReversalSaga.
	ReversalOfRef uuid.UUID `json:"reversal_of_ref,omitempty"`

	// RequiredMode + SecondaryApproverPool carry the Gate 2 authorization
	// requirement (04 §4), frozen onto the action so the approval surface can
	// enforce TWO_PARTY without re-evaluating. Set by action.ApplyDecision.
	RequiredMode          string   `json:"required_mode,omitempty"`
	SecondaryApproverPool []string `json:"secondary_approver_pool,omitempty"`

	// PolicyEvaluations + MatchedPolicyRef carry the Gate 2 result (04 §4), so
	// the PolicyEvaluated audit event is recorded in the same transaction as
	// ActionRequested (02 §3). Empty when Gate 2 did not run (e.g. a request
	// built before the endpoint wires it in).
	PolicyEvaluations []PolicyEvaluationRecord `json:"policy_evaluations,omitempty"`
	MatchedPolicyRef  string                   `json:"matched_policy_ref,omitempty"`
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

// Validate checks the envelope and the authorization shape, including the
// 04 §3.3 mode/stage pairing — without it, a TWO_PARTY approval sent with
// stage SOLO would fold straight to APPROVED, bypassing the secondary.
func (c ApproveAction) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.ActionID == (uuid.UUID{}) {
		return errors.New("ApproveAction: ActionID is zero")
	}
	switch c.Authorization.Mode {
	case AuthModeManual, AuthModeAutoPolicy, AuthModeExternalDelegated:
		// Single-stage modes are always SOLO (04 §3.3).
		if c.Authorization.Stage != AuthStageSolo {
			return fmt.Errorf("ApproveAction: mode %s requires stage SOLO, got %q", c.Authorization.Mode, c.Authorization.Stage)
		}
	case AuthModeTwoParty:
		// TWO_PARTY is exactly PRIMARY then SECONDARY — SOLO would collapse the
		// two stages into one.
		if c.Authorization.Stage != AuthStagePrimary && c.Authorization.Stage != AuthStageSecondary {
			return fmt.Errorf("ApproveAction: mode TWO_PARTY requires stage PRIMARY or SECONDARY, got %q", c.Authorization.Stage)
		}
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

// DispatchAction records an APPROVED action being picked up for dispatch
// (02 §3). System-emitted by the ActionLifecycle workflow; the envelope
// principal is the action's approver (the workflow carries it, 05 §6.2). The
// adapter_request_id is the workflow id.
type DispatchAction struct {
	ActionID         uuid.UUID `json:"action_id"`
	Adapter          string    `json:"adapter"`
	AdapterRequestID string    `json:"adapter_request_id"`
}

// Kind returns "DispatchAction".
func (DispatchAction) Kind() string { return "DispatchAction" }

// Validate checks the envelope and the action id.
func (c DispatchAction) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.ActionID == (uuid.UUID{}) {
		return errors.New("DispatchAction: ActionID is zero")
	}
	return nil
}

// ResultAction records the terminal outcome of a dispatched action (02 §3).
// System-emitted.
type ResultAction struct {
	ActionID         uuid.UUID         `json:"action_id"`
	FinalOutcome     string            `json:"final_outcome"` // SUCCEEDED | FAILED | PARTIAL | TIMEOUT
	PerTargetResults map[string]string `json:"per_target_results,omitempty"`
	Attempts         int               `json:"attempts"`
	RawResponseRef   string            `json:"raw_response_ref,omitempty"`
}

// Kind returns "ResultAction".
func (ResultAction) Kind() string { return "ResultAction" }

// Validate checks the envelope, action id, and outcome vocabulary.
func (c ResultAction) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.ActionID == (uuid.UUID{}) {
		return errors.New("ResultAction: ActionID is zero")
	}
	switch c.FinalOutcome {
	case "SUCCEEDED", "FAILED", "PARTIAL", "TIMEOUT":
	default:
		return fmt.Errorf("ResultAction: invalid final_outcome %q", c.FinalOutcome)
	}
	return nil
}

// ReverseAction records the ORIGINAL action moving to REVERSED once its
// reversing action succeeded (02 §3, 04 §7). System-emitted by the ReversalSaga.
type ReverseAction struct {
	OriginalActionID  uuid.UUID `json:"original_action_id"`
	ReversingActionID uuid.UUID `json:"reversing_action_id"`
}

// Kind returns "ReverseAction".
func (ReverseAction) Kind() string { return "ReverseAction" }

// Validate checks the envelope and both action ids.
func (c ReverseAction) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.OriginalActionID == (uuid.UUID{}) || c.ReversingActionID == (uuid.UUID{}) {
		return errors.New("ReverseAction: both action ids required")
	}
	return nil
}

// RecordReversalAttempt records that a reversing action fully succeeded but its
// effect could not be verified (04 §7.1 Position C — the original is
// BEST_EFFORT): the original stays SUCCEEDED and only reversal_attempted_by_ref
// is recorded. System-emitted by the ReversalSaga, like ReverseAction.
type RecordReversalAttempt struct {
	OriginalActionID  uuid.UUID `json:"original_action_id"`
	ReversingActionID uuid.UUID `json:"reversing_action_id"`
}

// Kind returns "RecordReversalAttempt".
func (RecordReversalAttempt) Kind() string { return "RecordReversalAttempt" }

// Validate checks the envelope and both action ids.
func (c RecordReversalAttempt) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.OriginalActionID == (uuid.UUID{}) || c.ReversingActionID == (uuid.UUID{}) {
		return errors.New("RecordReversalAttempt: both action ids required")
	}
	return nil
}

// systemOnly reports whether a command may be issued only by a SYSTEM actor
// (the Temporal workflows / timers). Dispatch, result, expiry, and reversal are
// lifecycle transitions no human or AI issues directly — routing them through
// SYSTEM keeps the workflows the single emitter and prevents a spoofed human
// command from forging a dispatch, outcome, or reversal.
func systemOnly(cmd Command) bool {
	switch cmd.(type) {
	case DispatchAction, ResultAction, ExpireAction, ReverseAction, RecordReversalAttempt:
		return true
	default:
		return false
	}
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
		Reversibility:              c.Reversibility,
		Targets:                    c.Targets,
		Parameters:                 c.Parameters,
		EvidenceRefs:               c.EvidenceRefs,
		ExpiresAt:                  c.ExpiresAt,
		IsReversal:                 c.IsReversal,
		ReversalOfRef:              c.ReversalOfRef,
		RequiredMode:               c.RequiredMode,
		SecondaryApproverPool:      c.SecondaryApproverPool,
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
	events := []Event{domain, interp}

	// If Gate 2 ran, record its evaluation in the same transaction (02 §3).
	if len(c.PolicyEvaluations) > 0 {
		pePayload, err := json.Marshal(ActionPolicyEvaluated{
			ActionID:         c.ActionID,
			Evaluations:      c.PolicyEvaluations,
			MatchedPolicyRef: c.MatchedPolicyRef,
		})
		if err != nil {
			return nil, err
		}
		events = append(events, lifecycleDomainEvent(env, state.Seq+3, EventTypeActionPolicyEvaluated, pePayload))
	}
	return events, nil
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

	// Two-party requirement (04 §5.6, the Phase D approval seam): an action whose
	// frozen Gate 2 requirement is TWO_PARTY can NEVER be approved with a solo
	// (MANUAL/AUTO_POLICY) authorization — that would collapse the two-person
	// integrity the policy demanded into one. Enforced here at the aggregate
	// boundary, the single write path, so no approval surface can bypass it.
	if act.RequiredMode == AuthModeTwoParty && c.Authorization.Mode != AuthModeTwoParty {
		return nil, fmt.Errorf("ApproveAction rejected: action %s requires TWO_PARTY authorization, got a %s approval", c.ActionID, c.Authorization.Mode)
	}

	// Legal source states: REQUESTED for a solo/primary approval; PENDING_SECONDARY
	// for a two-party secondary approval.
	switch {
	case act.Status == ActionStatusRequested && stage != AuthStageSecondary:
	case act.Status == ActionStatusPendingSecondary && stage == AuthStageSecondary:
	default:
		return nil, fmt.Errorf("ApproveAction rejected: action %s is %s, cannot record a %s approval", c.ActionID, act.Status, stage)
	}

	// Two-party integrity (04 §3.2/§3.3): the secondary approver must be a
	// DIFFERENT human than the primary — one analyst approving both stages
	// defeats the mode — and the secondary event's primary_approver_ref must
	// match the primary approval actually recorded in the stream (checked
	// against folded state, never the caller's payload), so the audit chain
	// cannot be rewritten at the second stage.
	if stage == AuthStageSecondary {
		if c.Authorization.SecondaryApproverRef == c.Authorization.PrimaryApproverRef {
			return nil, fmt.Errorf("ApproveAction rejected: secondary approver %q must differ from the primary approver (TWO_PARTY requires two humans)", c.Authorization.SecondaryApproverRef)
		}
		if act.PrimaryApprover != "" && c.Authorization.PrimaryApproverRef != act.PrimaryApprover {
			return nil, fmt.Errorf("ApproveAction rejected: primary_approver_ref %q does not match the recorded primary approval by %q", c.Authorization.PrimaryApproverRef, act.PrimaryApprover)
		}
		// When the policy declared a secondary approver pool, the secondary must
		// be drawn from it (04 §5.6): the policy author bounded who can complete
		// the two-party approval, and that bound is frozen on the action.
		if len(act.SecondaryApproverPool) > 0 && !slices.Contains(act.SecondaryApproverPool, c.Authorization.SecondaryApproverRef) {
			return nil, fmt.Errorf("ApproveAction rejected: secondary approver %q is not in the action's secondary approver pool", c.Authorization.SecondaryApproverRef)
		}
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

// applyDispatchAction builds the (ActionDispatched, action-dispatch
// Interpretation) pair. Legal only from APPROVED. Its presence in the stream is
// the dispatch-ledger guard (08 §6b): a re-triggered workflow sees it and
// short-circuits re-issue.
func applyDispatchAction(env Envelope, state aggregateState, c DispatchAction) ([]Event, error) {
	act, ok := state.Actions[c.ActionID]
	if !ok {
		return nil, fmt.Errorf("DispatchAction rejected: action %s does not exist", c.ActionID)
	}
	if act.Status != ActionStatusApproved {
		return nil, fmt.Errorf("DispatchAction rejected: action %s is %s, not APPROVED", c.ActionID, act.Status)
	}

	interpID := uuid.New()
	payload, err := json.Marshal(ActionDispatched{
		ActionID:                 c.ActionID,
		Adapter:                  c.Adapter,
		AdapterRequestID:         c.AdapterRequestID,
		DispatchedAt:             env.OccurredAt,
		DispatchInterpretationID: interpID,
	})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeActionDispatched, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationActionDispatch,
		fmt.Sprintf("dispatched via %s (%s)", c.Adapter, c.AdapterRequestID), nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// applyResultAction builds the (ActionResulted, action-result Interpretation)
// pair. Legal only from EXECUTING.
func applyResultAction(env Envelope, state aggregateState, c ResultAction) ([]Event, error) {
	act, ok := state.Actions[c.ActionID]
	if !ok {
		return nil, fmt.Errorf("ResultAction rejected: action %s does not exist", c.ActionID)
	}
	if act.Status != ActionStatusExecuting {
		return nil, fmt.Errorf("ResultAction rejected: action %s is %s, not EXECUTING", c.ActionID, act.Status)
	}

	interpID := uuid.New()
	payload, err := json.Marshal(ActionResulted{
		ActionID:               c.ActionID,
		FinalOutcome:           c.FinalOutcome,
		PerTargetResults:       c.PerTargetResults,
		Attempts:               c.Attempts,
		RawResponseRef:         c.RawResponseRef,
		ResultInterpretationID: interpID,
	})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeActionResulted, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationActionResult,
		fmt.Sprintf("action %s: %s", c.ActionID, c.FinalOutcome), nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// applyReverseAction builds the (ActionReversed, action-reversal Interpretation)
// pair on the ORIGINAL action. Legal only from SUCCEEDED — you can only reverse
// an action that actually took effect (04 §7).
func applyReverseAction(env Envelope, state aggregateState, c ReverseAction) ([]Event, error) {
	orig, ok := state.Actions[c.OriginalActionID]
	if !ok {
		return nil, fmt.Errorf("ReverseAction rejected: original action %s does not exist", c.OriginalActionID)
	}
	if orig.Status != ActionStatusSucceeded {
		return nil, fmt.Errorf("ReverseAction rejected: original action %s is %s, not SUCCEEDED", c.OriginalActionID, orig.Status)
	}

	interpID := uuid.New()
	payload, err := json.Marshal(ActionReversed{
		OriginalActionID:         c.OriginalActionID,
		ReversingActionID:        c.ReversingActionID,
		ReversalInterpretationID: interpID,
	})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeActionReversed, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationActionReversal,
		fmt.Sprintf("action %s reversed by %s", c.OriginalActionID, c.ReversingActionID), nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// applyReversalAttempt builds the (ActionReversalAttempted, action-reversal
// Interpretation) pair on the ORIGINAL action. Same precondition as
// ReverseAction — only a SUCCEEDED action has an effect to attempt to reverse.
// The interpretation_type reuses the canonical action-reversal (01: the enum is
// closed); the domain event — not the interpretation — carries the
// verified/unverified distinction.
func applyReversalAttempt(env Envelope, state aggregateState, c RecordReversalAttempt) ([]Event, error) {
	orig, ok := state.Actions[c.OriginalActionID]
	if !ok {
		return nil, fmt.Errorf("RecordReversalAttempt rejected: original action %s does not exist", c.OriginalActionID)
	}
	if orig.Status != ActionStatusSucceeded {
		return nil, fmt.Errorf("RecordReversalAttempt rejected: original action %s is %s, not SUCCEEDED", c.OriginalActionID, orig.Status)
	}

	interpID := uuid.New()
	payload, err := json.Marshal(ActionReversalAttempted{
		OriginalActionID:         c.OriginalActionID,
		ReversingActionID:        c.ReversingActionID,
		ReversalInterpretationID: interpID,
	})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeActionReversalAttempted, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationActionReversal,
		fmt.Sprintf("reversal of action %s attempted by %s; effect unverified — original stays SUCCEEDED",
			c.OriginalActionID, c.ReversingActionID), nil)
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
