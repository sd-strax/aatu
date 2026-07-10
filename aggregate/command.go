package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Command is anything that produces zero or more Events when applied to
// an aggregate. Implementations are pure values — Command does not own a
// transaction or know about the database. The Handler orchestrates
// transaction + event store + projection updates around it.
type Command interface {
	// Kind is a stable identifier for logging and event types.
	Kind() string
	// Validate runs envelope + command-shape checks. Returns nil if the
	// command is well-formed.
	Validate(env Envelope) error
}

// CreateInvestigation is the first concrete command — sufficient for the
// A.4 done bar. Persists one investigation.created event.
//
// Deliberately thinner than the spec's InvestigationCreated: the Seed
// extension (01-domain-model.md §Extension 1 — AlertSeed/EntitySeed/
// QuestionSeed, context, description) lands together with STIX object CRUD
// in Phase B, when there are STIX objects for a seed to reference. Until
// then Title is the whole creation payload.
type CreateInvestigation struct {
	Title string `json:"title"`
}

// Kind returns "CreateInvestigation".
func (CreateInvestigation) Kind() string { return "CreateInvestigation" }

// Validate checks envelope completeness and title non-emptiness.
func (c CreateInvestigation) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.Title == "" {
		return errors.New("CreateInvestigation: Title is empty")
	}
	return nil
}

// validateEnvelope checks the request-time metadata every command requires.
// Shared by all commands so the envelope contract is defined once.
func validateEnvelope(env Envelope) error {
	if env.AggregateID == (AggregateID{}) {
		return ErrEnvelope("AggregateID is zero")
	}
	if env.TenantID == (uuid.UUID{}) {
		return ErrEnvelope("TenantID is zero")
	}
	if env.CorrelationID == (uuid.UUID{}) {
		return ErrEnvelope("CorrelationID is zero")
	}
	if env.Actor.PrincipalID == "" {
		return ErrEnvelope("Actor.PrincipalID is empty")
	}
	if env.OccurredAt.IsZero() {
		return ErrEnvelope("OccurredAt is zero")
	}
	return nil
}

// ErrEnvelope wraps envelope-validation errors so callers can distinguish
// them from command-specific validation failures.
type ErrEnvelope string

func (e ErrEnvelope) Error() string { return "envelope: " + string(e) }

// aggregateState is the current folded state of an investigation, computed from
// its event stream. The Handler folds the stream in-transaction and hands this
// to applyCommand so transition legality is checked against authoritative state
// (not a projection that could lag or be mid-rebuild).
type aggregateState struct {
	Seq           int64                     // sequence number of the last event (0 if none)
	Exists        bool                      // an investigation.created has been seen
	TenantID      uuid.UUID                 // tenant stamped at creation; immutable thereafter
	Status        string                    // current lifecycle status
	ConclusionRef string                    // set while concluded, cleared on reopen
	Actions       map[uuid.UUID]actionState // per-x-action folded state (C.1)
}

// foldState replays an event stream into the current aggregateState. Only
// lifecycle-bearing events move the investigation state machine; interpretation
// and membership events advance Seq but leave status unchanged. Action events
// fold into the per-action state map (foldActionEvent).
func foldState(events []Event) (aggregateState, error) {
	s := aggregateState{Actions: make(map[uuid.UUID]actionState)}
	for _, e := range events {
		s.Seq = e.SequenceNo
		switch e.Type {
		case EventTypeCreated:
			s.Exists = true
			s.TenantID = e.TenantID
			s.Status = StatusDraft
		case EventTypeStatusChanged:
			var p InvestigationStatusChanged
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				return aggregateState{}, fmt.Errorf("fold status_changed seq %d: %w", e.SequenceNo, err)
			}
			s.Status = p.To
		case EventTypeConcluded:
			var p InvestigationConcluded
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				return aggregateState{}, fmt.Errorf("fold concluded seq %d: %w", e.SequenceNo, err)
			}
			s.Status = StatusConcluded
			s.ConclusionRef = p.ReportRef
		case EventTypeReopened:
			s.Status = StatusActive
			s.ConclusionRef = ""
		case EventTypeArchived:
			s.Status = StatusArchived
		case EventTypeActionRequested, EventTypeActionApproved, EventTypeActionRejected,
			EventTypeActionExpired, EventTypeActionDispatched, EventTypeActionResulted,
			EventTypeActionReversed, EventTypeActionPolicyEvaluated:
			// PolicyEvaluated is audit-only (no status change); foldActionEvent
			// ignores it. The rest drive the per-action state machine.
			if err := foldActionEvent(s.Actions, e); err != nil {
				return aggregateState{}, err
			}
		}
	}
	return s, nil
}

// EventTypeCreated is the type tag for events that record an investigation
// being created.
const EventTypeCreated = "investigation.created"

// applyCommand translates (Envelope, Command, current state) into the events to
// persist + apply. It is the pure-function layer — no database, no transaction;
// the Handler folds the state, wraps the transaction, and projects.
//
// Two cross-cutting guards run before dispatch: every command except
// CreateInvestigation requires the aggregate to exist, and an archived
// investigation is terminal — it accepts no further events of any kind
// (01-domain-model.md §Extension 2).
func applyCommand(env Envelope, cmd Command, state aggregateState) ([]Event, error) {
	if err := cmd.Validate(env); err != nil {
		return nil, err
	}

	// AI write-protection (04 §5.6): AI_DELEGATED commands are validated against
	// an ALLOWLIST — spec wording, deliberately, so any future command (C.4's
	// dispatch/result/reversal, and everything after) is AI-denied by default
	// until explicitly admitted. Enforced here at the aggregate boundary — the
	// single write path — so it cannot be bypassed by an alternate code path.
	// NOTE for the HTTP layer: Actor.Kind must be derived from the JWT's
	// delegate_kind claim, never from the request body, or this guard is
	// caller-spoofable.
	if env.Actor.IsAIDelegated() && !aiAllowed(cmd) {
		return nil, fmt.Errorf("%s rejected: not in the AI_DELEGATED command allowlist (04 §5.6)", cmd.Kind())
	}

	// System-only guard: dispatch/result/expiry are lifecycle transitions the
	// Temporal workflows/timers emit — never a human or AI directly. Requiring
	// a SYSTEM actor keeps the workflow the single emitter and stops a spoofed
	// command from forging a dispatch or an outcome.
	if systemOnly(cmd) && env.Actor.Kind != ActorSystem {
		return nil, fmt.Errorf("%s rejected: system-emitted command requires a SYSTEM actor, got %q", cmd.Kind(), env.Actor.Kind)
	}

	if _, isCreate := cmd.(CreateInvestigation); !isCreate {
		if !state.Exists {
			return nil, fmt.Errorf("%s on non-existent investigation %s", cmd.Kind(), env.AggregateID)
		}
		// An aggregate belongs to exactly one tenant, stamped at creation
		// (01-domain-model.md §5). A command arriving under a different tenant
		// must not stamp foreign tenant_ids onto later events of the stream.
		if env.TenantID != state.TenantID {
			return nil, fmt.Errorf("%s rejected: envelope tenant %s does not match investigation tenant %s", cmd.Kind(), env.TenantID, state.TenantID)
		}
		if state.Status == StatusArchived {
			return nil, fmt.Errorf("%s rejected: investigation %s is archived (terminal)", cmd.Kind(), env.AggregateID)
		}
	}

	switch c := cmd.(type) {
	case CreateInvestigation:
		if state.Exists {
			return nil, fmt.Errorf("CreateInvestigation on existing aggregate %s (seq=%d)", env.AggregateID, state.Seq)
		}
		payload, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		return []Event{{
			AggregateID:   env.AggregateID,
			SequenceNo:    state.Seq + 1,
			TenantID:      env.TenantID,
			Type:          EventTypeCreated,
			Version:       schemaVersion,
			Payload:       payload,
			Actor:         env.Actor,
			OccurredAt:    env.OccurredAt,
			CorrelationID: env.CorrelationID,
		}}, nil
	case ActivateInvestigation:
		return statusTransition(env, state, StatusDraft, StatusActive, c.Reason)
	case PauseInvestigation:
		return statusTransition(env, state, StatusActive, StatusPaused, c.Reason)
	case ResumeInvestigation:
		return statusTransition(env, state, StatusPaused, StatusActive, c.Reason)
	case ConcludeInvestigation:
		return concludeEvents(env, state, c)
	case ReopenInvestigation:
		return reopenEvents(env, state, c)
	case ArchiveInvestigation:
		return archiveEvents(env, state, c)
	case AddMember:
		return membershipEvent(env, state, EventTypeMemberAdded, MemberAdded(c))
	case RemoveMember:
		return membershipEvent(env, state, EventTypeMemberRemoved, MemberRemoved(c))
	case AttachEvidence:
		return membershipEvent(env, state, EventTypeEvidenceAttached, EvidenceAttached(c))
	case RequestAction:
		return applyRequestAction(env, state, c)
	case ApproveAction:
		return applyApproveAction(env, state, c)
	case RejectAction:
		return applyRejectAction(env, state, c)
	case ExpireAction:
		return applyExpireAction(env, state, c)
	case DispatchAction:
		return applyDispatchAction(env, state, c)
	case ResultAction:
		return applyResultAction(env, state, c)
	case ReverseAction:
		return applyReverseAction(env, state, c)
	case RecordInterpretation:
		return applyRecordInterpretation(env, state, c)
	default:
		return nil, fmt.Errorf("unknown command: %s", cmd.Kind())
	}
}

// aiAllowed is the AI_DELEGATED command allowlist (04 §5.6). It admits exactly
// the T1-annotate tier (04 §1: hypotheses, membership, evidence, lifecycle
// DRAFT↔ACTIVE↔PAUSED — "the AI agent operates freely here"), RecordInterpretation
// (the AI is the legal author of x-interpretation — reasoning is annotate-tier,
// 03 §1), plus RequestAction (the AI may PROPOSE a T2/T3 action; 08 §2).
// Everything else — approve / reject / expire, conclude / reopen / archive, and
// any future command — defaults to denied. Approving, and concluding an
// investigation, are human acts.
func aiAllowed(cmd Command) bool {
	switch cmd.(type) {
	case CreateInvestigation,
		ActivateInvestigation, PauseInvestigation, ResumeInvestigation,
		AddMember, RemoveMember, AttachEvidence,
		RecordInterpretation,
		RequestAction:
		return true
	default:
		return false
	}
}
