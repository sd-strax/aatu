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
	Seq           int64  // sequence number of the last event (0 if none)
	Exists        bool   // an investigation.created has been seen
	Status        string // current lifecycle status
	ConclusionRef string // set while concluded, cleared on reopen
}

// foldState replays an event stream into the current aggregateState. Only
// lifecycle-bearing events move the state machine; interpretation and
// membership events advance Seq but leave status unchanged.
func foldState(events []Event) (aggregateState, error) {
	var s aggregateState
	for _, e := range events {
		s.Seq = e.SequenceNo
		switch e.Type {
		case EventTypeCreated:
			s.Exists = true
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

	if _, isCreate := cmd.(CreateInvestigation); !isCreate {
		if !state.Exists {
			return nil, fmt.Errorf("%s on non-existent investigation %s", cmd.Kind(), env.AggregateID)
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
	default:
		return nil, fmt.Errorf("unknown command: %s", cmd.Kind())
	}
}
