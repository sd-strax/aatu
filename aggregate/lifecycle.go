package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Lifecycle event types (02-persistence.md §3). Each is appended together with
// a paired InterpretationRecorded in the same transaction (shared
// correlation_id), per the 01-domain-model.md §Extension 2 invariant that every
// transition emits a lifecycle Interpretation.
const (
	EventTypeStatusChanged = "investigation.status_changed"
	EventTypeConcluded     = "investigation.concluded"
	EventTypeReopened      = "investigation.reopened"
	EventTypeArchived      = "investigation.archived"
)

// InvestigationStatusChanged is the payload for draft→active, active↔paused
// transitions (02-persistence.md §3). LifecycleInterpretationRef points at the
// paired InterpretationRecorded.
type InvestigationStatusChanged struct {
	From                       string    `json:"from"`
	To                         string    `json:"to"`
	Reason                     string    `json:"reason,omitempty"`
	LifecycleInterpretationRef uuid.UUID `json:"lifecycle_interpretation_ref"`
}

// InvestigationConcluded records active→concluded. ReportRef is the STIX Report
// id (the Report itself is written to the object store in the same transaction
// once STIX CRUD lands; here we record the reference).
type InvestigationConcluded struct {
	ReportRef                  string    `json:"report_ref"`
	Summary                    string    `json:"summary,omitempty"`
	LifecycleInterpretationRef uuid.UUID `json:"lifecycle_interpretation_ref"`
}

// InvestigationReopened records concluded→active; the projection clears
// conclusion_ref. The prior Report stays referenced from the reasoning thread.
type InvestigationReopened struct {
	Reason                     string    `json:"reason,omitempty"`
	LifecycleInterpretationRef uuid.UUID `json:"lifecycle_interpretation_ref"`
}

// InvestigationArchived records concluded→archived. Terminal: the aggregate
// accepts no further events.
type InvestigationArchived struct {
	Reason                     string    `json:"reason,omitempty"`
	LifecycleInterpretationRef uuid.UUID `json:"lifecycle_interpretation_ref"`
}

// ActivateInvestigation moves draft→active — clearing the investigation to
// request external actions (04-action-authorization.md §T1).
type ActivateInvestigation struct {
	Reason string `json:"reason,omitempty"`
}

// Kind returns "ActivateInvestigation".
func (ActivateInvestigation) Kind() string { return "ActivateInvestigation" }

// Validate checks the envelope shape.
func (ActivateInvestigation) Validate(env Envelope) error { return validateEnvelope(env) }

// PauseInvestigation moves active→paused (a reversible hold).
type PauseInvestigation struct {
	Reason string `json:"reason,omitempty"`
}

// Kind returns "PauseInvestigation".
func (PauseInvestigation) Kind() string { return "PauseInvestigation" }

// Validate checks the envelope shape.
func (PauseInvestigation) Validate(env Envelope) error { return validateEnvelope(env) }

// ResumeInvestigation moves paused→active.
type ResumeInvestigation struct {
	Reason string `json:"reason,omitempty"`
}

// Kind returns "ResumeInvestigation".
func (ResumeInvestigation) Kind() string { return "ResumeInvestigation" }

// Validate checks the envelope shape.
func (ResumeInvestigation) Validate(env Envelope) error { return validateEnvelope(env) }

// ConcludeInvestigation moves active→concluded with a final Report reference.
type ConcludeInvestigation struct {
	ReportRef string `json:"report_ref"`
	Summary   string `json:"summary,omitempty"`
}

// Kind returns "ConcludeInvestigation".
func (ConcludeInvestigation) Kind() string { return "ConcludeInvestigation" }

// Validate requires a non-empty ReportRef — concluded investigations must carry
// a conclusion_ref (01-domain-model.md §Extension 2 invariant).
func (c ConcludeInvestigation) Validate(env Envelope) error {
	if err := validateEnvelope(env); err != nil {
		return err
	}
	if c.ReportRef == "" {
		return errors.New("ConcludeInvestigation: ReportRef is required (a conclusion needs a Report)")
	}
	return nil
}

// ReopenInvestigation moves concluded→active, clearing conclusion_ref.
type ReopenInvestigation struct {
	Reason string `json:"reason,omitempty"`
}

// Kind returns "ReopenInvestigation".
func (ReopenInvestigation) Kind() string { return "ReopenInvestigation" }

// Validate checks the envelope shape.
func (ReopenInvestigation) Validate(env Envelope) error { return validateEnvelope(env) }

// ArchiveInvestigation moves concluded→archived (terminal).
type ArchiveInvestigation struct {
	Reason string `json:"reason,omitempty"`
}

// Kind returns "ArchiveInvestigation".
func (ArchiveInvestigation) Kind() string { return "ArchiveInvestigation" }

// Validate checks the envelope shape.
func (ArchiveInvestigation) Validate(env Envelope) error { return validateEnvelope(env) }

// statusTransition builds the paired (StatusChanged, InterpretationRecorded)
// events for a from→to lifecycle move, rejecting the command if the
// investigation is not currently in the from state.
func statusTransition(env Envelope, state aggregateState, from, to, reason string) ([]Event, error) {
	if state.Status != from {
		return nil, fmt.Errorf("cannot move %s→%s: investigation %s is %s", from, to, env.AggregateID, state.Status)
	}
	interpID := uuid.New()
	payload, err := json.Marshal(InvestigationStatusChanged{
		From: from, To: to, Reason: reason, LifecycleInterpretationRef: interpID,
	})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeStatusChanged, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationLifecycle,
		fmt.Sprintf("lifecycle %s→%s", from, to), nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// concludeEvents builds the (InvestigationConcluded, InterpretationRecorded)
// pair. Conclusion is recorded as a "conclusion" interpretation rather than a
// plain "lifecycle" one (01-domain-model.md §Interpretation types).
func concludeEvents(env Envelope, state aggregateState, c ConcludeInvestigation) ([]Event, error) {
	if state.Status != StatusActive {
		return nil, fmt.Errorf("cannot conclude investigation %s: it is %s, not %s", env.AggregateID, state.Status, StatusActive)
	}
	interpID := uuid.New()
	payload, err := json.Marshal(InvestigationConcluded{
		ReportRef: c.ReportRef, Summary: c.Summary, LifecycleInterpretationRef: interpID,
	})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeConcluded, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationConclusion, c.Summary, nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// reopenEvents builds the (InvestigationReopened, InterpretationRecorded) pair.
func reopenEvents(env Envelope, state aggregateState, c ReopenInvestigation) ([]Event, error) {
	if state.Status != StatusConcluded {
		return nil, fmt.Errorf("cannot reopen investigation %s: it is %s, not %s", env.AggregateID, state.Status, StatusConcluded)
	}
	interpID := uuid.New()
	payload, err := json.Marshal(InvestigationReopened{Reason: c.Reason, LifecycleInterpretationRef: interpID})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeReopened, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationLifecycle, "reopened", nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// archiveEvents builds the (InvestigationArchived, InterpretationRecorded) pair.
// Both are written in the archiving transaction; afterwards the terminal guard
// in applyCommand rejects every further command.
func archiveEvents(env Envelope, state aggregateState, c ArchiveInvestigation) ([]Event, error) {
	if state.Status != StatusConcluded {
		return nil, fmt.Errorf("cannot archive investigation %s: it is %s, not %s", env.AggregateID, state.Status, StatusConcluded)
	}
	interpID := uuid.New()
	payload, err := json.Marshal(InvestigationArchived{Reason: c.Reason, LifecycleInterpretationRef: interpID})
	if err != nil {
		return nil, err
	}
	domain := lifecycleDomainEvent(env, state.Seq+1, EventTypeArchived, payload)
	interp, err := interpretationEvent(env, state.Seq+2, interpID, InterpretationLifecycle, "archived", nil)
	if err != nil {
		return nil, err
	}
	return []Event{domain, interp}, nil
}

// lifecycleDomainEvent stamps the common envelope fields onto a lifecycle
// domain event.
func lifecycleDomainEvent(env Envelope, seqNo int64, eventType string, payload []byte) Event {
	return Event{
		AggregateID:   env.AggregateID,
		SequenceNo:    seqNo,
		TenantID:      env.TenantID,
		Type:          eventType,
		Version:       schemaVersion,
		Payload:       payload,
		Actor:         env.Actor,
		OccurredAt:    env.OccurredAt,
		CorrelationID: env.CorrelationID,
	}
}
