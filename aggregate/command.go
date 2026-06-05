package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"
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
	if env.AggregateID == (AggregateID{}) {
		return ErrEnvelope("AggregateID is zero")
	}
	if env.Actor.PrincipalID == "" {
		return ErrEnvelope("Actor.PrincipalID is empty")
	}
	if env.OccurredAt.IsZero() {
		return ErrEnvelope("OccurredAt is zero")
	}
	if c.Title == "" {
		return errors.New("CreateInvestigation: Title is empty")
	}
	return nil
}

// ErrEnvelope wraps envelope-validation errors so callers can distinguish
// them from command-specific validation failures.
type ErrEnvelope string

func (e ErrEnvelope) Error() string { return "envelope: " + string(e) }

// EventTypeCreated is the type tag for events that record an investigation
// being created.
const EventTypeCreated = "investigation.created"

// applyCommand runs the command against the current aggregate sequence
// number and produces the events to persist + apply.
//
// This is the pure-function layer — no database, no transaction. It just
// translates (Envelope, Command, currentSeq) into the events the Handler
// will atomically append + project.
func applyCommand(env Envelope, cmd Command, currentSeq int64) ([]Event, error) {
	if err := cmd.Validate(env); err != nil {
		return nil, err
	}
	switch c := cmd.(type) {
	case CreateInvestigation:
		// CreateInvestigation is only valid on a fresh aggregate.
		if currentSeq > 0 {
			return nil, fmt.Errorf("CreateInvestigation on existing aggregate %s (seq=%d)", env.AggregateID, currentSeq)
		}
		payload, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		return []Event{
			{
				AggregateID: env.AggregateID,
				SequenceNo:  currentSeq + 1,
				Type:        EventTypeCreated,
				Payload:     payload,
				Actor:       env.Actor,
				OccurredAt:  env.OccurredAt,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown command: %s", cmd.Kind())
	}
}
