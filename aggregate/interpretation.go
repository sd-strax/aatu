package aggregate

import (
	"encoding/json"

	"github.com/google/uuid"
)

// EventTypeInterpretationRecorded tags an event that records one reasoning act
// — an x-interpretation node (01-domain-model.md §Interpretation). Lifecycle
// transitions, linkages, and (later) action requests each pair their domain
// event with one of these in the same transaction, tied by correlation_id, so
// the reasoning thread can be reassembled from the event log.
const EventTypeInterpretationRecorded = "interpretation.recorded"

// Interpretation type tags (01-domain-model.md §Interpretation types). Only the
// tags this slice produces are defined; the rest land with their events.
const (
	InterpretationLifecycle  = "lifecycle"
	InterpretationConclusion = "conclusion"
)

// Derivation mode (01-domain-model.md §Interpretation schema): DIRECT = produced
// by a tool through the capability layer; INFERRED = derived/reasoned by the
// analyst or the AI delegate. Lifecycle transitions are reasoning acts, so
// INFERRED.
const (
	DerivationDirect   = "DIRECT"
	DerivationInferred = "INFERRED"
)

// InterpretationRecorded is the payload of an EventTypeInterpretationRecorded
// event: one recorded reasoning act. It is the event-log projection of the
// x-interpretation primitive; the full STIX node is materialized into the
// object store in Phase B. Recording it here keeps the reasoning thread
// reconstructable from events alone.
type InterpretationRecorded struct {
	InterpretationID   uuid.UUID `json:"interpretation_id"`
	InterpretationType string    `json:"interpretation_type"`
	DerivationMode     string    `json:"derivation_mode"`
	InputRefs          []string  `json:"input_refs,omitempty"`
	Summary            string    `json:"summary,omitempty"`
}

// interpretationEvent builds an InterpretationRecorded event for env at seqNo,
// sharing env's correlation_id with the domain event it is paired with. The
// caller mints interpID (so the paired domain event can reference it via a
// lifecycle_interpretation_ref) — reasoning acts are distinct and never
// deduplicated (unlike STIX entities, which are deterministic UUIDv5). That the
// mint is non-deterministic is fine: commands run once and the resulting event
// is immutable; replay re-applies the stored event, it does not re-run the
// command.
func interpretationEvent(env Envelope, seqNo int64, interpID uuid.UUID, itype, summary string, inputRefs []string) (Event, error) {
	payload, err := json.Marshal(InterpretationRecorded{
		InterpretationID:   interpID,
		InterpretationType: itype,
		DerivationMode:     DerivationInferred,
		InputRefs:          inputRefs,
		Summary:            summary,
	})
	if err != nil {
		return Event{}, err
	}
	return Event{
		AggregateID:   env.AggregateID,
		SequenceNo:    seqNo,
		TenantID:      env.TenantID,
		Type:          EventTypeInterpretationRecorded,
		Payload:       payload,
		Actor:         env.Actor,
		OccurredAt:    env.OccurredAt,
		CorrelationID: env.CorrelationID,
	}, nil
}
