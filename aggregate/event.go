// Package aggregate is the event-sourced investigation spine.
//
// One append-only events table holds every state change. State views are
// derived (projections) — never stored as primary state. Optimistic
// concurrency on (aggregate_id, sequence_no) ensures concurrent writers
// to the same aggregate serialize cleanly.
//
// See reckon/design/02-persistence.md for the canonical event taxonomy and
// projection model.
package aggregate

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AggregateID identifies one investigation.
type AggregateID = uuid.UUID

// Event is a single thing that happened to an aggregate. Persisted in
// reckon_main.events.
//
// TenantID is the partition the event belongs to. Every node and event belongs
// to exactly one tenant (01-domain-model.md §5); it is carried explicitly
// rather than left to the column DEFAULT so the value is meaningful in the
// read path and ready for per-tenant routing.
type Event struct {
	AggregateID AggregateID     `json:"aggregate_id"`
	SequenceNo  int64           `json:"sequence_no"`
	TenantID    uuid.UUID       `json:"tenant_id"`
	Type        string          `json:"type"`
	Payload     json.RawMessage `json:"payload"`
	Actor       Actor           `json:"actor"`
	OccurredAt  time.Time       `json:"occurred_at"`

	// EventID is the event's stable global identifier (02-persistence.md §3):
	// side stores (ai_tool_calls) and cross-store provenance reference one
	// event by it without carrying the composite natural key. Minted as
	// UUIDv7 at append time if zero — it is an infrastructure identity, not
	// command output, so applyCommand never sets it.
	EventID uuid.UUID `json:"event_id"`

	// Version is the payload schema version for this event type
	// (02-persistence.md §5). Bump per event type when its payload shape
	// changes, and upcast old versions at read time. Everything is version 1
	// today (schemaVersion).
	Version int `json:"event_version"`

	// RecordedAt is the DB-stamped write time, as opposed to the
	// caller-supplied business time OccurredAt. Zero on events built by
	// applyCommand; populated when events are read back from the store.
	RecordedAt time.Time `json:"recorded_at,omitzero"`

	// CausationID references the event that caused this one, for event-chain
	// provenance. Invalid (NULL) for command-initiated events — all events
	// today; system-emitted chains (Temporal workflows) populate it later.
	CausationID uuid.NullUUID `json:"causation_id,omitempty"`

	// CorrelationID groups every event produced by one command. A command that
	// emits a domain event plus its paired InterpretationRecorded (a lifecycle
	// transition, say) stamps the same CorrelationID on both, so the reasoning
	// trail can be reassembled (02-persistence.md §3, "shared correlation_id").
	CorrelationID uuid.UUID `json:"correlation_id"`
}

// schemaVersion is the current payload schema version stamped on every event
// built by this package (Event.Version). Bump per event type — not globally —
// when a payload shape changes; see 02-persistence.md §5.
const schemaVersion = 1

// Envelope is the request-time metadata accompanying every command. TenantID is
// resolved at the request boundary (module.TenancyModule.ResolveTenant; the OSS
// default is module.SingleTenantUUID) and stamped onto every produced event.
// CorrelationID is generated per command at the boundary (uuid.New) and shared
// by every event the command produces.
type Envelope struct {
	AggregateID   AggregateID
	TenantID      uuid.UUID
	CorrelationID uuid.UUID
	Actor         Actor
	OccurredAt    time.Time
}

// Actor kinds (02-persistence.md §7). The principal is ALWAYS a named human —
// the AI is a delegate, never a principal. Kind records who *initiated* the
// command so the action command handler can enforce the AI write-protection
// (04 §5.6): an AI_DELEGATED command may request an action but can never
// construct an Authorization record or advance action status. An empty Kind is
// treated as HUMAN (the safe default) so pre-C.1 commands are unaffected.
const (
	ActorHuman       = "HUMAN"
	ActorAIDelegated = "AI_DELEGATED"
	ActorSystem      = "SYSTEM" // system-emitted (Temporal workflows: expiry, dispatch, result)
)

// Actor records who made a command. The AI delegate, when present, is
// captured separately — every event records a human principal per the
// architectural commitment "AI is a delegate, never a principal."
//
// See reckon/design/01-domain-model.md and reckon/CLAUDE.md "Architectural
// commitments" → "AI is a delegate, never a principal."
type Actor struct {
	PrincipalID string      `json:"principal_id"`
	Kind        string      `json:"kind,omitempty"` // HUMAN | AI_DELEGATED | SYSTEM; empty = HUMAN
	Delegate    *AIDelegate `json:"delegate,omitempty"`
}

// IsAIDelegated reports whether the command was initiated by the AI on the
// principal's behalf (as opposed to a human acting directly or the system).
func (a Actor) IsAIDelegated() bool { return a.Kind == ActorAIDelegated }

// AIDelegate names the LLM (and its specific call) that produced the
// command on the principal's behalf.
type AIDelegate struct {
	Vendor         string `json:"vendor"`
	Model          string `json:"model"`
	TranscriptHash string `json:"transcript_hash,omitempty"`
}
