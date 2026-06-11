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

	// CorrelationID groups every event produced by one command. A command that
	// emits a domain event plus its paired InterpretationRecorded (a lifecycle
	// transition, say) stamps the same CorrelationID on both, so the reasoning
	// trail can be reassembled (02-persistence.md §3, "shared correlation_id").
	CorrelationID uuid.UUID `json:"correlation_id"`
}

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

// Actor records who made a command. The AI delegate, when present, is
// captured separately — every event records a human principal per the
// architectural commitment "AI is a delegate, never a principal."
//
// See reckon/design/01-domain-model.md and reckon/CLAUDE.md "Architectural
// commitments" → "AI is a delegate, never a principal."
type Actor struct {
	PrincipalID string      `json:"principal_id"`
	Delegate    *AIDelegate `json:"delegate,omitempty"`
}

// AIDelegate names the LLM (and its specific call) that produced the
// command on the principal's behalf.
type AIDelegate struct {
	Vendor         string `json:"vendor"`
	Model          string `json:"model"`
	TranscriptHash string `json:"transcript_hash,omitempty"`
}
