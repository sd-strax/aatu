// Package aggregate is the event-sourced investigation spine.
//
// One append-only events table holds every state change. State views are
// derived (projections) — never stored as primary state. Optimistic
// concurrency on (aggregate_id, sequence_no) ensures concurrent writers
// to the same aggregate serialize cleanly.
//
// See aatu/design/02-persistence.md for the canonical event taxonomy and
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
// aatu_main.events.
type Event struct {
	AggregateID AggregateID     `json:"aggregate_id"`
	SequenceNo  int64           `json:"sequence_no"`
	Type        string          `json:"type"`
	Payload     json.RawMessage `json:"payload"`
	Actor       Actor           `json:"actor"`
	OccurredAt  time.Time       `json:"occurred_at"`
}

// Envelope is the request-time metadata accompanying every command.
type Envelope struct {
	AggregateID AggregateID
	Actor       Actor
	OccurredAt  time.Time
}

// Actor records who made a command. The AI delegate, when present, is
// captured separately — every event records a human principal per the
// architectural commitment "AI is a delegate, never a principal."
//
// See aatu/design/01-domain-model.md and aatu/CLAUDE.md "Architectural
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
