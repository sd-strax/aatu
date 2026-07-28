package aggregate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// InvestigationCurrent is the materialized basic state of an investigation:
// title + status + when-created + the sequence number of the last event
// applied. Useful for "list my investigations" and the right pane of the
// VS Code extension.
type InvestigationCurrent struct {
	AggregateID       AggregateID
	Title             string
	Status            string
	ConclusionRef     string // empty unless concluded
	LastEventSequence int64

	// The verdict of record (01 §Verdict) — the fold over verdict-typed
	// interpretation acts, maintained by VerdictPinProjector. All empty when
	// the investigation has no verdict (the honest zero).
	VerdictDisposition     string
	VerdictRationale       string
	VerdictAt              sql.NullTime
	VerdictInterpretationID uuid.UUID

	// The seed (01 §Extension 1). Nil for pre-seed investigations.
	Seed        *Seed
	SeedSummary string
}

// InvestigationCurrentProjector populates the investigation_current table.
//
// The table has a row per aggregate. CreateInvestigation inserts; future
// commands (title rename, status change) UPDATE.
type InvestigationCurrentProjector struct{}

// Name returns "investigation_current".
func (InvestigationCurrentProjector) Name() string { return "investigation_current" }

// Apply updates the projection for a single event.
func (InvestigationCurrentProjector) Apply(ctx context.Context, tx *sql.Tx, evt Event) error {
	switch evt.Type {
	case EventTypeCreated:
		var p CreateInvestigation
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal CreateInvestigation payload: %w", err)
		}
		var seedJSON []byte
		var seedType, seedSummary sql.NullString
		if p.Seed != nil {
			var err error
			if seedJSON, err = json.Marshal(p.Seed); err != nil {
				return fmt.Errorf("marshal seed: %w", err)
			}
			seedType = sql.NullString{String: p.Seed.Type, Valid: true}
			seedSummary = sql.NullString{String: p.Seed.Summary(), Valid: true}
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO investigation_current (
				aggregate_id, tenant_id, title, status, created_at,
				last_event_sequence, updated_at, seed, seed_type, seed_summary
			) VALUES ($1, $2, $3, $6, $4, $5, $4, $7, $8, $9)
			ON CONFLICT (aggregate_id) DO UPDATE SET
				title               = EXCLUDED.title,
				last_event_sequence = EXCLUDED.last_event_sequence,
				updated_at          = EXCLUDED.updated_at
		`, evt.AggregateID, evt.TenantID, p.Title, evt.OccurredAt, evt.SequenceNo, StatusDraft,
			seedJSON, seedType, seedSummary)
		if err != nil {
			return fmt.Errorf("upsert investigation_current: %w", err)
		}
		return nil

	case EventTypeStatusChanged:
		var p InvestigationStatusChanged
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal InvestigationStatusChanged payload: %w", err)
		}
		return setStatus(ctx, tx, evt, p.To)

	case EventTypeConcluded:
		var p InvestigationConcluded
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal InvestigationConcluded payload: %w", err)
		}
		return setStatusAndConclusion(ctx, tx, evt, StatusConcluded, sql.NullString{String: p.ReportRef, Valid: true})

	case EventTypeReopened:
		return setStatusAndConclusion(ctx, tx, evt, StatusActive, sql.NullString{}) // clears conclusion_ref

	case EventTypeArchived:
		return setStatus(ctx, tx, evt, StatusArchived)

	case EventTypeInterpretationRecorded, EventTypeInterpretationSuperseded,
		EventTypeMemberAdded, EventTypeMemberRemoved, EventTypeEvidenceAttached:
		// These don't change basic state (the reasoning thread and membership
		// projections land separately); advance the cursor so
		// last_event_sequence reflects the true latest event — important after a
		// paired transition, whose interpretation is the last event written.
		_, err := tx.ExecContext(ctx, `
			UPDATE investigation_current
			SET last_event_sequence = $2, updated_at = $3
			WHERE aggregate_id = $1
		`, evt.AggregateID, evt.SequenceNo, evt.OccurredAt)
		if err != nil {
			return fmt.Errorf("advance investigation_current cursor: %w", err)
		}
		return nil

	default:
		// Unknown event type for this projection — no-op. Other projections
		// may consume it.
		return nil
	}
}

// setStatus updates status + the last-event cursor, leaving conclusion_ref
// untouched (used by transitions that don't change the conclusion).
func setStatus(ctx context.Context, tx *sql.Tx, evt Event, status string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE investigation_current
		SET status = $2, last_event_sequence = $3, updated_at = $4
		WHERE aggregate_id = $1
	`, evt.AggregateID, status, evt.SequenceNo, evt.OccurredAt)
	if err != nil {
		return fmt.Errorf("update investigation_current status: %w", err)
	}
	return nil
}

// setStatusAndConclusion updates status, conclusion_ref, and the cursor. A Valid
// conclusion sets the ref (on conclude); an invalid one clears it to NULL (on
// reopen).
func setStatusAndConclusion(ctx context.Context, tx *sql.Tx, evt Event, status string, conclusion sql.NullString) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE investigation_current
		SET status = $2, conclusion_ref = $3, last_event_sequence = $4, updated_at = $5
		WHERE aggregate_id = $1
	`, evt.AggregateID, status, conclusion, evt.SequenceNo, evt.OccurredAt)
	if err != nil {
		return fmt.Errorf("update investigation_current status+conclusion: %w", err)
	}
	return nil
}

// Reset truncates the projection table. Used by Replay before re-applying.
func (InvestigationCurrentProjector) Reset(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `TRUNCATE investigation_current`)
	if err != nil {
		return fmt.Errorf("truncate investigation_current: %w", err)
	}
	return nil
}

// LoadInvestigationCurrent returns the materialized basic state for one
// aggregate, or sql.ErrNoRows if no event has yet been projected.
func LoadInvestigationCurrent(ctx context.Context, db *sql.DB, aggID AggregateID) (InvestigationCurrent, error) {
	var ic InvestigationCurrent
	var conclusionRef, vDisp, vRat, seedSummary sql.NullString
	var vID uuid.NullUUID
	var seedJSON []byte
	err := db.QueryRowContext(ctx, `
		SELECT aggregate_id, title, status, conclusion_ref, last_event_sequence,
		       verdict_disposition, verdict_rationale, verdict_at, verdict_interpretation_id,
		       seed, seed_summary
		FROM investigation_current
		WHERE aggregate_id = $1
	`, aggID).Scan(&ic.AggregateID, &ic.Title, &ic.Status, &conclusionRef, &ic.LastEventSequence,
		&vDisp, &vRat, &ic.VerdictAt, &vID, &seedJSON, &seedSummary)
	ic.ConclusionRef = conclusionRef.String
	ic.VerdictDisposition, ic.VerdictRationale = vDisp.String, vRat.String
	ic.VerdictInterpretationID = vID.UUID
	ic.SeedSummary = seedSummary.String
	if len(seedJSON) > 0 {
		var s Seed
		if json.Unmarshal(seedJSON, &s) == nil {
			ic.Seed = &s
		}
	}
	return ic, err
}
