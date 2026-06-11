package aggregate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// InvestigationCurrent is the materialized basic state of an investigation:
// title + status + when-created + the sequence number of the last event
// applied. Useful for "list my investigations" and the right pane of the
// VS Code extension.
type InvestigationCurrent struct {
	AggregateID       AggregateID
	Title             string
	Status            string
	LastEventSequence int64
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
		_, err := tx.ExecContext(ctx, `
			INSERT INTO investigation_current (
				aggregate_id, tenant_id, title, status, created_at,
				last_event_sequence, updated_at
			) VALUES ($1, $2, $3, $6, $4, $5, $4)
			ON CONFLICT (aggregate_id) DO UPDATE SET
				title               = EXCLUDED.title,
				last_event_sequence = EXCLUDED.last_event_sequence,
				updated_at          = EXCLUDED.updated_at
		`, evt.AggregateID, evt.TenantID, p.Title, evt.OccurredAt, evt.SequenceNo, StatusDraft)
		if err != nil {
			return fmt.Errorf("upsert investigation_current: %w", err)
		}
		return nil
	default:
		// Unknown event type for this projection — no-op. Other projections
		// may consume it.
		return nil
	}
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
	err := db.QueryRowContext(ctx, `
		SELECT aggregate_id, title, status, last_event_sequence
		FROM investigation_current
		WHERE aggregate_id = $1
	`, aggID).Scan(&ic.AggregateID, &ic.Title, &ic.Status, &ic.LastEventSequence)
	return ic, err
}
