package aggregate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// VerdictPinProjector materializes the verdict-of-record fold (onto
// investigation_current) and the pinned-evidence list (evidence_pin_current)
// from interpretation events, in the same transaction as the append — the
// standard projector contract. Because both are folds over the event log,
// Reset+Replay rebuilds them from events alone.
type VerdictPinProjector struct{}

// Name returns "verdict_pins".
func (VerdictPinProjector) Name() string { return "verdict_pins" }

// Apply projects one event. Interpretation events without pin/verdict content
// are a no-op; supersession re-derives the verdict fold and deactivates pins.
func (VerdictPinProjector) Apply(ctx context.Context, tx *sql.Tx, evt Event) error {
	switch evt.Type {
	case EventTypeInterpretationRecorded:
		var rec InterpretationRecorded
		if err := json.Unmarshal(evt.Payload, &rec); err != nil {
			return fmt.Errorf("unmarshal InterpretationRecorded: %w", err)
		}
		switch rec.InterpretationType {
		case InterpretationEvidencePin:
			return insertPin(ctx, tx, evt, rec)
		case InterpretationVerdict:
			if rec.Verdict == nil {
				return nil
			}
			// A newly recorded verdict is by definition the latest — set the
			// fold directly.
			if _, err := tx.ExecContext(ctx, `
				UPDATE investigation_current
				SET verdict_disposition = $2, verdict_rationale = $3,
				    verdict_at = $4, verdict_interpretation_id = $5
				WHERE aggregate_id = $1
			`, evt.AggregateID, rec.Verdict.Disposition, rec.Summary, evt.OccurredAt, rec.InterpretationID); err != nil {
				return fmt.Errorf("set verdict fold: %w", err)
			}
		}
		return nil

	case EventTypeInterpretationSuperseded:
		var p InterpretationSupersededPayload
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal InterpretationSuperseded: %w", err)
		}
		switch p.SupersededType {
		case InterpretationEvidencePin:
			if _, err := tx.ExecContext(ctx, `
				UPDATE evidence_pin_current
				SET superseded = TRUE, last_event_sequence = $2
				WHERE interpretation_id = $1
			`, p.SupersededID, evt.SequenceNo); err != nil {
				return fmt.Errorf("supersede pin: %w", err)
			}
		case InterpretationVerdict:
			// The fold may fall back to an earlier verdict act — re-derive it
			// from the event log (authoritative, same transaction).
			return rederiveVerdict(ctx, tx, evt)
		}
		return nil

	default:
		return nil
	}
}

func insertPin(ctx context.Context, tx *sql.Tx, evt Event, rec InterpretationRecorded) error {
	refs, err := json.Marshal(rec.InputRefs)
	if err != nil {
		return fmt.Errorf("marshal pin input_refs: %w", err)
	}
	actor, err := json.Marshal(evt.Actor)
	if err != nil {
		return fmt.Errorf("marshal pin actor: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO evidence_pin_current (
			interpretation_id, aggregate_id, tenant_id, finding, input_refs,
			actor, pinned_at, superseded, last_event_sequence
		) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8)
		ON CONFLICT (interpretation_id) DO NOTHING
	`, rec.InterpretationID, evt.AggregateID, evt.TenantID, rec.Summary, refs,
		actor, evt.OccurredAt, evt.SequenceNo); err != nil {
		return fmt.Errorf("insert evidence_pin_current: %w", err)
	}
	return nil
}

// rederiveVerdict recomputes the verdict of record from the event stream:
// the latest verdict-typed interpretation not named by any supersession
// event. Runs in the projection transaction, so the event that triggered it
// is already visible.
func rederiveVerdict(ctx context.Context, tx *sql.Tx, evt Event) error {
	superseded, err := supersededSet(ctx, tx, evt.AggregateID)
	if err != nil {
		return err
	}

	// Latest non-superseded verdict act, walking newest-first.
	vrows, err := tx.QueryContext(ctx, `
		SELECT payload, occurred_at FROM events
		WHERE aggregate_id = $1 AND event_type = $2 AND payload ? 'verdict'
		ORDER BY sequence_no DESC
	`, evt.AggregateID, EventTypeInterpretationRecorded)
	if err != nil {
		return fmt.Errorf("query verdict acts: %w", err)
	}
	defer vrows.Close()
	for vrows.Next() {
		var raw []byte
		var at sql.NullTime
		if err := vrows.Scan(&raw, &at); err != nil {
			return fmt.Errorf("scan verdict act: %w", err)
		}
		var rec InterpretationRecorded
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("unmarshal verdict act: %w", err)
		}
		if rec.Verdict == nil || superseded[rec.InterpretationID] {
			continue
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE investigation_current
			SET verdict_disposition = $2, verdict_rationale = $3,
			    verdict_at = $4, verdict_interpretation_id = $5
			WHERE aggregate_id = $1
		`, evt.AggregateID, rec.Verdict.Disposition, rec.Summary, at.Time, rec.InterpretationID)
		if err != nil {
			return fmt.Errorf("re-set verdict fold: %w", err)
		}
		return vrows.Err()
	}
	if err := vrows.Err(); err != nil {
		return err
	}

	// Every verdict act superseded — back to the honest zero.
	if _, err := tx.ExecContext(ctx, `
		UPDATE investigation_current
		SET verdict_disposition = NULL, verdict_rationale = NULL,
		    verdict_at = NULL, verdict_interpretation_id = NULL
		WHERE aggregate_id = $1
	`, evt.AggregateID); err != nil {
		return fmt.Errorf("clear verdict fold: %w", err)
	}
	return nil
}

// supersededSet collects the ids named by every supersession event of one
// aggregate, in the projection transaction.
func supersededSet(ctx context.Context, tx *sql.Tx, aggID AggregateID) (map[uuid.UUID]bool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT payload FROM events
		WHERE aggregate_id = $1 AND event_type = $2
	`, aggID, EventTypeInterpretationSuperseded)
	if err != nil {
		return nil, fmt.Errorf("query supersessions: %w", err)
	}
	defer rows.Close()

	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan supersession: %w", err)
		}
		var p InterpretationSupersededPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("unmarshal supersession: %w", err)
		}
		out[p.SupersededID] = true
	}
	return out, rows.Err()
}

// Reset clears the pin projection; the verdict columns live on
// investigation_current, whose own projector truncates the table on replay.
func (VerdictPinProjector) Reset(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `TRUNCATE evidence_pin_current`); err != nil {
		return fmt.Errorf("truncate evidence_pin_current: %w", err)
	}
	return nil
}

// --- read side -----------------------------------------------------------------

// EvidencePin is one materialized pin row.
type EvidencePin struct {
	InterpretationID uuid.UUID
	AggregateID      AggregateID
	Finding          string
	InputRefs        []string
	Actor            Actor
	PinnedAt         sql.NullTime
	Superseded       bool
}

// ListEvidencePins returns an investigation's pins, oldest first. Superseded
// pins are included (the caller filters or renders them struck) — the record
// of what was once considered load-bearing is part of the thread.
func ListEvidencePins(ctx context.Context, db *sql.DB, aggregateID uuid.UUID) ([]EvidencePin, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT interpretation_id, aggregate_id, finding, input_refs, actor, pinned_at, superseded
		FROM evidence_pin_current
		WHERE aggregate_id = $1
		ORDER BY pinned_at, interpretation_id
	`, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("query evidence_pin_current: %w", err)
	}
	defer rows.Close()

	var out []EvidencePin
	for rows.Next() {
		var p EvidencePin
		var refs, actor []byte
		if err := rows.Scan(&p.InterpretationID, &p.AggregateID, &p.Finding, &refs, &actor, &p.PinnedAt, &p.Superseded); err != nil {
			return nil, fmt.Errorf("scan evidence pin: %w", err)
		}
		if len(refs) > 0 {
			_ = json.Unmarshal(refs, &p.InputRefs)
		}
		if len(actor) > 0 {
			_ = json.Unmarshal(actor, &p.Actor)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
