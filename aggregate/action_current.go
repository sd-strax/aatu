package aggregate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ActionCurrent is the materialized state of one x-action: what it is, its
// targets, and where it sits in the lifecycle. Drives the action review queue
// (a REQUESTED/PENDING_SECONDARY row is a pending approval) and the audit view.
type ActionCurrent struct {
	ActionID              uuid.UUID
	AggregateID           AggregateID
	ActionType            string
	Tier                  string
	Status                string
	Mode                  string    // empty until approved
	PrimaryApprover       string    // empty until approved
	PrimaryApprovedAt     time.Time // when the primary approval was recorded; zero until approved
	IsReversal            bool
	ReversalOfRef         uuid.UUID // set for reversals; drives the ReversalSaga
	RequiredMode          string    // frozen Gate 2 requirement (MANUAL|TWO_PARTY|AUTO_POLICY)
	SecondaryApproverPool []string  // who may complete a two-party approval
	Parameters            json.RawMessage
	Targets               []TargetSpec
	ExpiresAt             time.Time // approval deadline frozen at request time; zero = none
	LastEventSequence     int64
}

// ActionCurrentProjector populates the action_current table — one row per
// x-action, keyed by action_id (which is aggregate-internal, unlike STIX
// entities that live in the external object store).
type ActionCurrentProjector struct{}

// Name returns "action_current".
func (ActionCurrentProjector) Name() string { return "action_current" }

// Apply updates the projection for a single action event. Non-action events are
// a no-op (other projections consume them).
func (ActionCurrentProjector) Apply(ctx context.Context, tx *sql.Tx, evt Event) error {
	switch evt.Type {
	case EventTypeActionRequested:
		var p ActionRequested
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionRequested: %w", err)
		}
		targets, err := json.Marshal(p.Targets)
		if err != nil {
			return fmt.Errorf("marshal targets: %w", err)
		}
		var pool []byte
		if len(p.SecondaryApproverPool) > 0 {
			if pool, err = json.Marshal(p.SecondaryApproverPool); err != nil {
				return fmt.Errorf("marshal secondary_approver_pool: %w", err)
			}
		}
		var params []byte
		if len(p.Parameters) > 0 {
			params = p.Parameters
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO action_current (
				action_id, aggregate_id, tenant_id, action_type, tier, status,
				is_reversal, reversal_of_ref, required_mode, secondary_approver_pool,
				parameters, targets, expires_at, created_at, updated_at, last_event_sequence
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14, $15)
			ON CONFLICT (action_id) DO NOTHING
		`, p.ActionID, evt.AggregateID, evt.TenantID, p.ActionType, p.Tier, ActionStatusRequested,
			p.IsReversal, nullUUID(p.ReversalOfRef), nullString(p.RequiredMode), pool,
			params, targets, nullTime(p.ExpiresAt), evt.OccurredAt, evt.SequenceNo)
		if err != nil {
			return fmt.Errorf("insert action_current: %w", err)
		}
		return nil

	case EventTypeActionApproved:
		var p ActionApproved
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionApproved: %w", err)
		}
		status := ActionStatusApproved
		if p.Authorization.Mode == AuthModeTwoParty && p.Authorization.Stage == AuthStagePrimary {
			status = ActionStatusPendingSecondary
		}
		// primary_approved_at persists the PRIMARY approval's true time so the
		// secondary stage can cite it (never the secondary's clock). The
		// secondary event's Authorization threads the same value back, so the
		// write is idempotent across both stages.
		_, err := tx.ExecContext(ctx, `
			UPDATE action_current
			SET status = $2, mode = $3, primary_approver_ref = $4, primary_approved_at = $5,
			    last_event_sequence = $6, updated_at = $7
			WHERE action_id = $1
		`, p.ActionID, status, p.Authorization.Mode, p.Authorization.PrimaryApproverRef,
			nullTime(p.Authorization.PrimaryApprovedAt), evt.SequenceNo, evt.OccurredAt)
		if err != nil {
			return fmt.Errorf("update action_current (approve): %w", err)
		}
		return nil

	case EventTypeActionRejected:
		var p ActionRejected
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionRejected: %w", err)
		}
		return setActionStatus(ctx, tx, evt, p.ActionID, ActionStatusRejected)

	case EventTypeActionExpired:
		var p ActionExpired
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionExpired: %w", err)
		}
		return setActionStatus(ctx, tx, evt, p.ActionID, ActionStatusExpired)

	case EventTypeActionDispatched:
		var p ActionDispatched
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionDispatched: %w", err)
		}
		return setActionStatus(ctx, tx, evt, p.ActionID, ActionStatusExecuting)

	case EventTypeActionResulted:
		var p ActionResulted
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionResulted: %w", err)
		}
		status := ActionStatusSucceeded
		if p.FinalOutcome == "FAILED" || p.FinalOutcome == "TIMEOUT" {
			status = ActionStatusFailed
		}
		return setActionStatus(ctx, tx, evt, p.ActionID, status)

	case EventTypeActionReversed:
		var p ActionReversed
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionReversed: %w", err)
		}
		return setActionStatus(ctx, tx, evt, p.OriginalActionID, ActionStatusReversed)

	default:
		// Every non-action event is a no-op here.
		return nil
	}
}

// setActionStatus updates an action's status + cursor.
func setActionStatus(ctx context.Context, tx *sql.Tx, evt Event, actionID uuid.UUID, status string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE action_current
		SET status = $2, last_event_sequence = $3, updated_at = $4
		WHERE action_id = $1
	`, actionID, status, evt.SequenceNo, evt.OccurredAt)
	if err != nil {
		return fmt.Errorf("update action_current status: %w", err)
	}
	return nil
}

// nullTime maps the zero time to SQL NULL.
func nullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t, Valid: true}
}

// Reset truncates the projection table (Replay re-applies from scratch).
func (ActionCurrentProjector) Reset(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `TRUNCATE action_current`); err != nil {
		return fmt.Errorf("truncate action_current: %w", err)
	}
	return nil
}

// actionCurrentColumns is the SELECT list scanActionCurrent expects, shared by
// every action_current reader so the column order cannot drift per-query.
const actionCurrentColumns = `action_id, aggregate_id, action_type, tier, status, mode,
	       primary_approver_ref, primary_approved_at, is_reversal, reversal_of_ref,
	       required_mode, secondary_approver_pool, parameters, targets, expires_at,
	       last_event_sequence`

// scanActionCurrent decodes one actionCurrentColumns row (sql.Row or sql.Rows).
func scanActionCurrent(scan func(dest ...any) error) (ActionCurrent, error) {
	var a ActionCurrent
	var mode, approver, requiredMode sql.NullString
	var primaryAt, expiresAt sql.NullTime
	var reversalOf uuid.NullUUID
	var targets, pool, params []byte
	err := scan(&a.ActionID, &a.AggregateID, &a.ActionType, &a.Tier, &a.Status,
		&mode, &approver, &primaryAt, &a.IsReversal, &reversalOf,
		&requiredMode, &pool, &params, &targets, &expiresAt,
		&a.LastEventSequence)
	if err != nil {
		return ActionCurrent{}, err
	}
	a.Mode = mode.String
	a.PrimaryApprover = approver.String
	a.PrimaryApprovedAt = primaryAt.Time
	a.ExpiresAt = expiresAt.Time
	a.RequiredMode = requiredMode.String
	if reversalOf.Valid {
		a.ReversalOfRef = reversalOf.UUID
	}
	if len(pool) > 0 {
		_ = json.Unmarshal(pool, &a.SecondaryApproverPool)
	}
	if len(params) > 0 {
		a.Parameters = params
	}
	if len(targets) > 0 {
		_ = json.Unmarshal(targets, &a.Targets)
	}
	return a, nil
}

// LoadActionCurrent returns the materialized state for one x-action, or
// sql.ErrNoRows if it has not been projected.
func LoadActionCurrent(ctx context.Context, db *sql.DB, actionID uuid.UUID) (ActionCurrent, error) {
	row := db.QueryRowContext(ctx,
		`SELECT `+actionCurrentColumns+` FROM action_current WHERE action_id = $1`, actionID)
	return scanActionCurrent(row.Scan)
}

// ListActionCurrents returns every x-action of one investigation, oldest first
// — the action review queue (a REQUESTED/PENDING_SECONDARY row is a pending
// approval) and the audit list, with full targets/mode detail (unlike
// ListActionSummaries, which serves the export report's lightweight view).
func ListActionCurrents(ctx context.Context, db *sql.DB, aggregateID uuid.UUID) ([]ActionCurrent, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+actionCurrentColumns+` FROM action_current
		 WHERE aggregate_id = $1 ORDER BY created_at, action_id`, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("query action_current: %w", err)
	}
	defer rows.Close()

	var out []ActionCurrent
	for rows.Next() {
		a, err := scanActionCurrent(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan action_current: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// nullUUID maps the zero UUID to SQL NULL.
func nullUUID(id uuid.UUID) uuid.NullUUID {
	if id == (uuid.UUID{}) {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: id, Valid: true}
}
