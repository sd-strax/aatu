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
	ActionID          uuid.UUID
	AggregateID       AggregateID
	ActionType        string
	Tier              string
	Status            string
	Mode              string    // empty until approved
	PrimaryApprover   string    // empty until approved
	PrimaryApprovedAt time.Time // when the primary approval was recorded; zero until approved
	IsReversal        bool
	ReversalOfRef     uuid.UUID // set for reversals; drives the ReversalSaga
	// Reversibility is the classification frozen at request time (04 §7:
	// reversible | best_effort | irreversible); empty for actions requested
	// before it was frozen (callers fall back to the live catalog).
	Reversibility string
	// ReversedByRef is the reversing x-action once the original is REVERSED
	// (verified undo, 04 §7.1); zero otherwise.
	ReversedByRef uuid.UUID
	// ReversalAttemptedByRef is the reversing x-action of a fully-successful
	// but UNVERIFIED reversal (04 §7.1 — the original stays SUCCEEDED); zero if
	// no unverified attempt was recorded.
	ReversalAttemptedByRef uuid.UUID
	RequiredMode           string   // frozen Gate 2 requirement (MANUAL|TWO_PARTY|AUTO_POLICY)
	SecondaryApproverPool  []string // who may complete a two-party approval
	Parameters             json.RawMessage
	Targets                []TargetSpec
	// EvidenceRefs are the STIX/OCSF refs that grounded the request (08 §2),
	// surfaced from the ActionRequested event so the actions API (and the eval
	// harness's G1 grader) can read grounding without walking the event log.
	EvidenceRefs      []string
	ExpiresAt         time.Time // approval deadline frozen at request time; zero = none
	// RetryOf is the prior FAILED/EXPIRED action this one replaces — lineage
	// only (a retry is always a new action; the dispatch ledger forbids
	// re-dispatching one id). Zero when not a retry.
	RetryOf uuid.UUID
	// Adapter is the tool that dispatched the action (from ActionDispatched.
	// Adapter, 08 §6b) — the write-side provenance a surface shows so the
	// analyst sees WHICH tool acted when several could serve the action type.
	// Empty until the action is dispatched.
	Adapter string
	// ErrorDetail is the reason a non-success action failed (from ActionResulted,
	// 08 §6c) — surfaced so the ledger explains a FAILED action. Empty otherwise.
	ErrorDetail string
	// RawResponseRef is the operational reference the dispatch returned (e.g.
	// the created incident number) — the analyst's handle into the external
	// system of record.
	RawResponseRef    string
	LastEventSequence int64
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
		var evidence []byte
		if len(p.EvidenceRefs) > 0 {
			if evidence, err = json.Marshal(p.EvidenceRefs); err != nil {
				return fmt.Errorf("marshal evidence_refs: %w", err)
			}
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO action_current (
				action_id, aggregate_id, tenant_id, action_type, tier, status,
				is_reversal, reversal_of_ref, retry_of, reversibility, required_mode,
				secondary_approver_pool, parameters, targets, evidence_refs, expires_at,
				created_at, updated_at, last_event_sequence
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $17, $18)
			ON CONFLICT (action_id) DO NOTHING
		`, p.ActionID, evt.AggregateID, evt.TenantID, p.ActionType, p.Tier, ActionStatusRequested,
			p.IsReversal, nullUUID(p.ReversalOfRef), nullUUID(p.RetryOf), nullString(p.Reversibility), nullString(p.RequiredMode),
			pool, params, targets, evidence, nullTime(p.ExpiresAt), evt.OccurredAt, evt.SequenceNo)
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
		// Record the dispatcher alongside the EXECUTING status: this is where
		// the write-side adapter provenance lands on the projection.
		_, err := tx.ExecContext(ctx, `
			UPDATE action_current
			SET status = $2, adapter = $3, last_event_sequence = $4, updated_at = $5
			WHERE action_id = $1
		`, p.ActionID, ActionStatusExecuting, p.Adapter, evt.SequenceNo, evt.OccurredAt)
		if err != nil {
			return fmt.Errorf("update action_current dispatched: %w", err)
		}
		return nil

	case EventTypeActionResulted:
		var p ActionResulted
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionResulted: %w", err)
		}
		status := ActionStatusSucceeded
		if p.FinalOutcome == "FAILED" || p.FinalOutcome == "TIMEOUT" {
			status = ActionStatusFailed
		}
		// Store the failure reason alongside the terminal status so the ledger
		// can say WHY a FAILED action failed (08 §6c) — and converge adapter to
		// the tool the dispatch ACTUALLY used when the resulted event carries it
		// (the dispatched event recorded the planned selection; a live reload
		// between the two could differ). Empty actual keeps the planned value.
		_, err := tx.ExecContext(ctx, `
			UPDATE action_current
			SET status = $2, error_detail = $3,
			    adapter = COALESCE(NULLIF($4, ''), adapter),
			    raw_response_ref = $5,
			    last_event_sequence = $6, updated_at = $7
			WHERE action_id = $1
		`, p.ActionID, status, p.ErrorDetail, p.Adapter, p.RawResponseRef, evt.SequenceNo, evt.OccurredAt)
		if err != nil {
			return fmt.Errorf("update action_current resulted: %w", err)
		}
		return nil

	case EventTypeActionReversed:
		var p ActionReversed
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionReversed: %w", err)
		}
		// The verified undo: status flips AND the reversing action is recorded
		// on the original (04 §7.1 — reversed_by_ref), so "what reversed this?"
		// is answerable from the original's row, not just the event log.
		_, err := tx.ExecContext(ctx, `
			UPDATE action_current
			SET status = $2, reversed_by_ref = $3, last_event_sequence = $4, updated_at = $5
			WHERE action_id = $1
		`, p.OriginalActionID, ActionStatusReversed, p.ReversingActionID, evt.SequenceNo, evt.OccurredAt)
		if err != nil {
			return fmt.Errorf("update action_current (reversed): %w", err)
		}
		return nil

	case EventTypeActionReversalAttempted:
		var p ActionReversalAttempted
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionReversalAttempted: %w", err)
		}
		// The unverified attempt: status does NOT change (the original honestly
		// stays SUCCEEDED, 04 §7.1) — only the back-reference is recorded.
		_, err := tx.ExecContext(ctx, `
			UPDATE action_current
			SET reversal_attempted_by_ref = $2, last_event_sequence = $3, updated_at = $4
			WHERE action_id = $1
		`, p.OriginalActionID, p.ReversingActionID, evt.SequenceNo, evt.OccurredAt)
		if err != nil {
			return fmt.Errorf("update action_current (reversal attempted): %w", err)
		}
		return nil

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
	       primary_approver_ref, primary_approved_at, is_reversal, reversal_of_ref, retry_of,
	       reversibility, reversed_by_ref, reversal_attempted_by_ref,
	       required_mode, secondary_approver_pool, parameters, targets, evidence_refs,
	       expires_at, adapter, error_detail, raw_response_ref, last_event_sequence`

// scanActionCurrent decodes one actionCurrentColumns row (sql.Row or sql.Rows).
func scanActionCurrent(scan func(dest ...any) error) (ActionCurrent, error) {
	var a ActionCurrent
	var mode, approver, requiredMode, reversibility sql.NullString
	var primaryAt, expiresAt sql.NullTime
	var reversalOf, retryOf, reversedBy, attemptedBy uuid.NullUUID
	var targets, pool, params, evidence []byte
	err := scan(&a.ActionID, &a.AggregateID, &a.ActionType, &a.Tier, &a.Status,
		&mode, &approver, &primaryAt, &a.IsReversal, &reversalOf, &retryOf,
		&reversibility, &reversedBy, &attemptedBy,
		&requiredMode, &pool, &params, &targets, &evidence, &expiresAt,
		&a.Adapter, &a.ErrorDetail, &a.RawResponseRef, &a.LastEventSequence)
	if err != nil {
		return ActionCurrent{}, err
	}
	a.Mode = mode.String
	a.PrimaryApprover = approver.String
	a.PrimaryApprovedAt = primaryAt.Time
	a.ExpiresAt = expiresAt.Time
	a.RequiredMode = requiredMode.String
	a.Reversibility = reversibility.String
	if reversalOf.Valid {
		a.ReversalOfRef = reversalOf.UUID
	}
	if retryOf.Valid {
		a.RetryOf = retryOf.UUID
	}
	if reversedBy.Valid {
		a.ReversedByRef = reversedBy.UUID
	}
	if attemptedBy.Valid {
		a.ReversalAttemptedByRef = attemptedBy.UUID
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
	if len(evidence) > 0 {
		_ = json.Unmarshal(evidence, &a.EvidenceRefs)
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

// ListPendingActionCurrents returns every action still awaiting a decision
// (REQUESTED / PENDING_SECONDARY) across ALL investigations — the expiry
// timer's startup-sweep input: each pending action gets (or already has) a
// durable timer for its frozen deadline.
func ListPendingActionCurrents(ctx context.Context, db *sql.DB) ([]ActionCurrent, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+actionCurrentColumns+` FROM action_current
		 WHERE status IN ($1, $2) ORDER BY created_at, action_id`,
		ActionStatusRequested, ActionStatusPendingSecondary)
	if err != nil {
		return nil, fmt.Errorf("query pending action_current: %w", err)
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
