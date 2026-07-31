package aggregate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ReasoningNodeProjector materializes the reasoning nodes carried on
// interpretation.recorded events into two places, in the same transaction as
// the event append:
//
//   - stix_objects — the canonical STIX-shaped node (x-hypothesis /
//     x-prediction JSON payload, 01-domain-model.md). This is the first writer
//     of the interpretation-layer object store: reasoning nodes are "STIX
//     nodes inside the Grouping," and here they land as exactly that. (The
//     Grouping object itself, membership/x-supports/x-refutes edges, and the
//     capability layer's SCO writes land with full STIX CRUD in Phase E.)
//   - hypothesis_current / prediction_current — investigation-scoped read
//     models (the panels' query surface), same pattern as action_current.
//
// Because the nodes are projections of interpretation events, Reset+Replay
// rebuilds them from the event log alone. Reset deletes ONLY the reasoning
// types from stix_objects — the store will later hold capability-layer
// entities that are NOT event-sourced, and replay must never destroy those.
type ReasoningNodeProjector struct{}

// Name returns "reasoning_nodes".
func (ReasoningNodeProjector) Name() string { return "reasoning_nodes" }

// Apply materializes one event's node content. Events without reasoning-node
// content are a no-op.
func (ReasoningNodeProjector) Apply(ctx context.Context, tx *sql.Tx, evt Event) error {
	if evt.Type != EventTypeInterpretationRecorded {
		return nil
	}
	var rec InterpretationRecorded
	if err := json.Unmarshal(evt.Payload, &rec); err != nil {
		return fmt.Errorf("unmarshal InterpretationRecorded: %w", err)
	}

	if rec.Hypothesis != nil {
		if err := insertHypothesis(ctx, tx, evt, rec, *rec.Hypothesis); err != nil {
			return err
		}
	}
	if rec.HypothesisTransition != nil {
		if err := transitionNode(ctx, tx, evt, stixTypeHypothesis, rec.HypothesisTransition.Ref, rec.HypothesisTransition.To, nil); err != nil {
			return err
		}
	}
	if rec.Prediction != nil {
		if err := insertPrediction(ctx, tx, evt, rec, *rec.Prediction); err != nil {
			return err
		}
	}
	if rec.PredictionTransition != nil {
		if err := transitionNode(ctx, tx, evt, stixTypePrediction, rec.PredictionTransition.Ref, rec.PredictionTransition.To, rec.PredictionTransition.TestResultRefs); err != nil {
			return err
		}
	}
	return nil
}

// stixHypothesis is the canonical x-hypothesis STIX JSON written to
// stix_objects (01-domain-model.md §x-hypothesis). created_by_ref is omitted at
// v0 — there are no Identity SDOs yet; authorship is fully recorded on the
// producing interpretation event (actor + delegate).
type stixHypothesis struct {
	Type        string   `json:"type"`
	SpecVersion string   `json:"spec_version"`
	ID          string   `json:"id"`
	Statement   string   `json:"statement"`
	Status      string   `json:"status"`
	ParentRef   string   `json:"parent_ref,omitempty"`
	RootedAtRef string   `json:"rooted_at_ref,omitempty"`
	Rationale   string   `json:"rationale,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	Created     string   `json:"created"`
	Modified    string   `json:"modified"`
}

// stixPrediction is the canonical x-prediction STIX JSON (01 §x-prediction).
type stixPrediction struct {
	Type           string     `json:"type"`
	SpecVersion    string     `json:"spec_version"`
	ID             string     `json:"id"`
	HypothesisRef  string     `json:"hypothesis_ref"`
	Statement      string     `json:"statement"`
	Status         string     `json:"status"`
	TestQuery      *QuerySpec `json:"test_query,omitempty"`
	TestResultRefs []string   `json:"test_result_refs,omitempty"`
	Created        string     `json:"created"`
	Modified       string     `json:"modified"`
}

func stixTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.999Z") }

func insertHypothesis(ctx context.Context, tx *sql.Tx, evt Event, rec InterpretationRecorded, h HypothesisRecorded) error {
	nodeUUID, err := stixIDUUID(h.ID, stixTypeHypothesis)
	if err != nil {
		return fmt.Errorf("project hypothesis: %w", err)
	}
	payload, err := json.Marshal(stixHypothesis{
		Type:        stixTypeHypothesis,
		SpecVersion: "2.1",
		ID:          h.ID,
		Statement:   h.Statement,
		Status:      h.Status,
		ParentRef:   h.ParentRef,
		RootedAtRef: h.RootedAtRef,
		Rationale:   rec.Summary,
		Labels:      h.Labels,
		Created:     stixTime(evt.OccurredAt),
		Modified:    stixTime(evt.OccurredAt),
	})
	if err != nil {
		return fmt.Errorf("marshal x-hypothesis: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO stix_objects (id, tenant_id, type, spec_version, payload, created, modified)
		VALUES ($1, $2, $3, '2.1', $4, $5, $5)
		ON CONFLICT (id) DO NOTHING
	`, nodeUUID, evt.TenantID, stixTypeHypothesis, payload, evt.OccurredAt); err != nil {
		return fmt.Errorf("insert stix x-hypothesis: %w", err)
	}

	var labels []byte
	if len(h.Labels) > 0 {
		if labels, err = json.Marshal(h.Labels); err != nil {
			return fmt.Errorf("marshal labels: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO hypothesis_current (
			id, aggregate_id, tenant_id, statement, status, parent_ref,
			rooted_at_ref, labels, created_at, updated_at, last_event_sequence
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10)
		ON CONFLICT (id) DO NOTHING
	`, h.ID, evt.AggregateID, evt.TenantID, h.Statement, h.Status,
		nullString(h.ParentRef), nullString(h.RootedAtRef), labels,
		evt.OccurredAt, evt.SequenceNo); err != nil {
		return fmt.Errorf("insert hypothesis_current: %w", err)
	}
	return nil
}

func insertPrediction(ctx context.Context, tx *sql.Tx, evt Event, _ InterpretationRecorded, p PredictionRecorded) error {
	nodeUUID, err := stixIDUUID(p.ID, stixTypePrediction)
	if err != nil {
		return fmt.Errorf("project prediction: %w", err)
	}
	payload, err := json.Marshal(stixPrediction{
		Type:          stixTypePrediction,
		SpecVersion:   "2.1",
		ID:            p.ID,
		HypothesisRef: p.HypothesisRef,
		Statement:     p.Statement,
		Status:        p.Status,
		TestQuery:     p.TestQuery,
		Created:       stixTime(evt.OccurredAt),
		Modified:      stixTime(evt.OccurredAt),
	})
	if err != nil {
		return fmt.Errorf("marshal x-prediction: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO stix_objects (id, tenant_id, type, spec_version, payload, created, modified)
		VALUES ($1, $2, $3, '2.1', $4, $5, $5)
		ON CONFLICT (id) DO NOTHING
	`, nodeUUID, evt.TenantID, stixTypePrediction, payload, evt.OccurredAt); err != nil {
		return fmt.Errorf("insert stix x-prediction: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO prediction_current (
			id, hypothesis_ref, aggregate_id, tenant_id, statement, status,
			created_at, updated_at, last_event_sequence
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
		ON CONFLICT (id) DO NOTHING
	`, p.ID, p.HypothesisRef, evt.AggregateID, evt.TenantID, p.Statement, p.Status,
		evt.OccurredAt, evt.SequenceNo); err != nil {
		return fmt.Errorf("insert prediction_current: %w", err)
	}
	return nil
}

// transitionNode moves a node's status in both stores. testResultRefs is
// non-nil only for prediction outcomes; it lands in both the STIX payload and
// prediction_current.
func transitionNode(ctx context.Context, tx *sql.Tx, evt Event, stixType, ref, to string, testResultRefs []string) error {
	nodeUUID, err := stixIDUUID(ref, stixType)
	if err != nil {
		return fmt.Errorf("project %s transition: %w", stixType, err)
	}

	// The STIX payload: set status (+ test_result_refs for predictions), bump
	// modified. jsonb_set on the stored payload keeps this a single UPDATE.
	if testResultRefs == nil {
		if _, err := tx.ExecContext(ctx, `
			UPDATE stix_objects
			SET payload = jsonb_set(payload, '{status}', to_jsonb($2::text)),
			    modified = $3
			WHERE id = $1
		`, nodeUUID, to, evt.OccurredAt); err != nil {
			return fmt.Errorf("update stix %s status: %w", stixType, err)
		}
	} else {
		refs, err := json.Marshal(testResultRefs)
		if err != nil {
			return fmt.Errorf("marshal test_result_refs: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE stix_objects
			SET payload = jsonb_set(
			        jsonb_set(payload, '{status}', to_jsonb($2::text)),
			        '{test_result_refs}', $3::jsonb),
			    modified = $4
			WHERE id = $1
		`, nodeUUID, to, refs, evt.OccurredAt); err != nil {
			return fmt.Errorf("update stix %s outcome: %w", stixType, err)
		}
	}

	switch stixType {
	case stixTypeHypothesis:
		if _, err := tx.ExecContext(ctx, `
			UPDATE hypothesis_current
			SET status = $2, last_event_sequence = $3, updated_at = $4
			WHERE id = $1
		`, ref, to, evt.SequenceNo, evt.OccurredAt); err != nil {
			return fmt.Errorf("update hypothesis_current: %w", err)
		}
	case stixTypePrediction:
		var refs []byte
		if len(testResultRefs) > 0 {
			refs, err = json.Marshal(testResultRefs)
			if err != nil {
				return fmt.Errorf("marshal test_result_refs: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE prediction_current
			SET status = $2, test_result_refs = COALESCE($3, test_result_refs),
			    last_event_sequence = $4, updated_at = $5
			WHERE id = $1
		`, ref, to, refs, evt.SequenceNo, evt.OccurredAt); err != nil {
			return fmt.Errorf("update prediction_current: %w", err)
		}
	}
	return nil
}

// Reset clears the projection for replay. stix_objects is scoped to the
// reasoning types — the object store will hold non-event-sourced entities
// (capability-layer SCOs, Phase E) that a replay must never destroy.
func (ReasoningNodeProjector) Reset(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM stix_objects WHERE type IN ($1, $2)`,
		stixTypeHypothesis, stixTypePrediction); err != nil {
		return fmt.Errorf("delete reasoning stix_objects: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `TRUNCATE hypothesis_current, prediction_current`); err != nil {
		return fmt.Errorf("truncate reasoning projections: %w", err)
	}
	return nil
}

// --- read side -----------------------------------------------------------------

// HypothesisCurrent is one materialized hypothesis row.
type HypothesisCurrent struct {
	ID                string
	AggregateID       AggregateID
	Statement         string
	Status            string
	ParentRef         string
	RootedAtRef       string
	Labels            []string
	LastEventSequence int64
}

// PredictionCurrent is one materialized prediction row. TestQuery is read from
// the canonical x-prediction STIX payload (the projector's other write) rather
// than a duplicated column — the declared test is immutable after creation.
type PredictionCurrent struct {
	ID                string
	HypothesisRef     string
	AggregateID       AggregateID
	Statement         string
	Status            string
	TestQuery         *QuerySpec
	TestResultRefs    []string
	LastEventSequence int64
}

// ListHypotheses returns the hypotheses of one investigation, oldest first.
func ListHypotheses(ctx context.Context, db *sql.DB, aggregateID uuid.UUID) ([]HypothesisCurrent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, aggregate_id, statement, status, parent_ref, rooted_at_ref, labels, last_event_sequence
		FROM hypothesis_current
		WHERE aggregate_id = $1
		ORDER BY created_at, id
	`, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("query hypothesis_current: %w", err)
	}
	defer rows.Close()

	var out []HypothesisCurrent
	for rows.Next() {
		var h HypothesisCurrent
		var parent, rooted sql.NullString
		var labels []byte
		if err := rows.Scan(&h.ID, &h.AggregateID, &h.Statement, &h.Status,
			&parent, &rooted, &labels, &h.LastEventSequence); err != nil {
			return nil, fmt.Errorf("scan hypothesis_current: %w", err)
		}
		h.ParentRef, h.RootedAtRef = parent.String, rooted.String
		if len(labels) > 0 {
			_ = json.Unmarshal(labels, &h.Labels)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListPredictions returns the predictions of one investigation, oldest first.
// The declared test query rides along from the canonical STIX payload, so the
// tracker can stage it ("Test this") without a second fetch.
func ListPredictions(ctx context.Context, db *sql.DB, aggregateID uuid.UUID) ([]PredictionCurrent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.hypothesis_ref, p.aggregate_id, p.statement, p.status,
		       p.test_result_refs, p.last_event_sequence,
		       s.payload -> 'test_query'
		FROM prediction_current p
		LEFT JOIN stix_objects s ON s.id = split_part(p.id, '--', 2)::uuid
		WHERE p.aggregate_id = $1
		ORDER BY p.created_at, p.id
	`, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("query prediction_current: %w", err)
	}
	defer rows.Close()

	var out []PredictionCurrent
	for rows.Next() {
		var p PredictionCurrent
		var refs, testQuery []byte
		if err := rows.Scan(&p.ID, &p.HypothesisRef, &p.AggregateID, &p.Statement,
			&p.Status, &refs, &p.LastEventSequence, &testQuery); err != nil {
			return nil, fmt.Errorf("scan prediction_current: %w", err)
		}
		if len(refs) > 0 {
			_ = json.Unmarshal(refs, &p.TestResultRefs)
		}
		if len(testQuery) > 0 {
			_ = json.Unmarshal(testQuery, &p.TestQuery)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListReasoningStixPayloads returns the canonical STIX payloads of the
// interpretation-layer nodes belonging to one investigation — the objects the
// export bundle's stix-bundle.json carries (07 §2.1). The reasoning nodes'
// _current tables key the node by its full STIX id (x-hypothesis--<uuid>);
// stix_objects keys by the bare uuid, so we join on the uuid extracted from the
// full id (split on the STIX "--" separator). Ordered by type+id for a stable
// bundle.
func ListReasoningStixPayloads(ctx context.Context, db *sql.DB, aggregateID uuid.UUID) ([]json.RawMessage, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT payload FROM stix_objects
		WHERE id IN (
			SELECT split_part(id, '--', 2)::uuid FROM hypothesis_current WHERE aggregate_id = $1
			UNION
			SELECT split_part(id, '--', 2)::uuid FROM prediction_current WHERE aggregate_id = $1
		)
		ORDER BY type, id
	`, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("query reasoning stix_objects: %w", err)
	}
	defer rows.Close()

	var out []json.RawMessage
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan stix payload: %w", err)
		}
		out = append(out, json.RawMessage(payload))
	}
	return out, rows.Err()
}

// ActionSummary is the lightweight view of an x-action for the export report
// (07 §2.1) — what it was, its tier, and where it ended.
type ActionSummary struct {
	ActionID   uuid.UUID
	ActionType string
	Tier       string
	Status     string
}

// ListActionSummaries returns every x-action of one investigation, oldest
// first, for the export report + audit view.
func ListActionSummaries(ctx context.Context, db *sql.DB, aggregateID uuid.UUID) ([]ActionSummary, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT action_id, action_type, tier, status
		FROM action_current
		WHERE aggregate_id = $1
		ORDER BY created_at, action_id
	`, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("query action_current: %w", err)
	}
	defer rows.Close()

	var out []ActionSummary
	for rows.Next() {
		var a ActionSummary
		if err := rows.Scan(&a.ActionID, &a.ActionType, &a.Tier, &a.Status); err != nil {
			return nil, fmt.Errorf("scan action summary: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
