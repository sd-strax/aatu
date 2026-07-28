package aggregate

// Cross-investigation ref appearances (design/ui binding §6.1): the memory
// join behind "appears in N other investigations." One row per
// (ref, investigation), folded from every interpretation's citations, every
// action's targets, and entity seeds. Deterministic identity (03 §7) is what
// makes a ref a join key: the same entity resolves to the same id in every
// investigation, forever — "not surveillance, just join keys."

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// RefAppearanceProjector maintains ref_appearances in the append transaction.
type RefAppearanceProjector struct{}

// Name returns "ref_appearances".
func (RefAppearanceProjector) Name() string { return "ref_appearances" }

// Apply folds one event's refs.
func (RefAppearanceProjector) Apply(ctx context.Context, tx *sql.Tx, evt Event) error {
	switch evt.Type {
	case EventTypeCreated:
		var p CreateInvestigation
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal CreateInvestigation: %w", err)
		}
		if p.Seed != nil && p.Seed.EntityRef != "" {
			return touchRefs(ctx, tx, evt, []string{p.Seed.EntityRef})
		}
		if p.Seed != nil && p.Seed.DetectionFindingRef != "" {
			return touchRefs(ctx, tx, evt, []string{p.Seed.DetectionFindingRef})
		}
		return nil

	case EventTypeInterpretationRecorded:
		var rec InterpretationRecorded
		if err := json.Unmarshal(evt.Payload, &rec); err != nil {
			return fmt.Errorf("unmarshal InterpretationRecorded: %w", err)
		}
		refs := make([]string, 0, len(rec.InputRefs)+len(rec.OutputRefs))
		refs = append(refs, rec.InputRefs...)
		refs = append(refs, rec.OutputRefs...)
		return touchRefs(ctx, tx, evt, refs)

	case EventTypeActionRequested:
		var p ActionRequested
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			return fmt.Errorf("unmarshal ActionRequested: %w", err)
		}
		var refs []string
		for _, t := range p.Targets {
			if t.EntityRef != "" {
				refs = append(refs, t.EntityRef)
			}
		}
		refs = append(refs, p.EvidenceRefs...)
		return touchRefs(ctx, tx, evt, refs)

	default:
		return nil
	}
}

func touchRefs(ctx context.Context, tx *sql.Tx, evt Event, refs []string) error {
	seen := map[string]bool{}
	for _, ref := range refs {
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ref_appearances (ref, aggregate_id, tenant_id, first_seen, last_seen, mentions)
			VALUES ($1, $2, $3, $4, $4, 1)
			ON CONFLICT (ref, aggregate_id) DO UPDATE SET
				last_seen = EXCLUDED.last_seen,
				mentions  = ref_appearances.mentions + 1
		`, ref, evt.AggregateID, evt.TenantID, evt.OccurredAt); err != nil {
			return fmt.Errorf("upsert ref_appearances: %w", err)
		}
	}
	return nil
}

// Reset clears the projection for replay.
func (RefAppearanceProjector) Reset(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `TRUNCATE ref_appearances`); err != nil {
		return fmt.Errorf("truncate ref_appearances: %w", err)
	}
	return nil
}

// RefAppearance is one investigation a ref appears in, joined with the
// investigation's display state.
type RefAppearance struct {
	AggregateID AggregateID
	Title       string
	Status      string
	SeedSummary string
	FirstSeen   sql.NullTime
	LastSeen    sql.NullTime
	Mentions    int
}

// ListRefAppearances returns every investigation citing a ref, most recently
// touched first.
func ListRefAppearances(ctx context.Context, db *sql.DB, ref string) ([]RefAppearance, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT r.aggregate_id, i.title, i.status, COALESCE(i.seed_summary, ''), r.first_seen, r.last_seen, r.mentions
		FROM ref_appearances r
		JOIN investigation_current i ON i.aggregate_id = r.aggregate_id
		WHERE r.ref = $1
		ORDER BY r.last_seen DESC
	`, ref)
	if err != nil {
		return nil, fmt.Errorf("query ref_appearances: %w", err)
	}
	defer rows.Close()

	var out []RefAppearance
	for rows.Next() {
		var a RefAppearance
		if err := rows.Scan(&a.AggregateID, &a.Title, &a.Status, &a.SeedSummary, &a.FirstSeen, &a.LastSeen, &a.Mentions); err != nil {
			return nil, fmt.Errorf("scan ref_appearances: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
