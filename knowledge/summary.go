package knowledge

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/knowledge/substrate"
)

// summarySourcePrefix marks the reserved tag carrying a summary's source
// investigation ref, so a re-derivation of the same concluded investigation
// becomes a substrate revision (design/06 §3.1) rather than a duplicate — which
// also makes the post-conclusion pipeline safely retriable.
const summarySourcePrefix = "__case_source:"

// SummaryAction is one state-changing action a summary records (design/06
// §3.2 actions_taken).
type SummaryAction struct {
	ActionType  string `json:"action_type"`
	TargetCount int    `json:"target_count"`
	Outcome     string `json:"outcome"`
}

// Summary is the domain shape of a concluded-investigation summary (design/06
// §3.1) — assembled by the producer (temporal/summary_activities.go) from the
// aggregate, then mapped here onto the substrate's DERIVED case-summaries
// corpus. It is derived, never authored: identity is the substrate's, and a
// re-derivation revises the prior entry.
type Summary struct {
	InvestigationRef string    // grouping--<uuid>, the source investigation
	Title            string    // the investigation title
	ConclusionAt     time.Time // when the source investigation concluded

	// SummaryText is the recallable body. v0 renders it deterministically from
	// the structured fields; a server-side LLM narrative replaces it later, at
	// which point GeneratorModel names the model (empty = deterministic).
	SummaryText      string
	GeneratorModel   string
	ExtractorVersion string

	// Structured fields (design/06 §3.2), surfaced as tags/meta for recall.
	SeedKind           string
	SeedValue          string
	Techniques         []string // MITRE ATT&CK technique ids
	PrimaryEntities    []string // entity identifiers/refs
	ActionsTaken       []SummaryAction
	ConclusionOutcome  string // succeeded | failed | abandoned | inconclusive
	DurationHours      float64
	VerdictDisposition string
	VerdictRationale   string
}

// WriteSummary maps a domain Summary onto a substrate DERIVED entry in the
// case-summaries corpus and writes it. A re-derivation of the same source
// investigation (resolved via the reserved source tag) is a revision, so the
// pipeline is idempotent under retry. Returns the substrate entry id.
func (s *Store) WriteSummary(ctx context.Context, tenantID uuid.UUID, sum Summary) (uuid.UUID, error) {
	if sum.InvestigationRef == "" {
		return uuid.Nil, fmt.Errorf("WriteSummary: investigation_ref required")
	}
	if sum.Title == "" || sum.SummaryText == "" {
		return uuid.Nil, fmt.Errorf("WriteSummary: title and summary_text required")
	}
	ns := tenantID.String()
	entry := substrate.Entry{
		Title: sum.Title,
		Body:  sum.SummaryText,
		Tags:  summaryTags(sum),
		Meta:  summaryMeta(sum),
		Provenance: &substrate.Provenance{
			Producer:        "case-summarizer",
			ProducerVersion: sum.ExtractorVersion,
			GeneratorModel:  sum.GeneratorModel,
			SourceRef:       sum.InvestigationRef,
		},
	}

	// Re-derivation is a revision (design/06 §3.1): find a prior summary of this
	// source and revise it, else write a fresh one.
	prior, err := s.sub.List(ctx, ns, CorpusCaseSummaries, substrate.ListFilter{
		Tag:            summarySourcePrefix + sum.InvestigationRef,
		IncludeRetired: true,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve prior summary: %w", err)
	}
	if len(prior) > 0 {
		e, err := s.sub.Revise(ctx, ns, CorpusCaseSummaries, prior[0].ID, substrate.Revision{
			Title:      entry.Title,
			Body:       entry.Body,
			Tags:       entry.Tags,
			Meta:       entry.Meta,
			Provenance: entry.Provenance,
		})
		if err != nil {
			return uuid.Nil, fmt.Errorf("revise summary: %w", err)
		}
		return e.ID, nil
	}
	e, err := s.sub.Put(ctx, ns, CorpusCaseSummaries, entry)
	if err != nil {
		return uuid.Nil, fmt.Errorf("write summary: %w", err)
	}
	return e.ID, nil
}

// summaryTags are the hard-filterable facets: techniques, the seed kind, the
// disposition, and the reserved source tag for idempotent re-derivation.
func summaryTags(sum Summary) []string {
	tags := make([]string, 0, len(sum.Techniques)+3)
	tags = append(tags, summarySourcePrefix+sum.InvestigationRef)
	if sum.SeedKind != "" {
		tags = append(tags, "seed:"+sum.SeedKind)
	}
	if sum.VerdictDisposition != "" {
		tags = append(tags, "disposition:"+sum.VerdictDisposition)
	}
	tags = append(tags, sum.Techniques...)
	return tags
}

// summaryMeta carries the structured fields as opaque metadata (design/06
// §3.1 structured) for downstream analytics and CEL projection (06 §12).
func summaryMeta(sum Summary) map[string]any {
	actions := make([]map[string]any, 0, len(sum.ActionsTaken))
	for _, a := range sum.ActionsTaken {
		actions = append(actions, map[string]any{
			"action_type":  a.ActionType,
			"target_count": a.TargetCount,
			"outcome":      a.Outcome,
		})
	}
	return map[string]any{
		"investigation_ref":  sum.InvestigationRef,
		"conclusion_at":      sum.ConclusionAt.UTC().Format(time.RFC3339),
		"seed_kind":          sum.SeedKind,
		"seed_value":         sum.SeedValue,
		"techniques":         sum.Techniques,
		"primary_entities":   sum.PrimaryEntities,
		"actions_taken":      actions,
		"conclusion_outcome": sum.ConclusionOutcome,
		"duration_hours":     sum.DurationHours,
		"verdict":            map[string]any{"disposition": sum.VerdictDisposition, "rationale": sum.VerdictRationale},
	}
}
