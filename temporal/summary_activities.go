package temporal

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/knowledge"
)

// summaryExtractorVersion stamps every summary's provenance (design/06 §3.1
// extractor_version). Bump when the extraction shape changes so a re-derivation
// is distinguishable from the prior version's output.
const summaryExtractorVersion = "1"

// summaryWriter is the narrow consumer seam the producer needs — the knowledge
// facade maps the domain summary onto the substrate's DERIVED corpus. Kept an
// interface so the activity is testable without a substrate.
type summaryWriter interface {
	WriteSummary(ctx context.Context, tenantID uuid.UUID, sum knowledge.Summary) (uuid.UUID, error)
}

// SummaryActivities are the side-effecting steps of SummarizeForKnowledgeIndex.
// They hold the aggregate handler (event store + projections, the read side of
// extraction) and the knowledge writer (the substrate-backed DERIVED corpus).
// Extraction reads investigation/STIX domain state here; the mapping onto the
// substrate lives entirely behind the writer, keeping this producer unaware of
// the storage mechanism.
type SummaryActivities struct {
	handler *aggregate.Handler
	writer  summaryWriter
}

// NewSummaryActivities constructs the summary activity set.
func NewSummaryActivities(handler *aggregate.Handler, writer summaryWriter) *SummaryActivities {
	return &SummaryActivities{handler: handler, writer: writer}
}

// SummarizeInput is the frozen identity of the concluded investigation to
// summarize plus the tenant context the write needs.
type SummarizeInput struct {
	GroupingID string `json:"grouping_id"`
	TenantID   string `json:"tenant_id"`
}

// SummarizeOutput is the small descriptor the write returns — the summary
// itself lives in the substrate.
type SummarizeOutput struct {
	SummaryID  string `json:"summary_id"`
	SeedKind   string `json:"seed_kind"`
	Outcome    string `json:"outcome"`
	ActionsLen int    `json:"actions_len"`
}

// Summarize loads a CONCLUDED investigation, extracts the structured summary
// deterministically (design/06 §3.2), and writes it to the DERIVED
// case-summaries corpus. v0 renders the recallable body from the structured
// fields — no LLM; the narrative + conclusion-outcome disambiguation are a
// server-side-LLM enhancement (06 §3.2), and the seam is the summary body /
// GeneratorModel. Idempotent: a re-run revises the prior summary of the same
// source, so a retry never duplicates.
func (a *SummaryActivities) Summarize(ctx context.Context, in SummarizeInput) (SummarizeOutput, error) {
	tenantID, err := uuid.Parse(in.TenantID)
	if err != nil {
		return SummarizeOutput{}, fmt.Errorf("bad tenant id %q: %w", in.TenantID, err)
	}
	aggID, err := uuid.Parse(in.GroupingID)
	if err != nil {
		return SummarizeOutput{}, fmt.Errorf("bad grouping id %q: %w", in.GroupingID, err)
	}
	db := a.handler.DB()

	ic, err := aggregate.LoadInvestigationCurrent(ctx, db, aggID)
	if err != nil {
		return SummarizeOutput{}, fmt.Errorf("load investigation: %w", err)
	}
	if ic.Status != aggregate.StatusConcluded {
		return SummarizeOutput{}, fmt.Errorf("investigation %s is %s; only a CONCLUDED investigation is summarized", in.GroupingID, ic.Status)
	}
	hyps, err := aggregate.ListHypotheses(ctx, db, aggID)
	if err != nil {
		return SummarizeOutput{}, fmt.Errorf("load hypotheses: %w", err)
	}
	actions, err := aggregate.ListActionCurrents(ctx, db, aggID)
	if err != nil {
		return SummarizeOutput{}, fmt.Errorf("load actions: %w", err)
	}
	createdAt, concludedAt, err := investigationSpan(ctx, db, aggID)
	if err != nil {
		return SummarizeOutput{}, err
	}

	sum := buildSummary(in.GroupingID, ic, hyps, actions, createdAt, concludedAt)
	id, err := a.writer.WriteSummary(ctx, tenantID, sum)
	if err != nil {
		return SummarizeOutput{}, fmt.Errorf("write summary: %w", err)
	}
	return SummarizeOutput{
		SummaryID:  id.String(),
		SeedKind:   sum.SeedKind,
		Outcome:    sum.ConclusionOutcome,
		ActionsLen: len(sum.ActionsTaken),
	}, nil
}

// investigationSpan reads the create → conclusion span from the event stream
// (created = first event's occurred-at, concluded = the InvestigationConcluded
// event's). Both feed duration_hours (design/06 §3.2).
func investigationSpan(ctx context.Context, db *sql.DB, aggID uuid.UUID) (created, concluded time.Time, err error) {
	stream, err := aggregate.NewStore(db).LoadStream(ctx, aggID)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("load event stream: %w", err)
	}
	for i := range stream {
		if i == 0 {
			created = stream[i].OccurredAt
		}
		if stream[i].Type == aggregate.EventTypeConcluded {
			concluded = stream[i].OccurredAt
		}
	}
	return created, concluded, nil
}

var techniqueRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// buildSummary is the pure extraction (design/06 §3.2): aggregate state →
// domain Summary, no I/O. Kept pure so the extraction shape is unit-testable
// without a database.
func buildSummary(groupingID string, ic aggregate.InvestigationCurrent, hyps []aggregate.HypothesisCurrent, actions []aggregate.ActionCurrent, createdAt, concludedAt time.Time) knowledge.Summary {
	seedKind, seedValue := "", ""
	var entities []string
	if ic.Seed != nil {
		seedKind = ic.Seed.Type
		seedValue = seedValueOf(ic.Seed)
		if ic.Seed.Type == aggregate.SeedEntity && ic.Seed.EntityIdentifier != "" {
			entities = append(entities, ic.Seed.EntityIdentifier)
		}
	}

	techniques := extractTechniques(hyps)
	summaryActions := make([]knowledge.SummaryAction, 0, len(actions))
	for _, ac := range actions {
		summaryActions = append(summaryActions, knowledge.SummaryAction{
			ActionType:  ac.ActionType,
			TargetCount: len(ac.Targets),
			Outcome:     ac.Status,
		})
	}

	var duration float64
	if !createdAt.IsZero() && !concludedAt.IsZero() && concludedAt.After(createdAt) {
		duration = concludedAt.Sub(createdAt).Hours()
	}

	sum := knowledge.Summary{
		InvestigationRef:   groupingID,
		Title:              ic.Title,
		ConclusionAt:       concludedAt,
		GeneratorModel:     "", // deterministic v0 — no LLM narrative yet
		ExtractorVersion:   summaryExtractorVersion,
		SeedKind:           seedKind,
		SeedValue:          seedValue,
		Techniques:         techniques,
		PrimaryEntities:    entities,
		ActionsTaken:       summaryActions,
		ConclusionOutcome:  conclusionOutcome(ic),
		DurationHours:      duration,
		VerdictDisposition: ic.VerdictDisposition,
		VerdictRationale:   ic.VerdictRationale,
	}
	sum.SummaryText = renderSummaryBody(sum)
	return sum
}

// seedValueOf renders the seed's identifying value per kind (design/06 §3.2).
func seedValueOf(s *aggregate.Seed) string {
	switch s.Type {
	case aggregate.SeedAlert:
		return s.AlertID
	case aggregate.SeedEntity:
		if s.EntityIdentifier != "" {
			return s.EntityIdentifier
		}
		return s.EntityRef
	case aggregate.SeedQuestion:
		return s.HypothesisStatement
	case aggregate.SeedCase:
		return s.CaseID
	default:
		return ""
	}
}

// extractTechniques pulls MITRE technique ids from hypothesis labels, sorted
// and deduplicated. Indicator-type contributions (06 §3.2) are a later
// enrichment once indicators are read from the STIX store.
func extractTechniques(hyps []aggregate.HypothesisCurrent) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hyps {
		for _, label := range h.Labels {
			if techniqueRe.MatchString(label) && !seen[label] {
				seen[label] = true
				out = append(out, label)
			}
		}
	}
	sort.Strings(out)
	return out
}

// conclusionOutcome is the v0 crude classification (design/06 §3.2): a recorded
// verdict means the investigation reached a disposition ("succeeded"); its
// absence is "inconclusive". The finer failed/abandoned distinction needs the
// conclusion Interpretation's rationale with LLM disambiguation — deferred with
// the narrative.
func conclusionOutcome(ic aggregate.InvestigationCurrent) string {
	if ic.VerdictDisposition != "" {
		return "succeeded"
	}
	return "inconclusive"
}

// renderSummaryBody is the deterministic recallable body (design/06 §3.2 v0):
// a compact prose rendering of the structured fields, embeddable for similarity
// and searchable by keyword. The server-side-LLM narrative replaces this later.
func renderSummaryBody(sum knowledge.Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Investigation %q concluded %s.", sum.Title, sum.ConclusionOutcome)
	if sum.SeedKind != "" {
		fmt.Fprintf(&b, " Seeded from %s: %s.", sum.SeedKind, sum.SeedValue)
	}
	if sum.VerdictDisposition != "" {
		fmt.Fprintf(&b, " Verdict: %s.", sum.VerdictDisposition)
		if sum.VerdictRationale != "" {
			fmt.Fprintf(&b, " %s", sum.VerdictRationale)
		}
	}
	if len(sum.Techniques) > 0 {
		fmt.Fprintf(&b, " Techniques: %s.", strings.Join(sum.Techniques, ", "))
	}
	if len(sum.PrimaryEntities) > 0 {
		fmt.Fprintf(&b, " Entities: %s.", strings.Join(sum.PrimaryEntities, ", "))
	}
	if len(sum.ActionsTaken) > 0 {
		parts := make([]string, 0, len(sum.ActionsTaken))
		for _, a := range sum.ActionsTaken {
			parts = append(parts, fmt.Sprintf("%s (%d target(s), %s)", a.ActionType, a.TargetCount, a.Outcome))
		}
		fmt.Fprintf(&b, " Actions taken: %s.", strings.Join(parts, "; "))
	}
	if sum.DurationHours > 0 {
		fmt.Fprintf(&b, " Duration: %.1fh.", sum.DurationHours)
	}
	return b.String()
}
