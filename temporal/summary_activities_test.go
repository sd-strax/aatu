package temporal

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/knowledge"
)

// TestBuildSummary exercises the pure extraction (design/06 §3.2): aggregate
// state → domain Summary, no I/O.
func TestBuildSummary(t *testing.T) {
	created := time.Date(2026, 8, 12, 8, 0, 0, 0, time.UTC)
	concluded := created.Add(6 * time.Hour)
	ic := aggregate.InvestigationCurrent{
		Title:              "RDP lateral movement from WIN-FILE01",
		Status:             aggregate.StatusConcluded,
		VerdictDisposition: "MALICIOUS",
		VerdictRationale:   "Confirmed hands-on-keyboard lateral movement.",
		Seed:               &aggregate.Seed{Type: aggregate.SeedEntity, EntityIdentifier: "WIN-FILE01", EntityRef: "host--abc"},
	}
	hyps := []aggregate.HypothesisCurrent{
		{Statement: "Attacker moved via RDP", Labels: []string{"T1021.001", "lateral-movement"}},
		{Statement: "Valid accounts abused", Labels: []string{"T1078", "T1021.001"}}, // dup technique
	}
	actions := []aggregate.ActionCurrent{
		{ActionType: "host.isolate", Status: "SUCCEEDED", Targets: []aggregate.TargetSpec{{}, {}}},
		{ActionType: "account.disable", Status: "FAILED", Targets: []aggregate.TargetSpec{{}}},
	}

	sum := buildSummary("grouping--xyz", ic, hyps, actions, created, concluded)

	if sum.InvestigationRef != "grouping--xyz" || sum.Title != ic.Title {
		t.Errorf("identity wrong: %+v", sum)
	}
	if sum.SeedKind != "entity" || sum.SeedValue != "WIN-FILE01" {
		t.Errorf("seed extraction wrong: kind=%q value=%q", sum.SeedKind, sum.SeedValue)
	}
	if len(sum.PrimaryEntities) != 1 || sum.PrimaryEntities[0] != "WIN-FILE01" {
		t.Errorf("primary entities = %v", sum.PrimaryEntities)
	}
	// Techniques deduped and sorted; the free-text label is excluded.
	if got := strings.Join(sum.Techniques, ","); got != "T1021.001,T1078" {
		t.Errorf("techniques = %q; want T1021.001,T1078", got)
	}
	if sum.ConclusionOutcome != "succeeded" {
		t.Errorf("outcome = %q; want succeeded (verdict present)", sum.ConclusionOutcome)
	}
	if sum.DurationHours != 6 {
		t.Errorf("duration = %v; want 6", sum.DurationHours)
	}
	if len(sum.ActionsTaken) != 2 || sum.ActionsTaken[0].TargetCount != 2 || sum.ActionsTaken[1].Outcome != "FAILED" {
		t.Errorf("actions extraction wrong: %+v", sum.ActionsTaken)
	}
	if sum.ExtractorVersion != summaryExtractorVersion || sum.GeneratorModel != "" {
		t.Errorf("provenance stamp wrong: v=%q model=%q", sum.ExtractorVersion, sum.GeneratorModel)
	}
	// The deterministic body carries the essence for embedding + keyword recall.
	for _, want := range []string{"MALICIOUS", "WIN-FILE01", "T1021.001", "host.isolate", "6.0h"} {
		if !strings.Contains(sum.SummaryText, want) {
			t.Errorf("summary body missing %q: %s", want, sum.SummaryText)
		}
	}
}

func TestBuildSummaryInconclusive(t *testing.T) {
	ic := aggregate.InvestigationCurrent{
		Title:  "Unresolved beaconing hunt",
		Status: aggregate.StatusConcluded,
		Seed:   &aggregate.Seed{Type: aggregate.SeedQuestion, HypothesisStatement: "Is host X beaconing?"},
	}
	sum := buildSummary("grouping--q", ic, nil, nil, time.Time{}, time.Time{})
	if sum.ConclusionOutcome != "inconclusive" {
		t.Errorf("no verdict should be inconclusive, got %q", sum.ConclusionOutcome)
	}
	if sum.SeedKind != "question" || sum.SeedValue != "Is host X beaconing?" {
		t.Errorf("question seed extraction wrong: %+v", sum)
	}
	if sum.DurationHours != 0 {
		t.Errorf("missing timestamps should yield 0 duration, got %v", sum.DurationHours)
	}
}

// stubWriter captures what the activity would persist.
type stubWriter struct {
	got      knowledge.Summary
	tenantID uuid.UUID
	id       uuid.UUID
	err      error
}

func (w *stubWriter) WriteSummary(_ context.Context, tenantID uuid.UUID, sum knowledge.Summary) (uuid.UUID, error) {
	w.tenantID = tenantID
	w.got = sum
	return w.id, w.err
}

// TestSummaryWriterSeam asserts the producer hands the writer a fully-formed
// summary under the right tenant — the boundary between extraction (temporal)
// and mapping (knowledge).
func TestSummaryWriterSeam(t *testing.T) {
	ic := aggregate.InvestigationCurrent{
		Title: "T", Status: aggregate.StatusConcluded,
		VerdictDisposition: "BENIGN",
		Seed:               &aggregate.Seed{Type: aggregate.SeedAlert, AlertID: "EDR-1"},
	}
	sum := buildSummary("grouping--w", ic, nil, nil, time.Time{}, time.Time{})
	w := &stubWriter{id: uuid.New()}
	if _, err := w.WriteSummary(context.Background(), uuid.MustParse("00000000-0000-0000-0000-000000000001"), sum); err != nil {
		t.Fatal(err)
	}
	if w.got.SeedKind != "alert" || w.got.SeedValue != "EDR-1" || w.got.VerdictDisposition != "BENIGN" {
		t.Errorf("writer received a malformed summary: %+v", w.got)
	}
}
