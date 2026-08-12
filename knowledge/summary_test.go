package knowledge

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/knowledge/substrate"
)

// TestWriteSummary covers the DERIVED-corpus mapping and re-derivation-as-
// revision idempotency (design/06 §3.1).
func TestWriteSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	s := reset(t)
	ctx := context.Background()

	sum := Summary{
		InvestigationRef:   "grouping--" + uuid.New().String(),
		Title:              "RDP lateral movement",
		ConclusionAt:       time.Now().UTC(),
		SummaryText:        "Investigation concluded. Verdict: MALICIOUS. Techniques: T1021.001.",
		ExtractorVersion:   "1",
		SeedKind:           "entity",
		SeedValue:          "WIN-FILE01",
		Techniques:         []string{"T1021.001", "T1078"},
		ActionsTaken:       []SummaryAction{{ActionType: "host.isolate", TargetCount: 1, Outcome: "SUCCEEDED"}},
		ConclusionOutcome:  "succeeded",
		DurationHours:      6,
		VerdictDisposition: "MALICIOUS",
		VerdictRationale:   "Confirmed hands-on-keyboard.",
	}

	id1, err := s.WriteSummary(ctx, testTenant, sum)
	if err != nil {
		t.Fatal(err)
	}

	// It lands in case-summaries as a DERIVED entry with provenance + the
	// structured meta, and is recallable — with the reserved source tag hidden.
	res, err := s.sub.Recall(ctx, testTenant.String(), substrate.RecallQuery{
		Corpus: CorpusCaseSummaries, Query: "lateral movement", // present in the title
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 {
		t.Fatalf("summary not recallable: %+v", res)
	}
	// The facets are hard-filterable (the reserved source tag also rides here at
	// the substrate level; the facade strips it on the K4 recall path).
	hit := res.Results[0]
	if !hasTag(hit.Tags, "T1021.001") || !hasTag(hit.Tags, "seed:entity") || !hasTag(hit.Tags, "disposition:MALICIOUS") {
		t.Errorf("expected facets missing from tags: %v", hit.Tags)
	}
	got, err := s.sub.Get(ctx, testTenant.String(), CorpusCaseSummaries, id1)
	if err != nil {
		t.Fatal(err)
	}
	if got.Provenance == nil || got.Provenance.Producer != "case-summarizer" || got.Provenance.SourceRef != sum.InvestigationRef {
		t.Errorf("provenance wrong: %+v", got.Provenance)
	}
	if got.Meta["conclusion_outcome"] != "succeeded" {
		t.Errorf("structured meta not carried: %+v", got.Meta)
	}

	// Re-derivation of the SAME source is a revision, not a duplicate.
	sum.SummaryText = "Re-derived: MALICIOUS, more detail."
	id2, err := s.WriteSummary(ctx, testTenant, sum)
	if err != nil {
		t.Fatal(err)
	}
	if id2 == id1 {
		t.Error("re-derivation should produce a new revision id")
	}
	list, err := s.sub.List(ctx, testTenant.String(), CorpusCaseSummaries, substrate.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("re-derivation duplicated the summary: %d current entries", len(list))
	}
	if list[0].Revision != 2 {
		t.Errorf("re-derivation should be revision 2, got %d", list[0].Revision)
	}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// TestRecallSimilar covers the K4 similarity recall over case-summaries: the
// source investigation ref is recovered from the reserved tag, reserved tags
// are stripped, and bands ride through (via the vector backend).
func TestRecallSimilar(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	emb := &stubEmbedder{vec: map[string][]float32{}}
	s := reset(t, substrate.WithEmbedder(emb))
	ctx := context.Background()

	// Two prior cases on orthogonal axes; the query aligns with the RDP one.
	ref1 := "grouping--" + uuid.New().String()
	ref2 := "grouping--" + uuid.New().String()
	emb.set("RDP lateral movement\n\nAttacker pivoted via RDP from WIN-FILE01.", 1, 0)
	emb.set("Phishing payload\n\nUser opened a malicious attachment.", 0, 1)
	emb.set("host pivoted over remote desktop", 1, 0)

	mk := func(ref, title, body string, techniques ...string) {
		if _, err := s.WriteSummary(ctx, testTenant, Summary{
			InvestigationRef: ref, Title: title, SummaryText: body, ExtractorVersion: "1",
			SeedKind: "entity", Techniques: techniques, VerdictDisposition: "MALICIOUS",
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk(ref1, "RDP lateral movement", "Attacker pivoted via RDP from WIN-FILE01.", "T1021.001")
	mk(ref2, "Phishing payload", "User opened a malicious attachment.", "T1566")

	res, err := s.RecallSimilar(ctx, testTenant, SimilarRequest{Query: "host pivoted over remote desktop"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage != CoverageComplete || len(res.Results) == 0 {
		t.Fatalf("expected a similar case, got %+v", res)
	}
	top := res.Results[0]
	if top.InvestigationRef != ref1 {
		t.Errorf("top match ref = %q; want %q (the RDP case)", top.InvestigationRef, ref1)
	}
	if top.Band != string(substrate.BandNearDuplicate) {
		t.Errorf("aligned query should band NEAR_DUPLICATE, got %q", top.Band)
	}
	if top.Backend != "vector-cosine/1/stub-embed" {
		t.Errorf("backend = %q", top.Backend)
	}
	for _, tag := range top.Tags {
		if len(tag) >= 2 && tag[:2] == "__" {
			t.Errorf("reserved tag leaked into similar recall: %q", tag)
		}
	}
	if !hasTag(top.Tags, "T1021.001") {
		t.Errorf("expected technique facet in tags: %v", top.Tags)
	}
}
