package substrate

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// axisEmbedder maps entry/query texts onto controlled vectors so cosine
// outcomes are exact. Entries embed as title+"\n\n"+body (embedText).
func axisEmbedder() *fakeEmbedder {
	return &fakeEmbedder{byText: map[string][]float32{
		embedText("Ransomware isolation SOP", "Isolate the host, preserve memory."): {1, 0, 0, 0},
		embedText("Ransomware comms plan", "Notify IR lead and legal."):             {0.9, 0.435, 0, 0}, // cos ≈ 0.90 vs axis 1
		embedText("Phishing triage", "Check headers and detonate attachments."):     {0, 1, 0, 0},
		"how do we isolate a ransomed host?":                                        {1, 0, 0, 0},
	}}
}

func seedThree(t *testing.T, st *Postgres) {
	t.Helper()
	ctx := context.Background()
	for _, e := range []Entry{
		{Title: "Ransomware isolation SOP", Body: "Isolate the host, preserve memory.", Tags: []string{"ransomware"}},
		{Title: "Ransomware comms plan", Body: "Notify IR lead and legal.", Tags: []string{"ransomware", "comms"}},
		{Title: "Phishing triage", Body: "Check headers and detonate attachments.", Tags: []string{"phishing"}},
	} {
		if _, err := st.Put(ctx, testNS, "procedures", e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVectorRankRecall(t *testing.T) {
	st := newTestStore(t, WithEmbedder(axisEmbedder()))
	seedThree(t, st)

	res, err := st.Recall(context.Background(), testNS, RecallQuery{
		Corpus: "procedures",
		Query:  "how do we isolate a ransomed host?",
		Limit:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage != CoverageComplete {
		t.Errorf("coverage = %s", res.Coverage)
	}
	if res.Ranker.Backend != "vector-cosine" || res.Ranker.BackendVersion != "1/fake-embed-1" {
		t.Errorf("ranker attribution = %+v", res.Ranker)
	}
	if len(res.Results) != 2 {
		t.Fatalf("got %d results", len(res.Results))
	}
	if res.Results[0].Title != "Ransomware isolation SOP" || res.Results[1].Title != "Ransomware comms plan" {
		t.Errorf("order wrong: %s, %s", res.Results[0].Title, res.Results[1].Title)
	}
	if res.Results[0].Score < res.Results[1].Score {
		t.Error("scores must order the response")
	}
	if !strings.Contains(res.Results[0].MatchRationale, "cosine") || !strings.Contains(res.Results[0].MatchRationale, "fake-embed-1") {
		t.Errorf("rationale = %q", res.Results[0].MatchRationale)
	}
	if res.Results[0].Band != "" {
		t.Error("RANK mode must not band")
	}
	if res.Results[0].ContentHash == "" || res.Results[0].HashVersion != HashVersionV1 {
		t.Error("hits must carry the content hash for attestation")
	}
}

func TestVectorSimilarityBands(t *testing.T) {
	st := newTestStore(t, WithEmbedder(axisEmbedder()))
	seedThree(t, st)

	res, err := st.Recall(context.Background(), testNS, RecallQuery{
		Corpus: "procedures",
		Mode:   ModeSimilarity,
		Query:  "how do we isolate a ransomed host?", // axis 1: cos 1.0 / 0.90 / 0.0
	})
	if err != nil {
		t.Fatal(err)
	}
	byTitle := map[string]Band{}
	for _, h := range res.Results {
		byTitle[h.Title] = h.Band
	}
	if byTitle["Ransomware isolation SOP"] != BandNearDuplicate {
		t.Errorf("cos 1.0 should band NEAR_DUPLICATE, got %s", byTitle["Ransomware isolation SOP"])
	}
	if byTitle["Ransomware comms plan"] != BandRelated {
		t.Errorf("cos 0.90 should band RELATED, got %s", byTitle["Ransomware comms plan"])
	}
	if byTitle["Phishing triage"] != BandDistinct {
		t.Errorf("cos 0 should band DISTINCT, got %s", byTitle["Phishing triage"])
	}
}

func TestVectorRecallTagFilterAndEmpty(t *testing.T) {
	st := newTestStore(t, WithEmbedder(axisEmbedder()))
	seedThree(t, st)
	ctx := context.Background()

	res, err := st.Recall(ctx, testNS, RecallQuery{Corpus: "procedures", Query: "how do we isolate a ransomed host?", Tags: []string{"comms"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 || res.Results[0].Title != "Ransomware comms plan" {
		t.Fatalf("tag hard-filter failed: %+v", res.Results)
	}
	if !strings.Contains(res.Results[0].MatchRationale, "tags [comms] matched") {
		t.Errorf("rationale should name the matched tag: %q", res.Results[0].MatchRationale)
	}

	// Zero matches over an indexed corpus is EMPTY — evidence of absence.
	res, err = st.Recall(ctx, testNS, RecallQuery{Corpus: "procedures", Query: "how do we isolate a ransomed host?", Tags: []string{"no-such-tag"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage != CoverageEmpty || len(res.Results) != 0 {
		t.Errorf("want EMPTY coverage, got %s with %d results", res.Coverage, len(res.Results))
	}
}

func TestVectorRecallMissingEmbeddingFailsLoudly(t *testing.T) {
	// Entries written on a keyword-only deployment, then an embedder is
	// configured: recall must error (never silently drop), and Reindex is the
	// documented remedy.
	st := newTestStore(t)
	seedThree(t, st)
	ctx := context.Background()

	withVec, err := NewPostgres(testDB, testCorpora(), WithEmbedder(axisEmbedder()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = withVec.Recall(ctx, testNS, RecallQuery{Corpus: "procedures", Query: "how do we isolate a ransomed host?"})
	if !errors.Is(err, ErrNoEmbedding) {
		t.Fatalf("want ErrNoEmbedding, got %v", err)
	}
	if _, err := withVec.Reindex(ctx, testNS); err != nil {
		t.Fatal(err)
	}
	res, err := withVec.Recall(ctx, testNS, RecallQuery{Corpus: "procedures", Query: "how do we isolate a ransomed host?"})
	if err != nil || res.Coverage != CoverageComplete {
		t.Fatalf("recall after Reindex: %v / %s", err, res.Coverage)
	}
}

func TestRecallExcludesNonCurrent(t *testing.T) {
	st := newTestStore(t, WithEmbedder(axisEmbedder()))
	ctx := context.Background()

	// A draft in a gated corpus and a superseded revision must not surface.
	if _, err := st.Put(ctx, testNS, "policies", Entry{Title: "Draft policy", Body: "Not yet signed."}); err != nil {
		t.Fatal(err)
	}
	res, err := st.Recall(ctx, testNS, RecallQuery{Corpus: "policies", Query: "how do we isolate a ransomed host?"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage != CoverageEmpty {
		t.Errorf("drafts must not be recallable: %+v", res.Results)
	}

	r1, err := st.Put(ctx, testNS, "procedures", Entry{Title: "Ransomware isolation SOP", Body: "Isolate the host, preserve memory."})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Revise(ctx, testNS, "procedures", r1.ID, Revision{Title: "Ransomware comms plan", Body: "Notify IR lead and legal."}); err != nil {
		t.Fatal(err)
	}
	res, err = st.Recall(ctx, testNS, RecallQuery{Corpus: "procedures", Query: "how do we isolate a ransomed host?"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 || res.Results[0].Revision != 2 {
		t.Errorf("superseded revisions must not surface: %+v", res.Results)
	}
}

func TestKeywordFallbackRecall(t *testing.T) {
	st := newTestStore(t) // no embedder → degraded keyword backend
	seedThree(t, st)
	ctx := context.Background()

	res, err := st.Recall(ctx, testNS, RecallQuery{Corpus: "procedures", Query: "isolate host memory"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ranker.Backend != "pg-fts" {
		t.Errorf("ranker = %+v", res.Ranker)
	}
	if len(res.Results) == 0 || res.Results[0].Title != "Ransomware isolation SOP" {
		t.Fatalf("keyword recall failed: %+v", res.Results)
	}

	// SIMILARITY on the keyword backend: coarse bands, never NEAR_DUPLICATE.
	res, err = st.Recall(ctx, testNS, RecallQuery{
		Corpus: "procedures",
		Mode:   ModeSimilarity,
		Query:  "Isolate the host, preserve memory. " + strings.Repeat("Long incident narrative follows. ", 50),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range res.Results {
		if h.Band == BandNearDuplicate {
			t.Errorf("keyword backend must never claim NEAR_DUPLICATE (00-substrate §13)")
		}
		if h.Band != BandRelated {
			t.Errorf("keyword similarity bands RELATED, got %s", h.Band)
		}
	}
}

func TestRecallValidation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if _, err := st.Recall(ctx, testNS, RecallQuery{Corpus: "nope", Query: "x"}); !errors.Is(err, ErrUnknownCorpus) {
		t.Fatalf("want ErrUnknownCorpus, got %v", err)
	}
	if _, err := st.Recall(ctx, testNS, RecallQuery{Corpus: "procedures", Query: "  "}); err == nil {
		t.Fatal("blank query must be an error, not EMPTY")
	}
	if _, err := st.Recall(ctx, testNS, RecallQuery{Corpus: "procedures", Query: "x", Mode: "FUZZY"}); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
}
