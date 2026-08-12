package knowledge

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/knowledge/substrate"
)

// Coverage is retrieval's coarse outcome (design/06 §4.3), mirroring the
// substrate's verdict. EMPTY is meaningful evidence-of-absence: "we have no
// institutional procedure for this."
const (
	CoverageComplete = "COMPLETE"
	CoverageEmpty    = "EMPTY"
)

// RecallRequest is the recall_sops query (design/06 §4). A present query drives
// semantic (or, on the degraded backend, keyword) ranking; tags hard-filter
// before ranking; an empty query browses by tag, newest first.
type RecallRequest struct {
	Query          string   `json:"query"`
	Tags           []string `json:"tags,omitempty"`
	Limit          int      `json:"limit"`
	IncludeRetired bool     `json:"include_retired"`
}

// SOPMatch is one ranked retrieval result (design/06 §4).
type SOPMatch struct {
	SOPID          uuid.UUID `json:"sop_id"`
	Title          string    `json:"title"`
	Excerpt        string    `json:"excerpt"`
	Score          float64   `json:"score"`
	MatchRationale string    `json:"match_rationale"`
	Tags           []string  `json:"tags,omitempty"`
	Recommendation string    `json:"recommendation,omitempty"`
	Status         string    `json:"status"`
	// Backend attributes the ranker that produced this result (substrate §5.2)
	// — "vector-cosine/<model>" or the degraded "pg-fts", so a consumer can tell
	// semantic recall from the keyword fallback.
	Backend string `json:"backend,omitempty"`
}

// RecallResult is the recall_sops response envelope.
type RecallResult struct {
	Results     []SOPMatch `json:"results"`
	Coverage    string     `json:"coverage"`
	RetrievalAt time.Time  `json:"retrieval_at"`
}

const defaultRecallLimit = 5

// RecallSOPs ranks the tenant's SOPs against the request (design/06 §4) by
// delegating to the substrate's semantic recall over the `procedures` corpus,
// then mapping entries back to the SOP shape. An empty query is not a substrate
// recall (which requires one) — it browses by tag, newest first.
func (s *Store) RecallSOPs(ctx context.Context, tenantID uuid.UUID, req RecallRequest) (RecallResult, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = defaultRecallLimit
	}
	if strings.TrimSpace(req.Query) == "" {
		return s.browseByTag(ctx, tenantID, req, limit)
	}

	res, err := s.sub.Recall(ctx, tenantID.String(), substrate.RecallQuery{
		Corpus:         CorpusProcedures,
		Mode:           substrate.ModeRank,
		Query:          req.Query,
		Tags:           req.Tags,
		Limit:          limit,
		IncludeRetired: req.IncludeRetired,
	})
	if err != nil {
		return RecallResult{}, fmt.Errorf("recall_sops: %w", err)
	}
	out := RecallResult{
		Coverage:    string(res.Coverage),
		RetrievalAt: res.RetrievalAt,
		Results:     make([]SOPMatch, 0, len(res.Results)),
	}
	backend := rankerLabel(res.Ranker)
	for _, h := range res.Results {
		lineage, _ := lineageOf(h.Tags)
		out.Results = append(out.Results, SOPMatch{
			SOPID:          lineage,
			Title:          h.Title,
			Excerpt:        h.Excerpt,
			Score:          h.Score,
			MatchRationale: h.MatchRationale,
			Tags:           stripReserved(h.Tags),
			Recommendation: h.Advice,
			Status:         sopStatus(h.Status),
			Backend:        backend,
		})
	}
	return out, nil
}

// browseByTag is the empty-query path: current SOPs, tag-overlap filtered,
// newest first. Preserves the pre-substrate "no query, just tags" behavior the
// substrate's recall (which requires a query) intentionally doesn't cover.
func (s *Store) browseByTag(ctx context.Context, tenantID uuid.UUID, req RecallRequest, limit int) (RecallResult, error) {
	entries, err := s.sub.List(ctx, tenantID.String(), CorpusProcedures, substrate.ListFilter{IncludeRetired: req.IncludeRetired})
	if err != nil {
		return RecallResult{}, fmt.Errorf("recall_sops (browse): %w", err)
	}
	res := RecallResult{Coverage: CoverageEmpty, RetrievalAt: time.Now().UTC()}
	for _, e := range entries {
		if len(req.Tags) > 0 && len(intersect(req.Tags, stripReserved(e.Tags))) == 0 {
			continue
		}
		lineage, ok := lineageOf(e.Tags)
		if !ok {
			continue
		}
		res.Results = append(res.Results, SOPMatch{
			SOPID:          lineage,
			Title:          e.Title,
			Excerpt:        excerpt(e.Body),
			MatchRationale: browseRationale(req.Tags, stripReserved(e.Tags)),
			Tags:           stripReserved(e.Tags),
			Recommendation: e.Advice,
			Status:         sopStatus(e.Status),
		})
	}
	// List already returns newest-created first; a revised SOP's new row keeps
	// that ordering meaningful.
	if len(res.Results) > limit {
		res.Results = res.Results[:limit]
	}
	if len(res.Results) > 0 {
		res.Coverage = CoverageComplete
	}
	return res, nil
}

// excerptRunes bounds a browse excerpt (design/06 §4.2 rune stand-in). Recall
// excerpts come pre-budgeted from the substrate (§5.6).
const excerptRunes = 1000

func excerpt(body string) string {
	r := []rune(body)
	if len(r) <= excerptRunes {
		return body
	}
	cut := string(r[:excerptRunes])
	if i := strings.LastIndex(cut, " "); i > excerptRunes/2 {
		cut = cut[:i]
	}
	return cut + "…"
}

func rankerLabel(r substrate.Ranker) string {
	if r.BackendVersion == "" {
		return r.Backend
	}
	return r.Backend + "/" + r.BackendVersion
}

func browseRationale(reqTags, sopTags []string) string {
	if overlap := intersect(reqTags, sopTags); len(overlap) > 0 {
		return "tags " + strings.Join(overlap, ", ") + " (hard filter); recency"
	}
	return "recency (no query)"
}

func intersect(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, x := range b {
		set[x] = true
	}
	var out []string
	for _, x := range a {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}
